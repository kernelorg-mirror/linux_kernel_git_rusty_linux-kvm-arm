/*
 * Copyright (C) 2012 - Virtual Open Systems and Columbia University
 * Author: Christoffer Dall <c.dall@virtualopensystems.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <linux/mm.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_coproc.h>
#include <trace/events/kvm.h>

#include "trace.h"

/******************************************************************************
 * Co-processor emulation
 *****************************************************************************/

struct coproc_params {
	unsigned long CRn;
	unsigned long CRm;
	unsigned long Op1;
	unsigned long Op2;
	unsigned long Rt1;
	unsigned long Rt2;
	bool is_64bit;
	bool is_write;
};

static void print_cp_instr(const struct coproc_params *p)
{
	/* Look, we even formatted it for you to paste into the table! */
	if (p->is_64bit) {
		kvm_err(" { CRm(%2lu), Op1(%2lu), is64, func_%s },\n",
			p->CRm, p->Op1, p->is_write ? "write" : "read");
	} else {
		kvm_err(" { CRn(%2lu), CRm(%2lu), Op1(%2lu), Op2(%2lu), is32,"
			" func_%s },\n",
			p->CRn, p->CRm, p->Op1, p->Op2,
			p->is_write ? "write" : "read");
	}
}

int kvm_handle_cp10_id(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	kvm_inject_undefined(vcpu);
	return 0;
}

int kvm_handle_cp_0_13_access(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	kvm_inject_undefined(vcpu);
	return 0;
}

int kvm_handle_cp14_load_store(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	kvm_inject_undefined(vcpu);
	return 0;
}

int kvm_handle_cp14_access(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	kvm_inject_undefined(vcpu);
	return 0;
}

static bool ignore_write(struct kvm_vcpu *vcpu,
			 const struct coproc_params *p,
			 unsigned long arg)
{
	if (arg)
		trace_kvm_emulate_cp15_imp(p->Op1, p->Rt1, p->CRn, p->CRm,
					   p->Op2, p->is_write);
	return true;
}

static bool read_zero(struct kvm_vcpu *vcpu,
		      const struct coproc_params *p,
		      unsigned long arg)
{
	if (arg)
		trace_kvm_emulate_cp15_imp(p->Op1, p->Rt1, p->CRn, p->CRm,
					   p->Op2, p->is_write);
	*vcpu_reg(vcpu, p->Rt1) = 0;
	return true;
}

/* A15 TRM 4.3.48: R/O WI. */
static bool access_l2ctlr(struct kvm_vcpu *vcpu,
			const struct coproc_params *p,
			unsigned long arg)
{
	u32 l2ctlr, ncores;

	if (p->is_write)
		return ignore_write(vcpu, p, 0);

	asm volatile("mrc p15, 1, %0, c9, c0, 2\n" : "=r" (l2ctlr));
	l2ctlr &= ~(3 << 24);
	ncores = atomic_read(&vcpu->kvm->online_vcpus) - 1;
	l2ctlr |= (ncores & 3) << 24;
	*vcpu_reg(vcpu, p->Rt1) = l2ctlr;
	return true;
}

/* A15 TRM 4.3.49: R/O WI (even if NSACR.NS_L2ERR, a write of 1 is ignored). */
static bool access_l2ectlr(struct kvm_vcpu *vcpu,
			   const struct coproc_params *p,
			   unsigned long arg)
{
	if (p->is_write)
		return ignore_write(vcpu, p, 0);

	*vcpu_reg(vcpu, p->Rt1) = 0;
	return true;
}

/* A15 TRM 4.3.60: R/O. */
static bool access_cbar(struct kvm_vcpu *vcpu,
			const struct coproc_params *p,
			unsigned long arg)
{
	if (p->is_write)
		return false;
	return read_zero(vcpu, p, 0);
}

/* A15 TRM 4.3.28: RO WI */
static bool access_actlr(struct kvm_vcpu *vcpu,
			 const struct coproc_params *p,
			 unsigned long arg)
{
	u32 actlr;

	if (p->is_write)
		return ignore_write(vcpu, p, 0);

	asm volatile("mrc p15, 0, %0, c1, c0, 1\n" : "=r" (actlr));
	/* Make the SMP bit consistent with the guest configuration */
	if (atomic_read(&vcpu->kvm->online_vcpus) > 1)
		actlr |= 1U << 6;
	else
		actlr &= ~(1U << 6);

	*vcpu_reg(vcpu, p->Rt1) = actlr;
	return true;
}

/* See note at ARM ARM B1.14.4 */
static bool access_dcsw(struct kvm_vcpu *vcpu,
			const struct coproc_params *p,
			unsigned long arg)
{
	u32 val;

	if (!p->is_write)
		return false;

	val = *vcpu_reg(vcpu, p->Rt1);

	switch (p->CRm) {
	case 6:			/* Upgrade DCISW to DCCISW, as per HCR.SWIO */
	case 14:		/* DCCISW */
		asm volatile("mcr p15, 0, %0, c7, c14, 2" : : "r" (val));
		break;

	case 10:		/* DCCSW */
		asm volatile("mcr p15, 0, %0, c7, c10, 2" : : "r" (val));
		break;
	}

	cpumask_setall(&vcpu->arch.require_dcache_flush);
	cpumask_clear_cpu(vcpu->cpu, &vcpu->arch.require_dcache_flush);

	return true;
}

/*
 * We could trap ID_DFR0 and tell the guest we don't support performance
 * monitoring.  Unfortunately the patch to make the kernel check ID_DFR0 was
 * NAKed, so it will read the PMCR anyway.
 *
 * Therefore we tell the guest we have 0 counters.  Unfortunately, we
 * must always support PMCCNTR (the cycle counter): we just RAZ/WI for
 * all PM registers, which doesn't crash the guest kernel at least.
 */
static bool pm_fake(struct kvm_vcpu *vcpu,
		    const struct coproc_params *p,
		    unsigned long arg)
{
	if (p->is_write)
		return ignore_write(vcpu, p, arg);
	else
		return read_zero(vcpu, p, arg);
}

#define access_pmcr pm_fake
#define access_pmcntenset pm_fake
#define access_pmcntenclr pm_fake
#define access_pmovsr pm_fake
#define access_pmselr pm_fake
#define access_pmceid0 pm_fake
#define access_pmceid1 pm_fake
#define access_pmccntr pm_fake
#define access_pmxevtyper pm_fake
#define access_pmxevcntr pm_fake
#define access_pmuserenr pm_fake
#define access_pmintenset pm_fake
#define access_pmintenclr pm_fake

struct coproc_reg {
	unsigned long CRn;
	unsigned long CRm;
	unsigned long Op1;
	unsigned long Op2;

	bool is_64;

	bool (*access)(struct kvm_vcpu *,
		       const struct coproc_params *,
		       unsigned long);
	unsigned long arg;
};

#define CRn(_x)		.CRn = _x
#define CRm(_x) 	.CRm = _x
#define Op1(_x) 	.Op1 = _x
#define Op2(_x) 	.Op2 = _x
#define is64		.is_64 = true
#define is32		.is_64 = false

/* Architected CP15 registers. */
static const struct coproc_reg cp15_regs[] = {
	/*
	 * DC{C,I,CI}SW operations:
	 */
	{ CRn( 7), CRm( 6), Op1( 0), Op2( 2), is32, access_dcsw},
	{ CRn( 7), CRm(10), Op1( 0), Op2( 2), is32, access_dcsw},
	{ CRn( 7), CRm(14), Op1( 0), Op2( 2), is32, access_dcsw},
	/*
	 * Dummy performance monitor implementation.
	 */
	{ CRn( 9), CRm(12), Op1( 0), Op2( 0), is32, access_pmcr},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 1), is32, access_pmcntenset},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 2), is32, access_pmcntenclr},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 3), is32, access_pmovsr},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 5), is32, access_pmselr},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 6), is32, access_pmceid0},
	{ CRn( 9), CRm(12), Op1( 0), Op2( 7), is32, access_pmceid1},
	{ CRn( 9), CRm(13), Op1( 0), Op2( 0), is32, access_pmccntr},
	{ CRn( 9), CRm(13), Op1( 0), Op2( 1), is32, access_pmxevtyper},
	{ CRn( 9), CRm(13), Op1( 0), Op2( 2), is32, access_pmxevcntr},
	{ CRn( 9), CRm(14), Op1( 0), Op2( 0), is32, access_pmuserenr},
	{ CRn( 9), CRm(14), Op1( 0), Op2( 1), is32, access_pmintenset},
	{ CRn( 9), CRm(14), Op1( 0), Op2( 2), is32, access_pmintenclr},
};

/* A15-specific CP15 registers. */
static const struct coproc_reg cp15_cortex_a15_regs[] = {
	/*
	 * ACTRL access:
	 */
	{ CRn( 1), CRm( 0), Op1( 0), Op2( 1), is32, access_actlr},
	/*
	 * L2CTLR access (guest wants to know #CPUs).
	 */
	{ CRn( 9), CRm( 0), Op1( 1), Op2( 2), is32, access_l2ctlr},
	{ CRn( 9), CRm( 0), Op1( 1), Op2( 3), is32, access_l2ectlr},

	/* The Configuration Base Address Register. */
	{ CRn(15), CRm( 0), Op1( 4), Op2( 0), is32, access_cbar},
};

/* Get specific register table for this target. */
static const struct coproc_reg *get_target_table(unsigned target, size_t *num)
{
	switch (target) {
	case KVM_ARM_TARGET_CORTEX_A15:
		*num = ARRAY_SIZE(cp15_cortex_a15_regs);
		return cp15_cortex_a15_regs;
	default:
		*num = 0;
		return NULL;
	}
}

static const struct coproc_reg *find_reg(const struct coproc_params *params,
					 const struct coproc_reg table[],
					 unsigned int num)
{
	unsigned int i;

	for (i = 0; i < num; i++) {
		const struct coproc_reg *r = &table[i];

		if (params->is_64bit != r->is_64)
			continue;
		if (params->CRn != r->CRn)
			continue;
		if (params->CRm != r->CRm)
			continue;
		if (params->Op1 != r->Op1)
			continue;
		if (params->Op2 != r->Op2)
			continue;

		return r;
	}
	return NULL;
}

static int emulate_cp15(struct kvm_vcpu *vcpu,
			const struct coproc_params *params)
{
	size_t num;
	const struct coproc_reg *table, *r;

	table = get_target_table(vcpu->arch.target, &num);

	/* Search target-specific then generic table. */
	r = find_reg(params, table, num);
	if (!r)
		r = find_reg(params, cp15_regs, ARRAY_SIZE(cp15_regs));

	if (likely(r)) {
		if (likely(r->access(vcpu, params, r->arg))) {
			/* Skip instruction, since it was emulated */
			int instr_len = ((vcpu->arch.hsr >> 25) & 1) ? 4 : 2;
			*vcpu_pc(vcpu) += instr_len;
			kvm_adjust_itstate(vcpu);
			return 0;
		}
		/* If access function fails, it should complain. */
	} else {
		kvm_err("Unsupported guest CP15 access at: %08x\n",
			vcpu->arch.regs.pc);
		print_cp_instr(params);
	}
	kvm_inject_undefined(vcpu);
	return 0;
}

/**
 * kvm_handle_cp15_64 -- handles a mrrc/mcrr trap on a guest CP15 access
 * @vcpu: The VCPU pointer
 * @run:  The kvm_run struct
 */
int kvm_handle_cp15_64(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	struct coproc_params params;

	params.CRm = (vcpu->arch.hsr >> 1) & 0xf;
	params.Rt1 = (vcpu->arch.hsr >> 5) & 0xf;
	params.is_write = ((vcpu->arch.hsr & 1) == 0);
	params.is_64bit = true;

	params.Op1 = (vcpu->arch.hsr >> 16) & 0xf;
	params.Op2 = 0;
	params.Rt2 = (vcpu->arch.hsr >> 10) & 0xf;
	params.CRn = 0;

	return emulate_cp15(vcpu, &params);
}

/**
 * kvm_handle_cp15_32 -- handles a mrc/mcr trap on a guest CP15 access
 * @vcpu: The VCPU pointer
 * @run:  The kvm_run struct
 */
int kvm_handle_cp15_32(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	struct coproc_params params;

	params.CRm = (vcpu->arch.hsr >> 1) & 0xf;
	params.Rt1 = (vcpu->arch.hsr >> 5) & 0xf;
	params.is_write = ((vcpu->arch.hsr & 1) == 0);
	params.is_64bit = false;

	params.CRn = (vcpu->arch.hsr >> 10) & 0xf;
	params.Op1 = (vcpu->arch.hsr >> 14) & 0x7;
	params.Op2 = (vcpu->arch.hsr >> 17) & 0x7;
	params.Rt2 = 0;

	return emulate_cp15(vcpu, &params);
}
