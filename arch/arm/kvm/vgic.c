/*
 * Copyright (C) 2012 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
//#define DEBUG 1
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>

#include <asm/hardware/gic.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

/* Temporary hacks, need to be provided by userspace emulation */
#define VGIC_DIST_BASE		0x2c001000
#define VGIC_DIST_SIZE		0x1000
#define VGIC_CPU_BASE		0x2c002000
#define VGIC_CPU_SIZE		0x2000

static struct kvm_vcpu __percpu **vgic_vcpus;
static void __iomem *vgic_vctrl_base;
static struct device_node *vgic_node;

#define ACCESS_READ_VALUE	(1 << 0)
#define ACCESS_READ_RAZ		(0 << 0)
#define ACCESS_READ_MASK(x)	((x) & (1 << 0))
#define ACCESS_WRITE_IGNORED	(0 << 1)
#define ACCESS_WRITE_SETBIT	(1 << 1)
#define ACCESS_WRITE_CLEARBIT	(2 << 1)
#define ACCESS_WRITE_VALUE	(3 << 1)
#define ACCESS_WRITE_MASK(x)	((x) & (3 << 1))

static void vgic_update_state(struct kvm *kvm);
static void kvm_vgic_kick_vcpus(struct kvm *kvm);
static void vgic_dispatch_sgi(struct kvm_vcpu *vcpu, u32 reg);

static void mmio_do_copy(struct kvm_run *run, u32 *reg, u32 offset, int mode)
{
	int u32off = offset & 3;
	int shift = u32off * 8;
	u32 mask;
	u32 regval;

	/*
	 * We do silly things on cross-register accesses, so pretend
	 * they do not exist. Will have to be handled though...
	 */
	if (WARN_ON((u32off + run->mmio.len) > 4))
		run->mmio.len = 4 - u32off;

	mask = ((u32)-1) >> (u32off * 8);
	if (reg)
		regval = *reg;
	else {
		BUG_ON(mode != (ACCESS_READ_RAZ | ACCESS_WRITE_IGNORED));
		regval = 0;
	}

	if (run->mmio.is_write) {
		u32 data = (*((u32 *)run->mmio.data) & mask) << shift;
		switch (ACCESS_WRITE_MASK(mode)) {
		case ACCESS_WRITE_IGNORED:
			return;

		case ACCESS_WRITE_SETBIT:
			regval |= data;
			break;

		case ACCESS_WRITE_CLEARBIT:
			regval &= ~data;
			break;

		case ACCESS_WRITE_VALUE:
			regval = (regval & ~(mask << shift)) | data;
			break;
		}
		*reg = regval;
	} else {
		switch (ACCESS_READ_MASK(mode)) {
		case ACCESS_READ_RAZ:
			regval = 0;
			/* fall through */

		case ACCESS_READ_VALUE:
			*((u32 *)run->mmio.data) = (regval >> shift) & mask;
		}
	}
}

static void handle_mmio_misc(struct kvm_vcpu *vcpu,
			     struct kvm_run *run, u32 offset)
{
	u32 reg;
	u32 u32off = offset & 3;

	switch (offset & ~3) {
	case 0:			/* CTLR */
		reg = vcpu->kvm->arch.vgic.enabled;
		mmio_do_copy(run, &reg, u32off,
			     ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
		if (run->mmio.is_write) {
			vcpu->kvm->arch.vgic.enabled = reg & 1;
			vgic_update_state(vcpu->kvm);
		}
		break;

	case 4:			/* TYPER */
		reg  = (atomic_read(&vcpu->kvm->online_vcpus) - 1) << 5;
		reg |= (VGIC_NR_IRQS >> 5) - 1;
		mmio_do_copy(run, &reg, u32off,
			     ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);
		break;

	case 8:			/* IIDR */
		reg = 0x4B00043B;
		mmio_do_copy(run, &reg, u32off,
			     ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);
		break;
	}
}

static void handle_mmio_group_reg(struct kvm_vcpu *vcpu,
				  struct kvm_run *run, u32 offset)
{
	mmio_do_copy(run, NULL, offset,
		     ACCESS_READ_RAZ | ACCESS_WRITE_IGNORED);
}

static void handle_mmio_set_enable_reg(struct kvm_vcpu *vcpu,
				       struct kvm_run *run, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_enabled,
				       vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_SETBIT);
	if (run->mmio.is_write)
		vgic_update_state(vcpu->kvm);
}

static void handle_mmio_clear_enable_reg(struct kvm_vcpu *vcpu,
					 struct kvm_run *run, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_enabled,
				       vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_CLEARBIT);
	if (run->mmio.is_write && offset < 4) /* Force SGI enabled */
		*reg |= 0xffff;
}

static void handle_mmio_set_pending_reg(struct kvm_vcpu *vcpu,
					struct kvm_run *run, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_pending,
				       vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_SETBIT);
	if (run->mmio.is_write)
		vgic_update_state(vcpu->kvm);
}

static void handle_mmio_clear_pending_reg(struct kvm_vcpu *vcpu,
					  struct kvm_run *run, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_pending,
				       vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_CLEARBIT);
}

static void handle_mmio_set_active_reg(struct kvm_vcpu *vcpu,
				       struct kvm_run *run, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_active,
				       vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_SETBIT);
}

static void handle_mmio_clear_active_reg(struct kvm_vcpu *vcpu,
					 struct kvm_run *run, u32 offset)
{
	u32 *reg = vgic_bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_active,
				       vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_CLEARBIT);
}

static void handle_mmio_priority_reg(struct kvm_vcpu *vcpu,
				     struct kvm_run *run, u32 offset)
{
	u32 *reg = vgic_bytemap_get_reg(&vcpu->kvm->arch.vgic.irq_priority,
					vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
}

static void update_spi_target(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	int c, i, nrcpus = atomic_read(&kvm->online_vcpus);
	u8 targ;
	unsigned long *bmap;

	for (i = 32; i < VGIC_NR_IRQS; i++) {
		targ = vgic_bytemap_get_irq_val(&dist->irq_target, 0, i);

		for (c = 0; c < nrcpus; c++) {
			bmap = dist->irq_spi_target[c].global.reg_ul;

			if (targ & (1 << c))
				set_bit(i - 32, bmap);
			else
				clear_bit(i - 32, bmap);
		}
	}
}

static void handle_mmio_target_reg(struct kvm_vcpu *vcpu,
				   struct kvm_run *run, u32 offset)
{
	u32 *reg;

	/* We treat the banked interrupts targets as read-only */
	if (offset < 32) {
		u32 roreg = 1 << vcpu->vcpu_id;
		roreg |= roreg << 8;
		roreg |= roreg << 16;

		mmio_do_copy(run, &roreg, offset,
			     ACCESS_READ_VALUE | ACCESS_WRITE_IGNORED);
		return;
	}

	reg = vgic_bytemap_get_reg(&vcpu->kvm->arch.vgic.irq_target,
				   vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
	if (run->mmio.is_write) {
		update_spi_target(vcpu->kvm);
		vgic_update_state(vcpu->kvm);
	}
}

static void handle_mmio_cfg_reg(struct kvm_vcpu *vcpu,
				struct kvm_run *run, u32 offset)
{
	u32 *reg = vgic_2bitmap_get_reg(&vcpu->kvm->arch.vgic.irq_cfg,
					vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
}

static void handle_mmio_sgi_reg(struct kvm_vcpu *vcpu,
				struct kvm_run *run, u32 offset)
{
	u32 reg;
	mmio_do_copy(run, &reg, offset,
		     ACCESS_READ_RAZ | ACCESS_WRITE_VALUE);
	if (run->mmio.is_write) {
		vgic_dispatch_sgi(vcpu, reg);
		vgic_update_state(vcpu->kvm);
	}
}

/* All this should really be generic code... FIXME!!! */
struct mmio_range {
	unsigned long base;
	unsigned long len;
	void (*handle_mmio)(struct kvm_vcpu *vcpu, struct kvm_run *run,
			    u32 offset);
};

static const struct mmio_range vgic_ranges[] = {
	{			/* CTRL, TYPER, IIDR */
		.base		= 0,
		.len		= 12,
		.handle_mmio	= handle_mmio_misc,
	},
	{			/* IGROUPRn */
		.base		= 0x80,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_group_reg,
	},
	{			/* ISENABLERn */
		.base		= 0x100,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_set_enable_reg,
	},
	{			/* ICENABLERn */
		.base		= 0x180,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_clear_enable_reg,
	},
	{			/* ISPENDRn */
		.base		= 0x200,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_set_pending_reg,
	},
	{			/* ICPENDRn */
		.base		= 0x280,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_clear_pending_reg,
	},
	{			/* ISACTIVERn */
		.base		= 0x300,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_set_active_reg,
	},
	{			/* ICACTIVERn */
		.base		= 0x380,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_clear_active_reg,
	},
	{			/* IPRIORITYRn */
		.base		= 0x400,
		.len		= VGIC_NR_IRQS,
		.handle_mmio	= handle_mmio_priority_reg,
	},
	{			/* ITARGETSRn */
		.base		= 0x800,
		.len		= VGIC_NR_IRQS,
		.handle_mmio	= handle_mmio_target_reg,
	},
	{			/* ICFGRn */
		.base		= 0xC00,
		.len		= VGIC_NR_IRQS / 4,
		.handle_mmio	= handle_mmio_cfg_reg,
	},
	{			/* SGIRn */
		.base		= 0xF00,
		.len		= 4,
		.handle_mmio	= handle_mmio_sgi_reg,
	},
	{}
};

static const
struct mmio_range *find_matching_range(const struct mmio_range *ranges,
				       struct kvm_run *run, unsigned long base)
{
	const struct mmio_range *r = ranges;
	unsigned long addr = run->mmio.phys_addr - base;

	while (r->len) {
		if (addr >= r->base &&
		    (addr + run->mmio.len) <= (r->base + r->len))
			return r;
		r++;
	}

	return NULL;
}

int vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	const struct mmio_range *range;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	unsigned long base = dist->vgic_dist_base;

	if (!irqchip_in_kernel(vcpu->kvm) ||
	    run->mmio.phys_addr < base ||
	    (run->mmio.phys_addr + run->mmio.len) > (base + dist->vgic_dist_size))
		return KVM_EXIT_MMIO;

	range = find_matching_range(vgic_ranges, run, base);
	if (unlikely(!range || !range->handle_mmio)) {
		pr_warn("Unhandled access %d %08llx %d\n",
			run->mmio.is_write, run->mmio.phys_addr, run->mmio.len);
		return KVM_EXIT_MMIO;
	}

	spin_lock(&vcpu->kvm->arch.vgic.lock);
	pr_debug("emulating %d %08llx %d\n", run->mmio.is_write,
		 run->mmio.phys_addr, run->mmio.len);
	range->handle_mmio(vcpu, run, run->mmio.phys_addr - range->base - base);
	kvm_handle_mmio_return(vcpu, run);
	spin_unlock(&vcpu->kvm->arch.vgic.lock);

	kvm_vgic_kick_vcpus(vcpu->kvm);

	return KVM_EXIT_UNKNOWN;
}

static void vgic_dispatch_sgi(struct kvm_vcpu *vcpu, u32 reg)
{
	struct kvm *kvm = vcpu->kvm;
	struct vgic_dist *dist = &kvm->arch.vgic;
	int nrcpus = atomic_read(&kvm->online_vcpus);
	u8 target_cpus;
	int sgi, mode, c, vcpu_id;

	vcpu_id = vcpu->vcpu_id;

	sgi = reg & 0xf;
	target_cpus = (reg >> 16) & 0xff;
	mode = (reg >> 24) & 3;

	switch (mode) {
	case 0:
		if (!target_cpus)
			return;

	case 1:
		target_cpus = ((1 << nrcpus) - 1) & ~(1 << vcpu_id) & 0xff;
		break;

	case 2:
		target_cpus = 1 << vcpu_id;
		break;
	}

	for (c = 0; c < nrcpus; c++) {
		if (target_cpus & 1) {
			/* Flag the SGI as pending */
			vgic_bitmap_set_irq_val(&dist->irq_pending, c, sgi, 1);
			dist->irq_sgi_sources[c][sgi] |= 1 << vcpu_id;
			pr_debug("SGI%d from CPU%d to CPU%d\n", sgi, vcpu_id, c);
		}

		target_cpus >>= 1;
	}
}

static int compute_pending_for_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	unsigned long *pending, *enabled, *pend;
	int vcpu_id;

	vcpu_id = vcpu->vcpu_id;
	pend = vcpu->arch.vgic_cpu.pending;

	pending = vgic_bitmap_get_cpu_map(&dist->irq_pending, vcpu_id);
	enabled = vgic_bitmap_get_cpu_map(&dist->irq_enabled, vcpu_id);
	bitmap_and(pend, pending, enabled, 32);
	
	pending = dist->irq_pending.global.reg_ul;
	enabled = dist->irq_enabled.global.reg_ul;
	bitmap_and(pend + 1, pending, enabled, VGIC_NR_IRQS - 32);
	bitmap_and(pend + 1, pend + 1, dist->irq_spi_target[vcpu_id].global.reg_ul,
		   VGIC_NR_IRQS - 32);

	return (find_first_bit(pend, VGIC_NR_IRQS) < VGIC_NR_IRQS);
}

/*
 * Update the interrupt state and determine which CPUs have pending
 * interrupts. Must be called with distributor lock held.
 *
 * It would be very tempting to just compute the pending bitmap once,
 * but that would make it quite ugly locking wise when a vcpu actually
 * moves the interrupt to its list registers (think of a single
 * interrupt pending on several vcpus). So we end up computing the
 * pending list twice (once here, and once in __kvm_vgic_sync_to_cpu).
 */
static void vgic_update_state(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	int nrcpus = atomic_read(&kvm->online_vcpus);
	int c;

	if (!dist->enabled) {
		atomic_set(&dist->irq_pending_on_cpu, 0);
		return;
	}

	for (c = 0; c < nrcpus; c++) {
		struct kvm_vcpu *vcpu = kvm_get_vcpu(kvm, c);

		if (compute_pending_for_cpu(vcpu)) {
			pr_debug("CPU%d has pending interrupts\n", c);
			atomic_or((1 << c), &dist->irq_pending_on_cpu);
		}
	}
}

/*
 * Queue an interrupt to a CPU virtual interface. Return 0 on success,
 * or 1 if it wasn't possible to queue it.
 */
static int kvm_gic_queue_irq(struct kvm_vcpu *vcpu, u8 cpuid, int irq)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	int lr = vgic_cpu->vgic_irq_lr_map[irq];

	pr_debug("Queue IRQ%d\n", irq);

	/* Sanitize cpuid... */
	cpuid &= 7;

	/* Do we have an active interrupt for the same CPUID? */
	if (lr != 0xff &&
	    (vgic_cpu->vgic_lr[lr] & VGIC_LR_PHYSID_CPUID) == (cpuid << 10)) {
		pr_debug("LR%d piggyback for IRQ%d %x\n", lr, irq, cpuid); 
		vgic_cpu->vgic_lr[lr] |= VGIC_LR_PENDING_BIT;
		return 0;
	}

	/* Try to use another LR for this interrupt */
	lr = find_first_bit((unsigned long *)vgic_cpu->vgic_elsr,
			       vgic_cpu->nr_lr);
	if (lr >= vgic_cpu->nr_lr)
		return 1;

	pr_debug("LR%d allocated for IRQ%d %x\n", lr, irq, cpuid);
	vgic_cpu->vgic_lr[lr] = (VGIC_LR_PENDING_BIT |  (cpuid << 10) | irq);
	vgic_cpu->vgic_irq_lr_map[irq] = lr;
	vgic_cpu->vgic_lr_irq_map[lr] = irq;
	clear_bit(lr, (unsigned long *)vgic_cpu->vgic_elsr);

	return 0;
}

/*
 * Fill the list registers with pending interrupts before running the
 * guest.
 */
static void __kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	unsigned long *pending;
	int i, c, vcpu_id;
	int overflow = 0;

	vcpu_id = vcpu->vcpu_id;

	/*
	 * We may not have any pending interrupt, or the interrupts
	 * may have been serviced from another vcpu. In all cases,
	 * move along.
	 */
	if (!kvm_vgic_vcpu_pending_irq(vcpu) ||
	    !compute_pending_for_cpu(vcpu)) {
		//pr_debug("CPU%d has no pending interrupt\n", vcpu->vcpu_id);
		goto epilog;
	}

	/* SGIs */
	pending = vgic_bitmap_get_cpu_map(&dist->irq_pending, vcpu_id);
	for (i = find_first_bit(vgic_cpu->pending, 16);
	     i < 16;
	     i = find_next_bit(vgic_cpu->pending, 16, i + 1)) {
		unsigned long sources;

		pr_debug("SGI%d on CPU%d\n", i, vcpu_id);
		sources = dist->irq_sgi_sources[vcpu_id][i];
		for (c = find_first_bit(&sources, 8);
		     c < 8;
		     c = find_next_bit(&sources, 8, c + 1)) {
			if (kvm_gic_queue_irq(vcpu, c, i)) {
				overflow = 1;
				continue;
			}

			sources &= ~(1 << c);
		}

		if (!sources)
			clear_bit(i, pending);

		dist->irq_sgi_sources[vcpu_id][i] = sources;
	}

	/* PPIs */
	for (i = find_next_bit(vgic_cpu->pending, 32, 16);
	     i < 32;
	     i = find_next_bit(vgic_cpu->pending, 32, i + 1)) {
		if (kvm_gic_queue_irq(vcpu, 0, i)) {
			overflow = 1;
			continue;
		}

		clear_bit(i, pending);
	}

	
	/* SPIs */
	pending = dist->irq_pending.global.reg_ul;
	for (i = find_next_bit(vgic_cpu->pending, VGIC_NR_IRQS, 32);
	     i < VGIC_NR_IRQS;
	     i = find_next_bit(vgic_cpu->pending, VGIC_NR_IRQS, i + 1)) {
		if (kvm_gic_queue_irq(vcpu, 0, i)) {
			overflow = 1;
			continue;
		}

		clear_bit(i - 32, pending);
	}

epilog:
	if (overflow)
		vgic_cpu->vgic_hcr |= VGIC_HCR_UIE;
	else {
		vgic_cpu->vgic_hcr &= ~VGIC_HCR_UIE;
		/*
		 * We're about to run this VCPU, and we've consumed
		 * everything the distributor had in store for
		 * us. Claim we don't have anything pending. We'll
		 * adjust that if needed while exiting.
		 */
		atomic_clear_mask(1 << vcpu_id,
				  (unsigned long *)&dist->irq_pending_on_cpu);
	}
}

/*
 * Sync back the VGIC state after a guest run.
 */
static void __kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	int empty, pending;

	/* Clear mappings for empty LRs */
	empty = find_first_bit((unsigned long *)vgic_cpu->vgic_elsr,
			       vgic_cpu->nr_lr);
	while (empty < vgic_cpu->nr_lr) {
		int lr = empty;
		int irq = vgic_cpu->vgic_lr_irq_map[lr];

		if (irq < VGIC_NR_IRQS)
			vgic_cpu->vgic_irq_lr_map[irq] = 0xff;

		vgic_cpu->vgic_lr_irq_map[lr] = VGIC_NR_IRQS;
		empty = find_next_bit((unsigned long *)vgic_cpu->vgic_elsr,
				      vgic_cpu->nr_lr, empty + 1);
	}

	/* Check if we still have something up our sleeve... */
	pending = find_first_zero_bit((unsigned long *)vgic_cpu->vgic_elsr,
				      vgic_cpu->nr_lr);
	if (pending < vgic_cpu->nr_lr)
		atomic_or(1 << vcpu->vcpu_id, &dist->irq_pending_on_cpu);
}

void kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	spin_lock(&dist->lock);
	spin_lock(&vgic_cpu->lock);
	__kvm_vgic_sync_to_cpu(vcpu);
	spin_unlock(&vgic_cpu->lock);
	spin_unlock(&dist->lock);

	*__this_cpu_ptr(vgic_vcpus) = vcpu;
}	

void kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	spin_lock(&dist->lock);
	spin_lock(&vgic_cpu->lock);
	__kvm_vgic_sync_from_cpu(vcpu);
	spin_unlock(&vgic_cpu->lock);
	spin_unlock(&dist->lock);

	*__this_cpu_ptr(vgic_vcpus) = NULL;
}

struct kvm_vcpu *kvm_vgic_get_current_vcpu(void)
{
	return *__this_cpu_ptr(vgic_vcpus);
}

int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;

	if (!irqchip_in_kernel(vcpu->kvm))
		return 0;

	return !!(atomic_read(&dist->irq_pending_on_cpu) & (1 << vcpu->vcpu_id));
}

static void kvm_vgic_kick_vcpus(struct kvm *kvm)
{
	int nrcpus = atomic_read(&kvm->online_vcpus);
	int c;

	/*
	 * We've injected an interrupt, time to find out who deserves
	 * a good kick...
	 */
	for (c = 0; c < nrcpus; c++) {
		struct kvm_vcpu *vcpu = kvm_get_vcpu(kvm, c);

		if (kvm_vgic_vcpu_pending_irq(vcpu)) {
			vcpu->arch.wait_for_interrupts = 0;
			kvm_vcpu_kick(vcpu);
		}
	}
}

int kvm_vgic_inject_irq(struct kvm *kvm, int cpuid, const struct kvm_irq_level *irq)
{
	int nrcpus = atomic_read(&kvm->online_vcpus);

	if (WARN_ON(cpuid >= nrcpus))
		return -EINVAL;

	/* Only PPIs or SPIs */
	if (WARN_ON(irq->irq >= VGIC_NR_IRQS || irq->irq < 16))
		return -EINVAL;

	if (!irq->level)
		return 0;

	pr_debug("Inject IRQ%d\n", irq->irq);
	spin_lock(&kvm->arch.vgic.lock);
	vgic_bitmap_set_irq_val(&kvm->arch.vgic.irq_pending, cpuid, irq->irq, 1);
	vgic_update_state(kvm);
	spin_unlock(&kvm->arch.vgic.lock);

	kvm_vgic_kick_vcpus(kvm);

	return 0;
}

static irqreturn_t kvm_vgic_maintainance_handler(int irq, void *data)
{
	struct kvm_vcpu *vcpu = *(struct kvm_vcpu **)data;

	WARN(!vcpu,
	     "VGIC interrupt on CPU %d with no vcpu\n", smp_processor_id());
	/*
	 * Not much to do, as we handle everything on world switch.
	 * It should be possible to do things lazily though, and move
	 * away from world-switch.
	 */
	return IRQ_HANDLED;
}

void kvm_vgic_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	
	int i;

	if (!irqchip_in_kernel(vcpu->kvm))
		return;

	spin_lock_init(&vgic_cpu->lock);
	for (i = 0; i < VGIC_NR_IRQS; i++) {
		if (i < 16)
			vgic_bitmap_set_irq_val(&dist->irq_enabled,
						vcpu->vcpu_id, i, 1);
		vgic_cpu->vgic_irq_lr_map[i] = 0xff;
	}

	BUG_ON(!vcpu->kvm->arch.vgic.vctrl_base);
	vgic_cpu->nr_lr = (readl_relaxed(vcpu->kvm->arch.vgic.vctrl_base + GICH_VTR) & 0x1f) + 1;
	for (i = 0; i < vgic_cpu->nr_lr; i++)
		vgic_cpu->vgic_lr_irq_map[i] = VGIC_NR_IRQS;

	vgic_cpu->vgic_mcr = readl_relaxed(vcpu->kvm->arch.vgic.vctrl_base + GICH_VMCR);
	vgic_cpu->vgic_mcr |= 0xf << 28; /* Priority */
	vgic_cpu->vgic_hcr |= VGIC_HCR_EN; /* Get the show on the road... */
}

int kvm_vgic_hyp_init(void)
{
	int ret;
	unsigned int irq;
	struct resource vctrl_res;

	vgic_node = of_find_compatible_node(NULL, NULL, "arm,cortex-a15-gic");
	if (!vgic_node)
		return -ENODEV;

	vgic_vcpus = alloc_percpu(struct kvm_vcpu *);
	if (!vgic_vcpus) {
		kvm_err("Cannot allocate vgic_vcpus\n");
		return -ENOMEM;
	}

	irq = irq_of_parse_and_map(vgic_node, 0);
	if (!irq) {
		ret = -ENXIO;
		goto out_free_vcpus;
	}

	ret = request_percpu_irq(irq, kvm_vgic_maintainance_handler,
				 "vgic", vgic_vcpus);
	if (ret) {
		kvm_err("Cannot register interrupt %d\n", irq);
		goto out_free_vcpus;
	}
	
	ret = of_address_to_resource(vgic_node, 2, &vctrl_res);
	if (ret) {
		kvm_err("Cannot obtain VCTRL resource\n");
		goto out_free_irq;
	}

	vgic_vctrl_base = of_iomap(vgic_node, 2);
	if (!vgic_vctrl_base) {
		kvm_err("Cannot ioremap VCTRL\n");
		ret = -ENOMEM;
		goto out_free_irq;
	}

	ret = create_hyp_io_mappings(vgic_vctrl_base,
				     vgic_vctrl_base + resource_size(&vctrl_res),
				     vctrl_res.start);
	if (ret) {
		kvm_err("Cannot map VCTRL into hyp\n");
		goto out_unmap;
	}

	kvm_info("%s@%llx IRQ%d\n", vgic_node->name, vctrl_res.start, irq);
	return 0;

out_unmap:
	iounmap(vgic_vctrl_base);	
out_free_irq:
	free_percpu_irq(irq, vgic_vcpus);
out_free_vcpus:
	free_percpu(vgic_vcpus);

	return ret;
}

int kvm_vgic_init(struct kvm *kvm)
{
	int ret;
	struct resource vcpu_res;

	mutex_lock(&kvm->lock);

	if (of_address_to_resource(vgic_node, 3, &vcpu_res)) {
		kvm_err("Cannot obtain VCPU resource\n");
		ret = -ENXIO;
		goto out;
	}

	if (atomic_read(&kvm->online_vcpus)) {
		ret = -EEXIST;
		goto out;
	}

	spin_lock_init(&kvm->arch.vgic.lock);
	kvm->arch.vgic.vctrl_base = vgic_vctrl_base;
	kvm->arch.vgic.vgic_dist_base = VGIC_DIST_BASE;
	kvm->arch.vgic.vgic_dist_size = VGIC_DIST_SIZE;

	ret = kvm_phys_addr_ioremap(kvm, VGIC_CPU_BASE,
				    vcpu_res.start, VGIC_CPU_SIZE);
	if (ret)
		kvm_err("Unable to remap VGIC CPU to VCPU\n");
out:
	mutex_unlock(&kvm->lock);

	if (!ret)
		kvm_timer_init(kvm);

	return ret;
}
