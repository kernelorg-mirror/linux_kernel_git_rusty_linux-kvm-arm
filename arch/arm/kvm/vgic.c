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

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>

/* Temporary hacks, need to probe DT instead */
#define VGIC_DIST_BASE		0x2c001000
#define VGIC_DIST_SIZE		0x1000

#define ACCESS_READ_VALUE	(1 << 0)
#define ACCESS_READ_RAZ		(0 << 0)
#define ACCESS_READ_MASK(x)	((x) & (1 << 0))
#define ACCESS_WRITE_IGNORED	(0 << 1)
#define ACCESS_WRITE_SETBIT	(1 << 1)
#define ACCESS_WRITE_CLEARBIT	(2 << 1)
#define ACCESS_WRITE_VALUE	(3 << 1)
#define ACCESS_WRITE_MASK(x)	((x) & (3 << 1))

static void vgic_update_state(struct kvm *kvm);
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
		.base		= VGIC_DIST_BASE,
		.len		= 12,
		.handle_mmio	= handle_mmio_misc,
	},
	{			/* IGROUPRn */
		.base		= VGIC_DIST_BASE + 0x80,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_group_reg,
	},
	{			/* ISENABLERn */
		.base		= VGIC_DIST_BASE + 0x100,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_set_enable_reg,
	},
	{			/* ICENABLERn */
		.base		= VGIC_DIST_BASE + 0x180,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_clear_enable_reg,
	},
	{			/* ISPENDRn */
		.base		= VGIC_DIST_BASE + 0x200,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_set_pending_reg,
	},
	{			/* ICPENDRn */
		.base		= VGIC_DIST_BASE + 0x280,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_clear_pending_reg,
	},
	{			/* ISACTIVERn */
		.base		= VGIC_DIST_BASE + 0x300,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_set_active_reg,
	},
	{			/* ICACTIVERn */
		.base		= VGIC_DIST_BASE + 0x380,
		.len		= VGIC_NR_IRQS / 8,
		.handle_mmio	= handle_mmio_clear_active_reg,
	},
	{			/* IPRIORITYRn */
		.base		= VGIC_DIST_BASE + 0x400,
		.len		= VGIC_NR_IRQS,
		.handle_mmio	= handle_mmio_priority_reg,
	},
	{			/* ITARGETSRn */
		.base		= VGIC_DIST_BASE + 0x800,
		.len		= VGIC_NR_IRQS,
		.handle_mmio	= handle_mmio_target_reg,
	},
	{			/* ICFGRn */
		.base		= VGIC_DIST_BASE + 0xC00,
		.len		= VGIC_NR_IRQS / 4,
		.handle_mmio	= handle_mmio_cfg_reg,
	},
	{			/* SGIRn */
		.base		= VGIC_DIST_BASE + 0xF00,
		.len		= 4,
		.handle_mmio	= handle_mmio_sgi_reg,
	},
	{}
};

static const
struct mmio_range *find_matching_range(const struct mmio_range *ranges,
				       struct kvm_run *run)
{
	const struct mmio_range *r = ranges;
	while (r->len) {
		if (run->mmio.phys_addr >= r->base &&
		    (run->mmio.phys_addr + run->mmio.len) <= (r->base + r->len))
			return r;
		r++;
	}

	return NULL;
}

int vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	const struct mmio_range *range;

	if (!irqchip_in_kernel(vcpu->kvm))
		return KVM_EXIT_MMIO;

	range = find_matching_range(vgic_ranges, run);
	if (!range || !range->handle_mmio)
		return KVM_EXIT_MMIO;

	spin_lock(&vcpu->kvm->arch.vgic.lock);
	pr_debug("emulating %d %08llx %d\n", run->mmio.is_write,
		 run->mmio.phys_addr, run->mmio.len);
	range->handle_mmio(vcpu, run, run->mmio.phys_addr - range->base);
	kvm_handle_mmio_return(vcpu, run);
	spin_unlock(&vcpu->kvm->arch.vgic.lock);

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
	return 0;
}

/*
 * Update the interrupt state and determine which CPUs have pending
 * interrupts. Must be called with distributor lock held.
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
