#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>

#include <asm/hardware/gic.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>

/* Temporary hacks, need to probe DT instead */
#define VGIC_DIST_BASE		0x2c001000
#define VGIC_DIST_SIZE		0x1000
#define VGIC_CPU_BASE		0x2c002000
#define VGIC_CPU_SIZE		0x2000
#define VGIC_VCTRL_BASE		0x2c004000
#define VGIC_VCTRL_SIZE		0x2000
#define VGIC_VCPU_BASE		0x2c006000
#define VGIC_VCPU_SIZE		0x2000
#define VGIC_MAINT_IRQ		25

static struct kvm_vcpu __percpu **vgic_vcpus;
static void __iomem *vgic_vctrl_base;

#define ACCESS_READ_VALUE	(1 << 0)
#define ACCESS_READ_RAZ		(0 << 0)
#define ACCESS_READ_MASK(x)	((x) & (1 << 0))
#define ACCESS_WRITE_IGNORED	(0 << 1)
#define ACCESS_WRITE_SETBIT	(1 << 1)
#define ACCESS_WRITE_CLEARBIT	(2 << 1)
#define ACCESS_WRITE_VALUE	(3 << 1)
#define ACCESS_WRITE_MASK(x)	((x) & (3 << 1))

static void vgic_update_state(struct kvm *kvm);

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

static void handle_mmio_target_reg(struct kvm_vcpu *vcpu,
				   struct kvm_run *run, u32 offset)
{
	u32 *reg = vgic_bytemap_get_reg(&vcpu->kvm->arch.vgic.irq_target,
					vcpu->vcpu_id, offset);
	mmio_do_copy(run, reg, offset,
		     ACCESS_READ_VALUE | ACCESS_WRITE_VALUE);
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
	u32 reg = vcpu->kvm->arch.vgic.irq_sgi[vcpu->vcpu_id];
	mmio_do_copy(run, &reg, offset,
		     ACCESS_READ_RAZ | ACCESS_WRITE_VALUE);
	if (run->mmio.is_write) {
		/* Set top bit to indicate we've actually written something */
		vcpu->kvm->arch.vgic.irq_sgi[vcpu->vcpu_id] = (reg & 0x03FF000F) | (1 << 31);
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

	range = find_matching_range(vgic_ranges, run);
	if (!range || !range->handle_mmio)
		return KVM_EXIT_MMIO;

	spin_lock(&vcpu->kvm->arch.vgic.lock);
	pr_err("emulating %d %08llx %d\n", run->mmio.is_write,
	       run->mmio.phys_addr, run->mmio.len);
	range->handle_mmio(vcpu, run, run->mmio.phys_addr - range->base);
	kvm_handle_mmio_return(vcpu, run);
	spin_unlock(&vcpu->kvm->arch.vgic.lock);
	return KVM_EXIT_UNKNOWN;
}

/*
 * Flag an interrupt as pending in the CPU interface of a vcpu.
 * If injecting an SGI, cpuid is the ID of the source CPU.
 */
static void kvm_vgic_cpu_inject_irq(struct kvm_vcpu *vcpu, u8 cpuid,
				    unsigned int irq)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	BUG_ON(irq >= VGIC_NR_IRQS);
	spin_lock(&vgic_cpu->lock);
	set_bit(irq, vgic_cpu->vgic_pending_irq);
	if (irq < 16)		/* SGI injection */
		vgic_cpu->vgic_pending_cpuid[irq] = cpuid;
	spin_unlock(&vgic_cpu->lock);

	kvm_vcpu_kick(vcpu);	/* Force the VCPU to reload its state */
}

static void vgic_send_sgi(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct vgic_dist *dist = &kvm->arch.vgic;
	int nrcpus = atomic_read(&kvm->online_vcpus);
	u32 reg;
	u8 target_cpus;
	int sgi, mode, c, cpu_id;

	cpu_id = vcpu->vcpu_id;
	if (!dist->irq_sgi[cpu_id])
		return;

	reg = dist->irq_sgi[cpu_id];
	dist->irq_sgi[cpu_id] = 0;

	sgi = reg & 0xf;
	target_cpus = (reg >> 16) & 0xff;
	mode = (reg >> 24) & 3;

	switch (mode) {
	case 0:
		if (!target_cpus)
			return;

	case 1:
		target_cpus = ((1 << nrcpus) - 1) & ~(1 << cpu_id) & 0xff;
		break;

	case 2:
		target_cpus = 1 << cpu_id;
		break;
	}

	for (c = 0; c < nrcpus; c++) {
		if ((target_cpus & 1) &&
		    vgic_bitmap_get_irq_val(&dist->irq_enabled, c, sgi)) {
			struct kvm_vcpu *target_vcpu = kvm_get_vcpu(kvm, c);
			kvm_vgic_cpu_inject_irq(target_vcpu, cpu_id, sgi);
		}

		target_cpus >>= 1;
	}
}

static void vgic_update_state(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	int nrcpus = atomic_read(&kvm->online_vcpus);
	void *enabled, *pending;
	int c, i;

	if (!dist->enabled)
		return;

	for (c = 0; c < nrcpus; c++) {
		/* SGIs */
		vgic_send_sgi(kvm_get_vcpu(kvm, c));

		/* PPIs */
		enabled = vgic_bitmap_get_private_map(&dist->irq_enabled, c);
		pending = vgic_bitmap_get_private_map(&dist->irq_pending, c);
		i = find_next_bit((unsigned long *)pending, 32, 16);
		while (i < 32) {
			if (test_bit(i, enabled)) {
				clear_bit(i, pending);
				kvm_vgic_cpu_inject_irq(kvm_get_vcpu(kvm, c), c, i);
			}

			i = find_next_bit((unsigned long *)pending, 32, i + 1);
		}
	}

	/* SPIs */
	enabled = dist->irq_enabled.global;
	pending = dist->irq_pending.global;
	i = find_first_bit((unsigned long *)pending, VGIC_NR_IRQS - 32);
	while (i < (VGIC_NR_IRQS - 32)) {
		int irq = i + 32;
		int targ;

		if (test_bit(i, enabled)) {
			clear_bit(i, pending);

			targ = vgic_bytemap_get_irq_val(&dist->irq_target, 0, irq);

			/*
			 * FIXME: We mark the interrupt pending on the
			 * first target CPU only.  This is utterly
			 * wrong, as this CPU may be offline!
			 *
			 * A solution would be to mark the interrupt
			 * pending on ALL target vcpus, and clear the
			 * pending state at the distributor level. It
			 * then becomes horribly racy... Idealy, we'd
			 * need a maintainance interrupt when one of
			 * the CPUs ACKs the interrupt. How?
			 */
			kvm_vgic_cpu_inject_irq(kvm_get_vcpu(kvm, ffs(targ) - 1), 0, irq);
		}

		i = find_next_bit((unsigned long *)pending, VGIC_NR_IRQS - 32, i + 1);
	}
}

/*
 * Fill the list registers with pending interrupts before running the
 * guest.
 */
static void __kvm_vgic_sync_to_cpu(struct vgic_cpu *vgic_cpu)
{
	int empty, pending;

	empty = find_first_bit((unsigned long *)vgic_cpu->vgic_elsr,
			       vgic_cpu->nr_lr);
	pending = find_first_bit(vgic_cpu->vgic_pending_irq, VGIC_NR_IRQS);
	while (pending < VGIC_NR_IRQS) {
		int irq = pending;
		int lr = vgic_cpu->vgic_irq_lr_map[irq];
		int cpuid = (irq < 16) ? vgic_cpu->vgic_pending_cpuid[irq]
				       : 0;

		pr_err("irq = %d\n", irq);
		pending = find_next_bit(vgic_cpu->vgic_pending_irq,
					VGIC_NR_IRQS, pending + 1);

		/* Do we have an active interrupt for the same CPUID? */
		if (lr != 0xff &&
		    (vgic_cpu->vgic_lr[lr] & VGIC_LR_PHYSID_CPUID) == (cpuid << 10)) {
			BUG_ON(!(vgic_cpu->vgic_lr[lr] & VGIC_LR_ACTIVE_BIT));
			vgic_cpu->vgic_lr[lr] |= VGIC_LR_PENDING_BIT;
			clear_bit(irq, vgic_cpu->vgic_pending_irq);
			continue;
		}

		/* Try to use another LR for this interrupt */
		if (empty > vgic_cpu->nr_lr) {
			/*
			 * No empty LR. Enable the underflow bit so we
			 * get a maintainance interrupt when there
			 * will be no pending interrupts at the VM
			 * level.
			 */
			vgic_cpu->vgic_hcr |= VGIC_HCR_UIE;
			return;
		}

		lr = empty;
		vgic_cpu->vgic_lr[lr] = (VGIC_LR_PENDING_BIT |
					 (cpuid << 10) | irq);
		vgic_cpu->vgic_irq_lr_map[irq] = lr;
		vgic_cpu->vgic_lr_irq_map[lr] = irq;

		empty = find_next_bit((unsigned long *)vgic_cpu->vgic_elsr,
				      vgic_cpu->nr_lr, empty + 1);
	}

	/*
	 * No pending interrupts anymore, make sure we don't get an
	 * underflow interrupt.
	 */

	vgic_cpu->vgic_hcr &= ~VGIC_HCR_UIE;
}

/*
 * Sync back the VGIC state after a guest run.
 */
static void __kvm_vgic_sync_from_cpu(struct vgic_cpu *vgic_cpu)
{
	int empty;

	/* Clear mappings for empty LRs */
	empty = find_first_bit((unsigned long *)vgic_cpu->vgic_elsr,
			       vgic_cpu->nr_lr);
	while (empty < vgic_cpu->nr_lr) {
		int lr = empty;
		int irq = vgic_cpu->vgic_lr_irq_map[lr];

		vgic_cpu->vgic_irq_lr_map[irq] = 0xff;
		empty = find_next_bit((unsigned long *)vgic_cpu->vgic_elsr,
				      vgic_cpu->nr_lr, empty + 1);
	}
}

void kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	spin_lock(&vgic_cpu->lock);
	__kvm_vgic_sync_to_cpu(vgic_cpu);
	spin_unlock(&vgic_cpu->lock);

	*__this_cpu_ptr(vgic_vcpus) = vcpu;
}	

void kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	spin_lock(&vgic_cpu->lock);
	__kvm_vgic_sync_from_cpu(vgic_cpu);
	spin_unlock(&vgic_cpu->lock);

	*__this_cpu_ptr(vgic_vcpus) = NULL;
}	

void kvm_vgic_inject_irq(struct kvm *kvm, u8 cpuid, unsigned int irq)
{
	int nrcpus = atomic_read(&kvm->online_vcpus);

	if (WARN_ON(cpuid >= nrcpus))
		return;

	if (WARN_ON(irq >= VGIC_NR_IRQS))
		return;

	pr_err("Inject IRQ%d to CPU%d\n", irq, cpuid);
	spin_lock(&kvm->arch.vgic.lock);
	vgic_bitmap_set_irq_val(&kvm->arch.vgic.irq_pending, cpuid, irq, 1);
	vgic_update_state(kvm);
	spin_unlock(&kvm->arch.vgic.lock);
	
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
	int i;

	spin_lock_init(&vgic_cpu->lock);
	for (i = 0; i < VGIC_NR_IRQS; i++)
		vgic_cpu->vgic_irq_lr_map[i] = 0xff;

	bitmap_zero(vgic_cpu->vgic_pending_irq, VGIC_NR_IRQS);
	BUG_ON(!vcpu->kvm->arch.vgic.vctrl_base);
	vgic_cpu->nr_lr = (readl_relaxed(vcpu->kvm->arch.vgic.vctrl_base + GICH_VTR) & 0x1f) + 1;
	vgic_cpu->vgic_hcr |= VGIC_HCR_EN; /* Get the show on the road... */
}

int kvm_vgic_hyp_init(void)
{
	int ret;

	vgic_vcpus = alloc_percpu(struct kvm_vcpu *);
	if (!vgic_vcpus) {
		kvm_err("Cannot allocate vgic_vcpus\n");
		return -ENOMEM;
	}

	ret = request_percpu_irq(VGIC_MAINT_IRQ, kvm_vgic_maintainance_handler,
				 "vgic", vgic_vcpus);
	if (ret) {
		kvm_err("Cannot register interrupt %d\n", VGIC_MAINT_IRQ);
		goto out_free_vcpus;
	}
	
	vgic_vctrl_base = ioremap(VGIC_VCTRL_BASE, VGIC_VCTRL_SIZE);
	if (!vgic_vctrl_base) {
		kvm_err("Cannot ioremap VCTRL\n");
		goto out_free_irq;
	}

	ret = create_hyp_io_mappings(kvm_hyp_pgd,
				     vgic_vctrl_base,
				     vgic_vctrl_base + VGIC_VCTRL_SIZE,
				     VGIC_VCTRL_BASE);
	if (ret) {
		kvm_err("Cannot map VCTRL into hyp\n");
		goto out_unmap;
	}

	return 0;

out_unmap:
	iounmap(vgic_vctrl_base);	
out_free_irq:
	free_percpu_irq(VGIC_MAINT_IRQ, vgic_vcpus);
out_free_vcpus:
	free_percpu(vgic_vcpus);

	return ret;
}

int kvm_vgic_init(struct kvm *kvm)
{
	int ret;

	spin_lock_init(&kvm->arch.vgic.lock);
	kvm->arch.vgic.vctrl_base = vgic_vctrl_base;

	ret = kvm_phys_addr_ioremap(kvm, VGIC_CPU_BASE,
				    VGIC_VCPU_BASE, VGIC_CPU_SIZE);
	if (ret)
		kvm_err("Unable to remap VGIC CPU to VCPU\n");
	return ret;
}
