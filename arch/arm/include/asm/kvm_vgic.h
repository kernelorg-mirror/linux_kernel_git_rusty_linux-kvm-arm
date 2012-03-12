#ifndef __ASM_ARM_KVM_VGIC_H
#define __ASM_ARM_KVM_VGIC_H

#include <linux/kernel.h>
#include <linux/kvm.h>
#include <linux/irqreturn.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define VGIC_NR_IRQS	128	/* Arbitrary number */
#define VGIC_MAX_CPUS	8	/* Same as the HW GIC */

/*
 * The GIC registers describing interrupts have two parts:
 * - 32 per-CPU interrupts (SGI + PPI)
 * - a bunch of global interrups (SPI)
 * They can have 1, 2 or 8 bit fields. Make it easier by having some template
 * to create the structures and the accessors.
 */
#define DEFINE_VGIC_MAP_STRUCT(typename, size)				  \
struct typename {						  	  \
	u32	private[VGIC_MAX_CPUS * 32 / (sizeof(u32) * 8 / size)];	  \
	u32	global[(VGIC_NR_IRQS - 32) / (sizeof(u32) * 8 / size)];	  \
};								  	  \
static inline u32 *typename##_get_reg(struct typename *x,		  \
				      int cpuid, u32 offset)		  \
{									  \
	static const int irq_per_u32 = sizeof(u32) * 8 / size;		  \
	static const int priv_offset = 32 / irq_per_u32;		  \
	offset >>= 2;							  \
	BUG_ON(offset > (VGIC_NR_IRQS  / irq_per_u32));			  \
	if (offset < priv_offset)					  \
		return x->private + offset + (cpuid * priv_offset);	  \
	else								  \
		return x->global + offset - priv_offset;		  \
}									  \
static inline int typename##_get_irq_val(struct typename *x,		  \
					 int cpuid, int irq)		  \
{									  \
	static const int irq_per_u32 = sizeof(u32) * 8 / size;		  \
	static const u32 mask = (1 << size) - 1;			  \
	u32 *reg, offset, shift;					  \
	offset = irq / irq_per_u32;					  \
	shift = (irq % irq_per_u32) * size;				  \
	reg = typename##_get_reg(x, cpuid, offset);			  \
	return (*reg >> shift) & mask;					  \
}									  \
static inline void typename##_set_irq_val(struct typename *x,		  \
					 int cpuid, int irq, int val)	  \
{									  \
	static const int irq_per_u32 = sizeof(u32) * 8 / size;		  \
	static const u32 mask = (1 << size) - 1;			  \
	u32 *reg, offset, shift;					  \
	offset = irq / irq_per_u32;					  \
	shift = (irq % irq_per_u32) * size;				  \
	reg = typename##_get_reg(x, cpuid, offset);			  \
	*reg &= ~(mask << shift);					  \
	*reg |= (val & mask) << shift;					  \
}									  \
static inline u32 *typename##_get_private_map(struct typename *x,	  \
					      int cpu_id)		  \
{									  \
	static const int irq_per_u32 = sizeof(u32) * 8 / size;		  \
	static const int priv_offset = 32 / irq_per_u32;		  \
	if (unlikely(cpu_id >= VGIC_MAX_CPUS))				  \
		return NULL;						  \
	return x->private + (cpu_id * priv_offset);			  \
}


DEFINE_VGIC_MAP_STRUCT(vgic_bitmap, 1);
DEFINE_VGIC_MAP_STRUCT(vgic_2bitmap, 2);
DEFINE_VGIC_MAP_STRUCT(vgic_bytemap, 8);

struct vgic_dist {
#ifdef CONFIG_KVM_ARM_VGIC
	spinlock_t		lock;

	void __iomem		*vctrl_base;

	struct vgic_bitmap	irq_enabled;
	struct vgic_bitmap	irq_pending;
	struct vgic_bitmap	irq_active; /* Not used yet. Useful? */

	struct vgic_bytemap	irq_priority;/* Not used yet. Useful? */
	struct vgic_bytemap	irq_target;

	struct vgic_2bitmap	irq_cfg; /* Not used yet. Useful? */

	u32			irq_sgi[VGIC_MAX_CPUS];
	u32			enabled;
#endif
};

struct vgic_cpu {
#ifdef CONFIG_KVM_ARM_VGIC
	spinlock_t	lock;

	u8		vgic_irq_lr_map[VGIC_NR_IRQS];	/* per IRQ to LR mapping */
	u8		vgic_lr_irq_map[64];		/* per LR to IRQ mapping */
	DECLARE_BITMAP(vgic_pending_irq, VGIC_NR_IRQS); /* Pending IRQs when no free LR */
	u8		vgic_pending_cpuid[16];	/* If SGI pending, contain the CPUid of the source */

	int	nr_lr;

	/* CPU vif control registers for world switch */
	u32	vgic_hcr;
	u32	vgic_mcr;
	u32	vgic_misr;	/* Saved only */
	u32	vgic_elsr[2];	/* Saved only */
	u32	vgic_apr;
	u32	vgic_lr[64];	/* A15 has only 4, need to reduce footprint */
#endif
};

#define VGIC_HCR_EN		(1 << 0)
#define VGIC_HCR_UIE		(1 << 1)

#define VGIC_LR_PHYSID_CPUID	(7 << 10)
#define VGIC_LR_STATE		(3 << 28)
#define VGIC_LR_PENDING_BIT	(1 << 28)
#define VGIC_LR_ACTIVE_BIT	(1 << 29)

struct kvm;
struct kvm_vcpu;
struct kvm_run;

#ifdef CONFIG_KVM_ARM_VGIC
int kvm_vgic_hyp_init(void);
int kvm_vgic_init(struct kvm *kvm);
void kvm_vgic_vcpu_init(struct kvm_vcpu *vcpu);
void kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu);
void kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu);
void kvm_vgic_inject_irq(struct kvm *kvm, u8 cpuid, unsigned int irq);
int vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run);
#else
static inline int kvm_vgic_hyp_init(void)
{
	return 0;
}

static inline int kvm_vgic_init(struct kvm *kvm)
{
	return 0;
}

static inline void kvm_vgic_vcpu_init(struct kvm_vcpu *vcpu) {}
static inline void kvm_vgic_sync_to_cpu(struct kvm_vcpu *vcpu) {}
static inline void kvm_vgic_sync_from_cpu(struct kvm_vcpu *vcpu) {}

static inline int vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return KVM_EXIT_MMIO;
}
#endif

#endif
