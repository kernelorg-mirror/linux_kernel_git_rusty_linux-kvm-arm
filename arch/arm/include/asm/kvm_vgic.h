#ifndef __ASM_ARM_KVM_VGIC_H
#define __ASM_ARM_KVM_VGIC_H

#include <linux/kernel.h>
#include <linux/kvm.h>
#include <linux/irqreturn.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#define VGIC_NR_IRQS	128	      /* Arbitrary number */
#define VGIC_MAX_CPUS	KVM_MAX_VCPUS /* Same as the HW GIC */

#if (VGIC_MAX_CPUS > 8)
#error	Invalid number of CPU interfaces
#endif

/*
 * The GIC registers describing interrupts have two parts:
 * - 32 per-CPU interrupts (SGI + PPI)
 * - a bunch of global interrups (SPI)
 * They can have 1, 2 or 8 bit fields. Make it easier by having some template
 * to create the structures and the accessors.
 */
#define DEFINE_VGIC_MAP_STRUCT(typename, size)				  \
struct typename {						  	  \
	union {								  \
		u32 reg[32 / (sizeof(u32) * 8 / size)];			  \
		unsigned long reg_ul[0];				  \
	} percpu[VGIC_MAX_CPUS];					  \
	union {								  \
		u32 reg[(VGIC_NR_IRQS - 32) / (sizeof(u32) * 8 / size)];  \
		unsigned long reg_ul[0];				  \
	} global;							  \
};								  	  \
static inline u32 *typename##_get_reg(struct typename *x,		  \
				      int cpuid, u32 offset)		  \
{									  \
	static const int irq_per_u32 = sizeof(u32) * 8 / size;		  \
	static const int glob_offset = 32 / irq_per_u32;		  \
	offset >>= 2;							  \
	BUG_ON(offset > (VGIC_NR_IRQS  / irq_per_u32));			  \
	if (offset < glob_offset)					  \
		return x->percpu[cpuid].reg + offset;			  \
	else								  \
		return x->global.reg + offset - glob_offset;		  \
}									  \
static inline int typename##_get_irq_val(struct typename *x,		  \
					 int cpuid, int irq)		  \
{									  \
	static const int irq_per_u32 = sizeof(u32) * 8 / size;		  \
	static const u32 mask = (1 << size) - 1;			  \
	u32 *reg, offset, shift;					  \
	offset = (irq / irq_per_u32) << 2;				  \
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
	offset = (irq / irq_per_u32) << 2;				  \
	shift = (irq % irq_per_u32) * size;				  \
	reg = typename##_get_reg(x, cpuid, offset);			  \
	*reg &= ~(mask << shift);					  \
	*reg |= (val & mask) << shift;					  \
}									  \
static inline unsigned long *typename##_get_cpu_map(struct typename *x,	  \
						    int cpu_id)		  \
{									  \
	if (unlikely(cpu_id >= VGIC_MAX_CPUS))				  \
		return NULL;						  \
	return x->percpu[cpu_id].reg_ul;				  \
}


DEFINE_VGIC_MAP_STRUCT(vgic_bitmap, 1);
DEFINE_VGIC_MAP_STRUCT(vgic_2bitmap, 2);
DEFINE_VGIC_MAP_STRUCT(vgic_bytemap, 8);

struct vgic_dist {
#ifdef CONFIG_KVM_ARM_VGIC
	spinlock_t		lock;

	void __iomem		*vctrl_base;
	unsigned long		vgic_dist_base;
	unsigned long		vgic_dist_size;

	u32			enabled;

	struct vgic_bitmap	irq_enabled;
	struct vgic_bitmap	irq_pending;
	struct vgic_bitmap	irq_active; /* Not used yet. Useful? */

	struct vgic_bytemap	irq_priority;/* Not used yet. Useful? */
	struct vgic_bytemap	irq_target;

	struct vgic_2bitmap	irq_cfg; /* Not used yet. Useful? */

	u8			irq_sgi_sources[VGIC_MAX_CPUS][16];

	struct vgic_bitmap	irq_spi_target[VGIC_MAX_CPUS];

	atomic_t		irq_pending_on_cpu;
#endif
};

struct vgic_cpu {
#ifdef CONFIG_KVM_ARM_VGIC
	spinlock_t	lock;

	u8		vgic_irq_lr_map[VGIC_NR_IRQS];	/* per IRQ to LR mapping */
	u8		vgic_lr_irq_map[64];		/* per LR to IRQ mapping */
	DECLARE_BITMAP(	pending, VGIC_NR_IRQS);

	int		nr_lr;

	/* CPU vif control registers for world switch */
	u32		vgic_hcr;
	u32		vgic_mcr;
	u32		vgic_misr;	/* Saved only */
	u32		vgic_elsr[2];	/* Saved only */
	u32		vgic_apr;
	u32		vgic_lr[64];	/* Silly, A15 has only 4... */
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
int kvm_vgic_inject_irq(struct kvm *kvm, int cpuid, const struct kvm_irq_level *irq);
int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu);
int vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run);

#define irqchip_in_kernel(k)	(!!((k)->arch.vgic.vctrl_base))
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

static inline int kvm_vgic_vcpu_pending_irq(struct kvm_vcpu *vcpu)
{
	return 0;
}

static inline int vgic_handle_mmio(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	return KVM_EXIT_MMIO;
}

static inline int irqchip_in_kernel(struct kvm *kvm)
{
	return 0;
}
#endif

#endif
