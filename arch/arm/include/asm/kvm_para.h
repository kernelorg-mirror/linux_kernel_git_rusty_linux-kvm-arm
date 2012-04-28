#ifndef _ASM_ARM_KVM_PARA_H
#define _ASM_ARM_KVM_PARA_H

#include <asm-generic/kvm_para.h>

static inline unsigned int kvm_arch_para_features(void)
{
	return 0;
}

#endif /* _ASM_ARM_KVM_PARA_H */
