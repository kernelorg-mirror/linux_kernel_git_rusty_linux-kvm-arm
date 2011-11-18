#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>

#include <asm/cputype.h>
#include <asm/idmap.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/sections.h>

#ifdef CONFIG_ARM_LPAE
static void idmap_add_pmd(pud_t *pud, unsigned long addr, unsigned long end,
	unsigned long prot)
{
	pmd_t *pmd;
	unsigned long next;

	if (pud_none_or_clear_bad(pud) || (pud_val(*pud) & L_PGD_SWAPPER)) {
		pmd = pmd_alloc_one(NULL, addr);
		if (!pmd) {
			pr_warning("Failed to allocate identity pmd.\n");
			return;
		}
		pud_populate(NULL, pud, pmd);
		pmd += pmd_index(addr);
	} else
		pmd = pmd_offset(pud, addr);

	do {
		next = pmd_addr_end(addr, end);
		*pmd = __pmd((addr & PMD_MASK) | prot);
		flush_pmd_entry(pmd);
	} while (pmd++, addr = next, addr != end);
}
#else	/* !CONFIG_ARM_LPAE */
static void idmap_add_pmd(pud_t *pud, unsigned long addr, unsigned long end,
	unsigned long prot)
{
	pmd_t *pmd = pmd_offset(pud, addr);

	addr = (addr & PMD_MASK) | prot;
	pmd[0] = __pmd(addr);
	addr += SECTION_SIZE;
	pmd[1] = __pmd(addr);
	flush_pmd_entry(pmd);
}
#endif	/* CONFIG_ARM_LPAE */

static void idmap_add_pud(pgd_t *pgd, unsigned long addr, unsigned long end,
	unsigned long prot)
{
	pud_t *pud = pud_offset(pgd, addr);
	unsigned long next;

	do {
		next = pud_addr_end(addr, end);
		idmap_add_pmd(pud, addr, next, prot);
	} while (pud++, addr = next, addr != end);
}

static void __identity_mapping_add(pgd_t *pgd, unsigned long addr,
				   unsigned long end, bool hyp_mapping)
{
	unsigned long prot, next;

	prot = PMD_TYPE_SECT | PMD_SECT_AP_WRITE | PMD_SECT_AF;

#ifdef CONFIG_ARM_LPAE
	if (hyp_mapping)
		prot |= PMD_SECT_AP1;
#endif

	if (cpu_architecture() <= CPU_ARCH_ARMv5TEJ && !cpu_is_xscale())
		prot |= PMD_BIT4;

	pgd += pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		idmap_add_pud(pgd, addr, next, prot);
	} while (pgd++, addr = next, addr != end);
}

void identity_mapping_add(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	__identity_mapping_add(pgd, addr, end, false);
}


#ifdef CONFIG_SMP
static void idmap_del_pmd(pud_t *pud, unsigned long addr, unsigned long end)
{
	pmd_t *pmd;

	if (pud_none_or_clear_bad(pud))
		return;
	pmd = pmd_offset(pud, addr);
	pmd_clear(pmd);
}

static void idmap_del_pud(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	pud_t *pud = pud_offset(pgd, addr);
	unsigned long next;

	do {
		next = pud_addr_end(addr, end);
		idmap_del_pmd(pud, addr, next);
	} while (pud++, addr = next, addr != end);
}

void identity_mapping_del(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	unsigned long next;

	pgd += pgd_index(addr);
	do {
		next = pgd_addr_end(addr, end);
		idmap_del_pud(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}
#else
void identity_mapping_del(pgd_t *pgd, unsigned long addr, unsigned long end)
{
}
#endif

#ifdef CONFIG_KVM_ARM_HOST
void hyp_identity_mapping_add(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	__identity_mapping_add(pgd, addr, end, true);
}
EXPORT_SYMBOL_GPL(hyp_identity_mapping_add);

static void hyp_idmap_del_pmd(pgd_t *pgd, unsigned long addr)
{
	pud_t *pud;
	pmd_t *pmd;

	pud = pud_offset(pgd, addr);
	pmd = pmd_offset(pud, addr);
	pmd_free(NULL, pmd);
}

/*
 * This version actually frees the underlying pmds for all pgds in range and
 * clear the pgds themselves afterwards.
 */
void hyp_identity_mapping_del(pgd_t *pgd, unsigned long addr, unsigned long end)
{
	unsigned long next;
	pgd_t *next_pgd;

	do {
		next = pgd_addr_end(addr, end);
		next_pgd = pgd + pgd_index(addr);
		if (!pgd_none_or_clear_bad(next_pgd)) {
			hyp_idmap_del_pmd(next_pgd, addr);
			pgd_clear(next_pgd);
		}
	} while (addr = next, addr < end);
}
EXPORT_SYMBOL_GPL(hyp_identity_mapping_del);
#endif

/*
 * In order to soft-boot, we need to insert a 1:1 mapping of memory.
 * This will then ensure that we have predictable results when turning
 * the mmu off.
 */
void setup_mm_for_reboot(char mode, pgd_t *pgd)
{
	unsigned long kernel_end;

	/* If we don't have a pgd, hijack the current task. */
	if (pgd == NULL) {
		pgd = current->active_mm->pgd;
		identity_mapping_add(pgd, 0, TASK_SIZE);
	} else {
		identity_mapping_add(pgd, 0, TASK_SIZE);
		/*
		 * Extend the flat mapping into kernelspace, leaving
		 * room for the kernel image itself.
		 */
		kernel_end = ALIGN((unsigned long)_end, PMD_SIZE);
		identity_mapping_add(pgd, kernel_end, 0);
	}

	/* Clean and invalidate L1. */
	flush_cache_all();

	/* Switch exclusively to kernel mappings. */
	cpu_switch_mm(pgd, &init_mm);

	/* Flush the TLB. */
	local_flush_tlb_all();
}
