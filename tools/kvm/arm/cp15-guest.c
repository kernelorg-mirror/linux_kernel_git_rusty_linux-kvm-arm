#include "guest.h"

extern u32 mcr_insn, mrc_insn, mcrr_insn, mrrc_insn;

/* Alter mcr or mrc instruction */
static void alter_insn32(u32 *insn,
			 unsigned int opc1,
			 unsigned int crn,
			 unsigned int crm,
			 unsigned int opc2)
{
	/* This actually works in both ARM and Thumb mode. */
	*insn &= 0xFF10FF10;
	*insn |= (opc1 << 21) | (crn << 16) | (opc2 << 5) | crm;
	/* ICIALLU */
	asm("mcr p15, 0, %0, c7, c5, 0"	: : "r" (0));
}

/* Alter mcrr or mrrc instruction */
static void alter_insn64(u32 *insn,
			 unsigned int opc1,
			 unsigned int crm)
{
	/* This actually works in both ARM and Thumb mode. */
	*insn &= 0xFFFFFF00;
	*insn |= (opc1 << 4) | crm;
	/* ICIALLU */
	asm("mcr p15, 0, %0, c7, c5, 0"	: : "r" (0));
}

static bool cp15_write(unsigned int opc1,
		       unsigned int crn,
		       unsigned int crm,
		       unsigned int opc2,
		       u32 val)
{
	alter_insn32(&mcr_insn, opc1, crn, crm, opc2);

	skip_undef++;
	undef_count = 0;
	asm volatile(".globl mcr_insn\n"
		     "mcr_insn:\n"
		     "	mcr p15, 0, %0, c0, c0, 0" : : "r"(val) : "memory");
	skip_undef--;

	/* This is incremented if we fault. */
	return undef_count;
}

static bool cp15_read(unsigned int opc1,
		       unsigned int crn,
		       unsigned int crm,
		       unsigned int opc2,
		       u32 *val)
{
	alter_insn32(&mrc_insn, opc1, crn, crm, opc2);
	*val = 0xdeadbeef;

	skip_undef++;
	undef_count = 0;
	asm volatile(".globl mrc_insn\n"
		     "mrc_insn:\n"
		     "	mrc p15, 0, %0, c0, c0, 0" : "=r"(val) : : "memory");
	skip_undef--;

	/* This is incremented if we fault. */
	return undef_count;
}

int test(void)
{
	bool faulted;

	print("Perform an mrc\n");
	faulted = cp15_write(0, 0, 0, 0, 100);

	if (faulted)
		print("IT FAULTED\n");
	else
		print("IT DID NOT FAULT\n");

	return 0;
}
