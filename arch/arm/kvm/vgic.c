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

#define ACCESS_READ_VALUE	(1 << 0)
#define ACCESS_READ_RAZ		(0 << 0)
#define ACCESS_READ_MASK(x)	((x) & (1 << 0))
#define ACCESS_WRITE_IGNORED	(0 << 1)
#define ACCESS_WRITE_SETBIT	(1 << 1)
#define ACCESS_WRITE_CLEARBIT	(2 << 1)
#define ACCESS_WRITE_VALUE	(3 << 1)
#define ACCESS_WRITE_MASK(x)	((x) & (3 << 1))

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

/* All this should really be generic code... FIXME!!! */
struct mmio_range {
	unsigned long base;
	unsigned long len;
	void (*handle_mmio)(struct kvm_vcpu *vcpu, struct kvm_run *run,
			    u32 offset);
};

static const struct mmio_range vgic_ranges[] = {
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

	pr_debug("emulating %d %08llx %d\n", run->mmio.is_write,
		 run->mmio.phys_addr, run->mmio.len);
	range->handle_mmio(vcpu, run, run->mmio.phys_addr - range->base);
	kvm_handle_mmio_return(vcpu, run);

	return KVM_EXIT_UNKNOWN;
}
