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

#include <asm/arch_timer.h>

#include <asm/kvm_vgic.h>
#include <asm/kvm_arch_timer.h>

static int virt_timer_ppi = 27;	/* Hardcoded crap! */
static struct timecounter *timecounter;
static struct workqueue_struct *wqueue;

static cycle_t kvm_phys_timer_read(void)
{
	return timecounter->cc->read(timecounter->cc);
}

static void kvm_timer_inject_irq(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	timer->cntv_ctl |= 1 << 1; /* Mask the interrupt in the guest */
	kvm_err("timer tick on vcpu%d cntv_clt = %d\n", vcpu->vcpu_id, timer->cntv_ctl);
	kvm_vgic_inject_irq(vcpu->kvm, vcpu->vcpu_id, virt_timer_ppi);
}

static irqreturn_t kvm_arch_timer_handler(int irq, void *dev_id)
{
	struct kvm_vcpu *vcpu = kvm_vgic_get_current_vcpu();

	if (WARN_ON(!vcpu))
		return IRQ_NONE;

	kvm_err("kvm_arch_timer_handler\n");
	kvm_timer_inject_irq(vcpu);
	return IRQ_HANDLED;
}

static void kvm_timer_inject_irq_work(struct work_struct *work)
{
	struct kvm_vcpu *vcpu;

	vcpu = container_of(work, struct kvm_vcpu, arch.timer_cpu.expired);
	vcpu->arch.timer_cpu.armed = false;
	kvm_timer_inject_irq(vcpu);
}

static enum hrtimer_restart kvm_timer_expire(struct hrtimer *hrt)
{
	struct arch_timer_cpu *timer;
	kvm_err("kvm_timer_expire\n");
	timer = container_of(hrt, struct arch_timer_cpu, timer);
	queue_work(wqueue, &timer->expired);
	return HRTIMER_NORESTART;
}

void kvm_timer_sync_to_cpu(struct kvm_vcpu *vcpu)
{
}

void kvm_timer_sync_from_cpu(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	cycle_t cval, now;
	u64 ns;

	/* Check if the timer is enabled and unmasked first */
	if ((timer->cntv_ctl & 3) != 1)
		return;

	cval = ((cycle_t)timer->cntv_cval_high << 32) | timer->cntv_cval_low;
	now = kvm_phys_timer_read() - vcpu->kvm->arch.timer.cntvoff;

	if (timer->armed) {
		if (cval == timer->cval)
			return;		/* Already programmed */
		kvm_err("cancel %lld %lld\n", timer->cval, cval);
		hrtimer_cancel(&timer->timer);
		cancel_work_sync(&timer->expired);
		timer->armed = false;
	}

	if (cval <= now) {
		/*
		 * Timer has already expired while we were not
		 * looking. Inject the interrupt and carry on.
		 */
		kvm_err("kvm_timer_sync_from_cpu\n");
		kvm_timer_inject_irq(vcpu);
		return;
	}

	timer->cval = cval;
	timer->armed = true;
	ns = cyclecounter_cyc2ns(timecounter->cc, cval - now);
	kvm_err("hrtimer_start %lld %lld\n", cval, ns);
	hrtimer_start(&timer->timer, ktime_add_ns(ktime_get(), ns),
		      HRTIMER_MODE_ABS);
	kvm_err("hrtimer_started\n");
}

void kvm_timer_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	cycle_t cntvoff = vcpu->kvm->arch.timer.cntvoff;

	if (!cntvoff) {
		cntvoff = kvm_phys_timer_read();
		vcpu->kvm->arch.timer.cntvoff = cntvoff;
	}

	timer->cntvoff_high = (u32)(cntvoff >> 32);
	timer->cntvoff_low  = (u32)(cntvoff & (u32)~0);
	INIT_WORK(&timer->expired, kvm_timer_inject_irq_work);
	hrtimer_init(&timer->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	timer->timer.function = kvm_timer_expire;
}

int kvm_timer_hyp_init(void)
{
	timecounter = arch_timer_get_timecounter();
	if (!timecounter)
		return -ENODEV;

	wqueue = create_singlethread_workqueue("kvm_arch_timer");
	if (!wqueue)
		return -ENOMEM;

	arch_timer_switch_to_phys(kvm_arch_timer_handler);
	return 0;
}

void kvm_timer_vcpu_terminate(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	hrtimer_cancel(&timer->timer);
	cancel_work_sync(&timer->expired);
}
