/*
 * Copyright (c) 2009 The Regents of the University of California
 * Barret Rhoden <brho@cs.berkeley.edu>
 * See LICENSE for details.
 */

#include <arch/mmu.h>
#include <arch/x86.h>
#include <arch/arch.h>
#include <arch/apic.h>
#include <trap.h>
#include <time.h>
#include <assert.h>
#include <stdio.h>
#include <bitmask.h>
#include <arch/topology.h>
#include <ros/procinfo.h>

bool lapic_check_spurious(int trap_nr)
{
	/* FYI: lapic_spurious is 255 on qemu and 15 on the nehalem..  We
	 * actually can set bits 4-7, and P6s have 0-3 hardwired to 0.  YMMV.
	 * NxM seems to say the lower 3 bits are usually 1.  We'll see if the
	 * assert trips.
	 *
	 * The SDM recommends not using the spurious vector for any other IRQs
	 * (LVT or IOAPIC RTE), since the handlers don't send an EOI.  However,
	 * our check here allows us to use the vector since we can tell the diff
	 * btw a spurious and a real IRQ. */
	assert(IdtLAPIC_SPURIOUS == (apicrget(MSR_LAPIC_SPURIOUS) & 0xff));
	/* Note the lapic's vectors are not shifted by an offset. */
	if ((trap_nr == IdtLAPIC_SPURIOUS) &&
	     !lapic_get_isr_bit(IdtLAPIC_SPURIOUS)) {
		/* i'm still curious about these */
		printk("Spurious LAPIC irq %d, core %d!\n", IdtLAPIC_SPURIOUS,
		       core_id());
		lapic_print_isr();
		return TRUE;
	}
	return FALSE;
}

/* Debugging helper.  Note the ISR/IRR are 32 bits at a time, spaced every 16
 * bytes in the LAPIC address space. */
void lapic_print_isr(void)
{
	printk("LAPIC ISR on core %d\n--------------\n", core_id());
	for (int i = 7; i >= 0; i--)
		printk("%3d-%3d: %p\n", (i + 1) * 32 - 1, i * 32,
			apicrget(MSR_LAPIC_ISR_START + i));
	printk("LAPIC IRR on core %d\n--------------\n", core_id());
	for (int i = 7; i >= 0; i--)
		printk("%3d-%3d: %p\n", (i + 1) * 32 - 1, i * 32,
			apicrget(MSR_LAPIC_IRR_START + i));
}

/* Returns TRUE if the bit 'vector' is set in the LAPIC ISR or IRR (whatever you
 * pass in.  These registers consist of 8, 32 byte registers spaced every 16
 * bytes from the base in the LAPIC. */
static bool __lapic_get_isrr_bit(unsigned long base, uint8_t vector)
{
	int which_reg = vector >> 5;	/* 32 bits per reg */
	uintptr_t lapic_reg = base + which_reg;

	return (apicrget(lapic_reg) & (1 << (vector % 32)) ? 1 : 0);
}

bool lapic_get_isr_bit(uint8_t vector)
{
	return __lapic_get_isrr_bit(MSR_LAPIC_ISR_START, vector);
}

bool lapic_get_irr_bit(uint8_t vector)
{
	return __lapic_get_isrr_bit(MSR_LAPIC_IRR_START, vector);
}

void lapic_mask_irq(struct irq_handler *unused, int apic_vector)
{
	uintptr_t mm_reg;

	if (apic_vector < IdtLAPIC || IdtLAPIC + 4 < apic_vector) {
		warn("Bad apic vector %d\n", apic_vector);
		return;
	}
	mm_reg = MSR_LAPIC_LVT_TIMER + (apic_vector - IdtLAPIC);
	apicrput(mm_reg, apicrget(mm_reg) | LAPIC_LVT_MASK);
}

void lapic_unmask_irq(struct irq_handler *unused, int apic_vector)
{
	uintptr_t mm_reg;

	if (apic_vector < IdtLAPIC || IdtLAPIC + 4 < apic_vector) {
		warn("Bad apic vector %d\n", apic_vector);
		return;
	}
	mm_reg = MSR_LAPIC_LVT_TIMER + (apic_vector - IdtLAPIC);
	apicrput(mm_reg, apicrget(mm_reg) & ~LAPIC_LVT_MASK);
}

/* This works for any interrupt that goes through the LAPIC, but not things like
 * ExtInts.  To prevent abuse, we'll use it just for IPIs for now (which only
 * come via the APIC).
 *
 * We only check the ISR, due to how we send EOIs.  Since we don't send til
 * after handlers return, the ISR will show pending for the current IRQ.  It is
 * the EOI that clears the bit from the ISR. */
bool ipi_is_pending(uint8_t vector)
{
	return lapic_get_isr_bit(vector);
}

/*
 * Sets the LAPIC timer to go off after a certain number of ticks.  The primary
 * clock freq is actually the bus clock, which we figure out during timer_init
 * Unmasking is implied.  Ref SDM, 3A, 9.6.4
 */
void __lapic_set_timer(uint32_t ticks, uint8_t vec, bool periodic, uint8_t div)
{
#ifdef CONFIG_LOUSY_LAPIC_TIMER
	/* qemu without kvm seems to delay timer IRQs on occasion, and needs
	 * extra IRQs from any source to get them delivered.  periodic does the
	 * trick. */
	periodic = TRUE;
#endif
	// clears bottom bit and then set divider
	apicrput(MSR_LAPIC_DIVIDE_CONFIG_REG,
	         (apicrget(MSR_LAPIC_DIVIDE_CONFIG_REG) & ~0xf) | (div & 0xf));
	// set LVT with interrupt handling information.  also unmasks.
	apicrput(MSR_LAPIC_LVT_TIMER, vec | (periodic << 17));
	apicrput(MSR_LAPIC_INITIAL_COUNT, ticks);
}

void lapic_set_timer(uint32_t usec, bool periodic)
{
	/* If we overflowed a uint32, send in the max timer possible.  The lapic
	 * can only handle a 32 bit.  We could muck with changing the divisor,
	 * but even then, we might not be able to match 4000 sec (based on the
	 * bus speed).  The kernel alarm code can handle spurious timer
	 * interrupts, so we just set the timer for as close as we can get to
	 * the desired time. */
	uint64_t ticks64 = (usec * __proc_global_info.bus_freq)
	                   / LAPIC_TIMER_DIVISOR_VAL / 1000000;

	// XXX had a bus_freq that was too small.  we used
	// LAPIC_TIMER_DIVISOR_VAL and whatnot for the highest granularity or
	// whatever, but this is really supposed to be based on bus freq. 
	// 	actually, 32 was supposed to be reasonable
	// 	12505216 = 12 MHz.  that is probably wrong... (computed)
	if (!ticks64)
		ticks64 = 1;

	uint32_t ticks32 = ((ticks64 >> 32) ? 0xffffffff : ticks64);

	assert(ticks32 > 0);
	__lapic_set_timer(ticks32, IdtLAPIC_TIMER, periodic,
	                  LAPIC_TIMER_DIVISOR_BITS);
}

uint32_t lapic_get_default_id(void)
{
	uint32_t ebx;
	
	cpuid(0x1, 0x0, 0, &ebx, 0, 0);
	// p6 family only uses 4 bits here, and 0xf is reserved for the IOAPIC
	return (ebx & 0xFF000000) >> 24;
}
