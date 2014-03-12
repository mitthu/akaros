#ifndef ROS_KERN_ARCH_TRAP_H
#define ROS_KERN_ARCH_TRAP_H

#include "msr-index.h"

#define NUM_IRQS					256

/* 0-31 are hardware traps */
#define T_DIVIDE     0		// divide error
#define T_DEBUG      1		// debug exception
#define T_NMI        2		// non-maskable interrupt
#define T_BRKPT      3		// breakpoint
#define T_OFLOW      4		// overflow
#define T_BOUND      5		// bounds check
#define T_ILLOP      6		// illegal opcode
#define T_DEVICE     7		// device not available 
#define T_DBLFLT     8		// double fault
/* #define T_COPROC  9 */	// reserved (not generated by recent processors)
#define T_TSS       10		// invalid task switch segment
#define T_SEGNP     11		// segment not present
#define T_STACK     12		// stack exception
#define T_GPFLT     13		// genernal protection fault
#define T_PGFLT     14		// page fault
/* #define T_RES    15 */	// reserved
#define T_FPERR     16		// floating point error
#define T_ALIGN     17		// aligment check
#define T_MCHK      18		// machine check
#define T_SIMDERR   19		// SIMD floating point error

/* 32-47 are PIC/8259 IRQ vectors */
#define IdtPIC					32
#define IrqCLOCK				0
#define IrqKBD					1
#define IrqUART1				3
#define IrqUART0				4
#define IrqPCMCIA				5
#define IrqFLOPPY				6
#define IrqLPT					7
#define IrqAUX					12	/* PS/2 port */
#define IrqIRQ13				13	/* coprocessor on 386 */
#define IrqATA0					14
#define IrqATA1					15
#define MaxIrqPIC				15
#define MaxIdtPIC				(IdtPIC + MaxIrqPIC)

/* 48-63 are LAPIC vectors */
#define IdtLAPIC				(IdtPIC + 16)
#define IdtLAPIC_LINT0			(IdtLAPIC + 0)
#define IdtLAPIC_LINT1			(IdtLAPIC + 1)
#define IdtLAPIC_TIMER			(IdtLAPIC + 2)
#define IdtLAPIC_ERROR			(IdtLAPIC + 3)
#define IdtLAPIC_PCINT			(IdtLAPIC + 4)
/* Plan 9 apic note: the spurious vector number must have bits 3-0 0x0f
 * unless the Extended Spurious Vector Enable bit is set in the
 * HyperTransport Transaction Control register.  Plan 9 used 63 (0x3f), but
 * 55 should have worked too (0x37). */
#define IdtLAPIC_SPURIOUS		(IdtLAPIC + 15) /* Aka 63, 0x3f */
#define MaxIdtLAPIC				(IdtLAPIC + 15)

/* T_SYSCALL is defined by the following include (64) */
#include <ros/arch/syscall.h>

/* 65-229 are IOAPIC routing vectors (from IOAPIC to LAPIC) */
#define IdtIOAPIC				(T_SYSCALL + 1)
#define MaxIdtIOAPIC			229
/* 230-255 are OS IPI vectors */
#define IdtMAX					255


#define T_DEFAULT   0x0000beef		// catchall

/* Floating point constants */
#define FP_EXCP_IE				(1 << 0)	/* invalid op */
#define FP_EXCP_DE				(1 << 1)	/* denormalized op */
#define FP_EXCP_ZE				(1 << 2)	/* div by zero */
#define FP_EXCP_OE				(1 << 3)	/* numeric overflow */
#define FP_EXCP_UE				(1 << 4)	/* numeric underflow */
#define FP_EXCP_PE				(1 << 5)	/* precision */

#define FP_SW_SF				(1 << 6)	/* stack fault */
#define FP_SW_ES				(1 << 7)	/* error summary status */
#define FP_SW_C0				(1 << 8)	/* condition codes */
#define FP_SW_C1				(1 << 9)
#define FP_SW_C2				(1 << 10)
#define FP_SW_C3				(1 << 14)
#define FP_CW_TOP_SHIFT			(11)
#define FP_CW_TOP_MASK			(7 << FP_CW_TOP_SHIFT)

#define FP_CW_PC_SHIFT			(8)
#define FP_CW_PC_MASK			(3 << FP_CW_PC_SHIFT)
#define FP_CW_RC_SHIFT			(10)
#define FP_CW_RC_MASK			(3 << FP_CW_RC_SHIFT)
#define FP_CW_IC				(1 << 12)

/* IPIs */
/* Testing IPI (used in testing.c) */
#define I_TESTING		230
/* smp_call_function IPIs, keep in sync with NUM_HANDLER_WRAPPERS (and < 16)
 * it's important that this begins with 0xf0.  check i386/trap.c for details. */
#define I_SMP_CALL0 	0xf0 // 240
#define I_SMP_CALL1 	0xf1
#define I_SMP_CALL2 	0xf2
#define I_SMP_CALL3 	0xf3
#define I_SMP_CALL4 	0xf4
#define I_SMP_CALL_LAST I_SMP_CALL4
/* Direct/Hardwired IPIs.  Hardwired in trapentry.S */
#define I_KERNEL_MSG	255

#ifndef __ASSEMBLER__

#ifndef ROS_KERN_TRAP_H
#error "Do not include include arch/trap.h directly"
#endif

#include <ros/common.h>
#include <arch/mmu.h>
#include <ros/trapframe.h>
#include <arch/pci.h>
#include <arch/pic.h>
#include <arch/coreid.h>
#include <arch/io.h>

struct irq_handler {
	struct irq_handler *next;
	void (*isr)(struct hw_trapframe *hw_tf, void *data);
	void *data;

	/* all handlers in the chain need to have the same func pointers.  we only
	 * really use the first one, and the latter are to catch bugs.  also, we
	 * won't be doing a lot of IRQ line sharing */
	bool (*check_spurious)(int);
	void (*eoi)(int);
	void (*mask)(int);
	void (*unmask)(int);

	int pci_tbdf;
	int dev_irq;
	int apic_vector;

	char *type;
	#define IRQ_NAME_LEN 26
	char name[IRQ_NAME_LEN];
};

static bool idt_vec_is_pic(int vec)
{
	return (IdtPIC <= vec) && (vec <= MaxIdtPIC);
}

static bool idt_vec_is_lapic(int vec)
{
	return (IdtLAPIC <= vec) && (vec <= MaxIdtLAPIC);
}

/* The kernel's interrupt descriptor table */
extern gatedesc_t idt[];
extern pseudodesc_t idt_pd;
extern taskstate_t ts;
/* Mapping of irq -> PCI device (TODO: make this PCI-agnostic) */
extern struct pci_device *irq_pci_map[NUM_IRQS];
extern const char *x86_trapname(int trapno);
extern void sysenter_handler(void);
void backtrace_kframe(struct hw_trapframe *hw_tf);

/* Defined and set up in in arch/init.c, used for XMM initialization */
extern struct ancillary_state x86_default_fpu;

static inline void save_fp_state(struct ancillary_state *silly)
{
	asm volatile("fxsave %0" : : "m"(*silly));
}

/* TODO: this can trigger a GP fault if MXCSR reserved bits are set.  Callers
 * will need to handle intercepting the kernel fault. */
static inline void restore_fp_state(struct ancillary_state *silly)
{
	asm volatile("fxrstor %0" : : "m"(*silly));
}

/* A regular fninit will only initialize the x87 header part of the FPU, not the
 * st(n) (MMX) registers, the XMM registers, or the MXCSR state.  So to init,
 * we'll just keep around a copy of the default FPU state, which we grabbed
 * during boot, and can copy that over.
 *
 * Alternatively, we can fninit, ldmxcsr with the default value, and 0 out all
 * of the registers manually. */
static inline void init_fp_state(void)
{
	restore_fp_state(&x86_default_fpu);
}

static inline void __attribute__((always_inline))
set_stack_pointer(uintptr_t sp)
{
	asm volatile("mov %0,%%"X86_REG_SP"" : : "r"(sp) : "memory", X86_REG_SP);
}

extern segdesc_t *gdt;

#ifdef CONFIG_X86_64
#include <arch/trap64.h>
#else
#include <arch/trap32.h>
#endif

#endif /* !__ASSEMBLER__ */

#endif /* !ROS_INC_ARCH_TRAP_H */
