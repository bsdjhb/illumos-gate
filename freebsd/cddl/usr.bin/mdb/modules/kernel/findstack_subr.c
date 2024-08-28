/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>

#include <sys/proc.h>
#include <machine/frame.h>

#include "findstack.h"
#include "freebsd_thread.h"
#include "kernel.h"

#define	TOO_BIG_FOR_A_STACK (1024 * 1024)

#define	KTOU(p) ((p) - kbase + ubase)
#define	UTOK(p) ((p) - ubase + kbase)

#define	CRAWL_FOUNDALL	(-1)

#if defined(__i386) || defined(__amd64)
struct rwindow {
	uintptr_t rw_fp;
	uintptr_t rw_rtn;
};
#endif

#ifndef STACK_BIAS
#define	STACK_BIAS	0
#endif

#ifdef __amd64__
#define	STACK_ALIGN	16

typedef struct {
	intptr_t	pcb_rip;
	intptr_t	pcb_rsp;
	intptr_t	pcb_rbp;
} mdb_pcb_t;

/* XXX: Use mdb_getareg? */
int
fetch_pc_sp(mdb_thread_t *td, uintptr_t *pc, uintptr_t *sp)
{
	mdb_pcb_t pcb;

	if (mdb_ctf_vread(&pcb, "struct pcb", "mdb_pcb_t",
	    (uintptr_t)td->td_pcb, 0) == -1)
		return (0);

	*pc = pcb.pcb_rip;
	*sp = pcb.pcb_rbp;
	return (1);
}
#else
#error "Unsupported platform"
#endif

/*
 * Given a stack pointer, try to crawl down it to the bottom.
 * "frame" is a VA in MDB's address space.
 *
 * Returns the number of frames successfully crawled down, or
 * CRAWL_FOUNDALL if it got to the bottom of the stack.
 */
static int
crawl(uintptr_t frame, uintptr_t kbase, uintptr_t ktop, uintptr_t ubase,
      int kill_fp, findstack_info_t *fsip)
{
	uintptr_t pc, next_pc;
	char funcname[MDB_TGT_SYM_NAMLEN];
	int levels = 0;
	int hit_bottom = 0;

	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;
	next_pc = (uintptr_t)-1;

	fs_dprintf(("<0> frame = %p, kbase = %p, ktop = %p, ubase = %p\n",
	    frame, kbase, ktop, ubase));
	for (;;) {
		uintptr_t fp;
		long *fpp = (long *)&((struct rwindow *)frame)->rw_fp;

		fs_dprintf(("<1> fpp = %p, frame = %p\n", fpp, frame));

		if ((frame & (STACK_ALIGN - 1)) != 0)
			break;

		fp = ((struct rwindow *)frame)->rw_fp + STACK_BIAS;
		if (next_pc != (uintptr_t)-1) {
			pc = next_pc;
			next_pc = (uintptr_t)-1;
		} else
			pc = ((struct rwindow *)frame)->rw_rtn;
#ifdef __amd64__
		if (pc != 0 && mdb_lookup_by_addr(pc, MDB_TGT_SYM_FUZZY,
		    funcname, sizeof(funcname), NULL) == 0 &&
		    (strcmp(funcname, "calltrap") == 0 ||
		    strcmp(funcname, "fast_syscall_common") == 0 ||
		    strcmp(funcname, "fork_trampoline") == 0 ||
		    strcmp(funcname, "mchk_calltrap") == 0 ||
		    strcmp(funcname, "nmi_calltrap") == 0 ||
		    strcmp(funcname, "Xdblfault") == 0 ||
		    strncmp(funcname, "Xatpic_intr", 11) == 0 ||
		    strncmp(funcname, "Xapic_isr", 9) == 0 ||
		    strcmp(funcname, "Xtimerint") == 0 ||
		    strcmp(funcname, "Xipi_intr_bitmap_handler") == 0 ||
		    strcmp(funcname, "Xcpustop") == 0 ||
		    strcmp(funcname, "Xcpususpend") == 0 ||
		    strcmp(funcname, "Xrendezvous") == 0 ||
		    strcmp(funcname, "Xfast_syscall") == 0 ||
		    strcmp(funcname, "Xint0x80_syscall") == 0 ||
		    strcmp(funcname, "Xtimerint") == 0 ||
		    strcmp(funcname, "Xcpustop") == 0 ||
		    strcmp(funcname, "Xcpususpend") == 0 ||
		    strcmp(funcname, "Xrendezvous") == 0 ||
		    strcmp(funcname, "Xipi_intr_bitmap_handler") == 0)) {
			struct trapframe *tf;

			tf = (struct trapframe *)(frame + 16);
			next_pc = tf->tf_rip;
			fp = tf->tf_rbp;
			fpp = &tf->tf_rbp;

			if (strcmp(funcname, "fork_trampoline") == 0 ||
			    next_pc < 0x0000800000000000)
				hit_bottom = 1;
		}
#endif

		if (fsip->fsi_depth < fsip->fsi_max_depth)
			fsip->fsi_stack[fsip->fsi_depth++] = pc;
		else
			fsip->fsi_overflow = 1;

		fs_dprintf(("<2> fp = %p\n", fp));

		if (fp == ktop || hit_bottom)
			return (CRAWL_FOUNDALL);
		fs_dprintf(("<3> not at base\n"));

#if defined(__i386) || defined(__amd64)
		if (ktop - fp == sizeof (struct rwindow)) {
			fs_dprintf(("<4> found base\n"));
			return (CRAWL_FOUNDALL);
		}
#endif

		fs_dprintf(("<5> fp = %p, kbase = %p, ktop - size = %p\n",
		    fp, kbase, ktop - sizeof (struct rwindow)));

		if (fp < kbase || fp >= (ktop - sizeof (struct rwindow)))
			break;

		frame = KTOU(fp);
		fs_dprintf(("<6> frame = %p\n", frame));

		/*
		 * NULL out the old %fp so we don't go down this stack
		 * more than once.
		 */
		if (kill_fp) {
			fs_dprintf(("<7> fpp = %p\n", fpp));
			*fpp = 0;
		}

		fs_dprintf(("<8> levels = %d\n", levels));
		levels++;
	}

	return (levels);
}

enum mdb_kthread_states
thread_state(mdb_thread_t *td)
{
	mdb_proc_t p;

	if (mdb_ctf_vread(&p, "struct proc", "mdb_proc_t",
	   (uintptr_t)td->td_proc, MDB_CTF_VREAD_QUIET) == -1)
		return (TS_FREE);
	switch (p.p_state) {
	case PRS_NEW:
		return (TS_NEW);
	case PRS_ZOMBIE:
		return (TS_ZOMBIE);
	case PRS_NORMAL:
		switch (td->td_state) {
		case TDS_RUNNING:
			return (TS_RUNNING);
		case TDS_RUNQ:
			return (TS_RUNQ);
		case TDS_CAN_RUN:
			return (TS_CAN_RUN);
		case TDS_INACTIVE:
			return (TS_INACTIVE);
		case TDS_INHIBITED:
			return (TS_INHIBITED);
		}
	}
	return (TS_FREE);
}

int
stacks_findstack(uintptr_t addr, findstack_info_t *fsip, uint_t print_warnings)
{
	mdb_thread_t td;
	size_t stksz;
	uintptr_t ubase, utop;
	uintptr_t kbase, ktop;
	uintptr_t sp, pc, tsp, win;

	fsip->fsi_failed = 0;
	fsip->fsi_pc = 0;
	fsip->fsi_sp = 0;
	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;

	if (mdb_ctf_vread(&td, "struct thread", "mdb_thread_t", addr,
	    print_warnings ? 0 : MDB_CTF_VREAD_QUIET) == -1) {
		fsip->fsi_failed = FSI_FAIL_BADTHREAD;
		return (DCMD_ERR);
	}

	fsip->fsi_wmesg = (uintptr_t)td.td_wmesg;
	fsip->fsi_lockname = (uintptr_t)td.td_lockname;
	fsip->fsi_tstate = thread_state(&td);
	fsip->fsi_panic = !!(td.td_flags & TDF_INPANIC);

	kbase = td.td_kstack;
	stksz = td.td_kstack_pages * PAGE_SIZE;
	ktop = kbase + stksz;

	/*
	 * If the stack size is larger than a meg, assume that it's bogus.
	 */
	if (stksz > TOO_BIG_FOR_A_STACK) {
		if (print_warnings)
			mdb_warn("stack size for thread %p is too big to be "
			    "reasonable\n", addr);
		fsip->fsi_failed = FSI_FAIL_THREADCORRUPT;
		return (DCMD_ERR);
	}

	ubase = (uintptr_t)mdb_alloc(stksz, UM_SLEEP);
	utop = ubase + stksz;
	if (mdb_vread((caddr_t)ubase, stksz, kbase) != (ssize_t)stksz) {
		mdb_free((void *)ubase, stksz);
		if (print_warnings)
			mdb_warn("couldn't read entire stack for thread %p\n",
			    addr);
		fsip->fsi_failed = FSI_FAIL_THREADCORRUPT;
		return (DCMD_ERR);
	}

	/*
	 * Try the saved %sp first, if it looks reasonable.
	 */
	if (fetch_pc_sp(&td, &pc, &tsp)) {
		sp = KTOU(tsp + STACK_BIAS);
		if (sp >= ubase && sp <= utop) {
			if (crawl(sp, kbase, ktop, ubase, 0, fsip) ==
			    CRAWL_FOUNDALL) {
				fsip->fsi_sp = tsp;
				fsip->fsi_pc = pc;
				goto found;
			}
		}
	}

	/*
	 * Now walk through the whole stack, starting at the base,
	 * trying every possible "window".
	 */
	for (win = ubase;
	    win + sizeof (struct rwindow) <= utop;
	    win += sizeof (struct rwindow *)) {
		if (crawl(win, kbase, ktop, ubase, 1, fsip) == CRAWL_FOUNDALL) {
			fsip->fsi_sp = UTOK(win) - STACK_BIAS;
			goto found;
		}
	}

	/*
	 * We didn't conclusively find the stack.  So we'll take another lap,
	 * and print out anything that looks possible.
	 */
	if (print_warnings)
		mdb_printf("Possible stack pointers for thread %p:\n", addr);
	(void) mdb_vread((caddr_t)ubase, stksz, kbase);

	for (win = ubase;
	    win + sizeof (struct rwindow) <= utop;
	    win += sizeof (struct rwindow *)) {
		uintptr_t fp = ((struct rwindow *)win)->rw_fp;
		int levels;

		if ((levels = crawl(win, kbase, ktop, ubase, 1, fsip)) > 1) {
			if (print_warnings)
				mdb_printf("  %p (%d)\n", fp, levels);
		} else if (levels == CRAWL_FOUNDALL) {
			/*
			 * If this is a live system, the stack could change
			 * between the two mdb_vread(ubase, utop, kbase)'s,
			 * and we could have a fully valid stack here.
			 */
			fsip->fsi_sp = UTOK(win) - STACK_BIAS;
			goto found;
		}
	}

	fsip->fsi_depth = 0;
	fsip->fsi_overflow = 0;
	fsip->fsi_failed = FSI_FAIL_STACKNOTFOUND;

	mdb_free((void *)ubase, stksz);
	return (DCMD_ERR);
found:
	mdb_free((void *)ubase, stksz);
	return (DCMD_OK);	
}

void
stacks_findstack_cleanup(void)
{
}

/*ARGSUSED*/
static void
print_tstate_help(uint_t state, const char *name, void *ignored)
{
	mdb_printf(" %s", name);
}

typedef struct {
	int	refs;
	TAILQ_ENTRY(linker_file) link;
	char	*filename;
	char	*pathname;
	int	id;
	char	*address;
	size_t	size;
	TAILQ_HEAD(, module) modules;
} mdb_linker_file_t;

/*ARGSUSED*/
int
stacks_module_cb(uintptr_t addr, const void *lfp, stacks_module_t *smp)
{
	char mod_modname[MAXPATHLEN];
	mdb_linker_file_t lf;

	if (mdb_ctf_convert(&lf, "struct linker_file", "mdb_linker_file_t",
	    lfp, 0) == -1) {
		mdb_warn("failed to parse struct linker_file at %#lr", addr);
		return (WALK_ERR);
	}

	if (mdb_readstr(mod_modname, sizeof (mod_modname),
	    (uintptr_t)lf.filename) == -1) {
		mdb_warn("failed to read filename in \"linker_files\" walk");
		return (WALK_ERR);
	}

	if (strcmp(smp->sm_name, mod_modname))
		return (WALK_NEXT);

	smp->sm_text = (uintptr_t)lf.address;
	smp->sm_size = lf.size;

	return (WALK_DONE);
}

int
stacks_module(stacks_module_t *smp)
{
	if (mdb_walk("linker_files", (mdb_walk_cb_t)stacks_module_cb, smp) !=
	    0) {
		mdb_warn("cannot walk \"linker_files\"");
		return (-1);
	}

	return (0);
}

void
stacks_help(void)
{
	mdb_printf(
"::stacks processes all of the thread stacks on the system, grouping\n"
"together threads which have the same:\n"
"\n"
"  * Thread state,\n"
"  * PCs in their stack trace.\n"
"\n"
"The default output (no address or options) is just a dump of the thread\n"
"groups in the system.  For a view of active threads, use \"::stacks -i\",\n"
"which filters out inhibited threads.  (Note that those threads may still\n"
"be noteworthy; this is just for a first glance.)  More general filtering\n"
"options are described below, in the \"FILTERS\" section.\n"
"\n"
"::stacks can be used in a pipeline.  The input to ::stacks is one or more\n"
"thread pointers.  For example, to get a summary of threads in a process,\n"
"you can do:\n"
"\n"
"  %<b>procp%</b>::walk thread | ::stacks\n"
"\n"
"When output into a pipe, ::stacks prints all of the threads input,\n"
"filtered by the given filtering options.  This means that multiple\n"
"::stacks invocations can be piped together to achieve more complicated\n"
"filters.  For example, to get threads which have both 'fop_read' and\n"
"'cv_wait_sig_swap' in their stack trace, you could do:\n"
"\n"
"  ::stacks -c fop_read | ::stacks -c cv_wait_sig_swap_core\n"
"\n"
"To get the full list of threads in each group, use the '-a' flag:\n"
"\n"
"  ::stacks -a\n"
"\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>OPTIONS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -a    Print all of the grouped threads, instead of just a count.\n"
"  -f    Force a re-run of the thread stack gathering.\n"
"  -v    Be verbose about thread stack gathering.\n"
"\n");
	mdb_dec_indent(2);
	mdb_printf("%<b>FILTERS%</b>\n");
	mdb_inc_indent(2);
	mdb_printf("%s",
"  -i    Show active threads; equivalent to '-T INHIBITED'.\n"
"  -c func[+offset]\n"
"        Only print threads whose stacks contain func/func+offset.\n"
"  -C func[+offset]\n"
"        Only print threads whose stacks do not contain func/func+offset.\n"
"  -m module\n"
"        Only print threads whose stacks contain functions from module.\n"
"  -M module\n"
"        Only print threads whose stacks do not contain functions from\n"
"        module.\n"
"  -t tstate\n"
"        Only print threads which are in thread state 'tstate'.\n"
"  -T tstate\n"
"        Only print threads which are not in thread state 'tstate'.\n"
"\n");
	mdb_printf("Thread states:");
	thread_walk_states(print_tstate_help, NULL);
	mdb_printf(" panic\n");
}
