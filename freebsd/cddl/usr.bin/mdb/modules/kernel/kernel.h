/*-
 * Copyright (c) 2017 Netflix, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _MDB_KERNEL_H_
#define _MDB_KERNEL_H_

#include <sys/queue.h>

typedef struct {
	struct proc	*td_proc;
	TAILQ_ENTRY(thread) td_plist;
	lwpid_t		td_tid;
	int		td_flags;
	int		td_inhibitors;
	void		*td_wchan;
	const char	*td_wmesg;
	struct turnstile *td_blocked;
	const char	*td_lockname;
	char		td_name[MAXCOMLEN + 1];
	struct pcb	*td_pcb;
#if __FreeBSD_version >= 1300015
	enum td_states	td_state;
#else
	enum {
		TDS_INACTIVE = 0x0,
		TDS_INHIBITED,
		TDS_CAN_RUN,
		TDS_RUNQ,
		TDS_RUNNING
	} td_state;
#endif
	uintptr_t	td_kstack;
	int		td_kstack_pages;
	int		td_oncpu;
} mdb_thread_t;

typedef struct {
	LIST_ENTRY(proc) p_list;
	TAILQ_HEAD(, thread) p_threads;
	struct ucred	*p_ucred;
	struct pstats	*p_stats;
	int		p_flag;
#if __FreeBSD_version >= 1300015
	enum p_states	p_state;
#else
	enum {
		PRS_NEW = 0,
		PRS_NORMAL,
		PRS_ZOMBIE
	} p_state;
#endif
	pid_t		p_pid;
	struct proc	*p_pptr;
	u_int		p_lock;
	char		p_comm[MAXCOMLEN + 1];
	struct pgrp	*p_pgrp;
} mdb_proc_t;

/* XXX: Can't include <vm/vm.h> directly due to conflicts with boolean_t. */
typedef u_char vm_prot_t;	/* protection codes */

#define	VM_PROT_NONE		((vm_prot_t) 0x00)
#define	VM_PROT_READ		((vm_prot_t) 0x01)
#define	VM_PROT_WRITE		((vm_prot_t) 0x02)
#define	VM_PROT_EXECUTE		((vm_prot_t) 0x04)
#define	VM_PROT_COPY		((vm_prot_t) 0x08)	/* copy-on-read */

enum obj_type { OBJT_DEFAULT, OBJT_SWAP, OBJT_VNODE, OBJT_DEVICE, OBJT_PHYS,
		OBJT_DEAD, OBJT_SG, OBJT_MGTDEVICE };
typedef u_char objtype_t;

#define MAP_ENTRY_IS_SUB_MAP		0x0002

typedef struct {
	struct vm_map_entry *next;
	uintptr_t start;
	uintptr_t end;
	union {
		struct vm_object *vm_object;
		struct vm_map *sub_map;
	} object;
	unsigned int eflags;
	vm_prot_t protection;
} mdb_vm_map_entry_t;

typedef struct {
	objtype_t type;
} mdb_vm_object_t;

typedef struct {
	LIST_HEAD(,uma_slab)	uk_part_slab;
	LIST_HEAD(,uma_slab)	uk_free_slab;
	LIST_HEAD(,uma_slab)	uk_full_slab;

	void *uk_allocf;

	LIST_ENTRY(uma_keg)	uk_link;
} mdb_uma_keg_t;

typedef struct {
	union {
		LIST_ENTRY(uma_slab)	_us_link;
		unsigned long	_us_size;
	} us_type;
	uint8_t		*us_data;
} mdb_uma_slab_t;

TAILQ_HEAD(pglist, vm_page);

extern int mbuf_walk_init(mdb_walk_state_t *);
extern int mbuf_walk_step(mdb_walk_state_t *);
extern void mbuf_walk_fini(mdb_walk_state_t *);
extern int vm_map_walk_init(mdb_walk_state_t *);
extern int vm_map_walk_step(mdb_walk_state_t *);
extern void vm_map_walk_fini(mdb_walk_state_t *);
extern int vm_pglist_walk_init(mdb_walk_state_t *);
extern int vm_pglist_walk_step(mdb_walk_state_t *);
extern void vm_pglist_walk_fini(mdb_walk_state_t *);
extern int uma_keg_walk_init(mdb_walk_state_t *);
extern int uma_keg_walk_step(mdb_walk_state_t *);
extern void uma_keg_walk_fini(mdb_walk_state_t *);
extern int uma_slab_walk_init(mdb_walk_state_t *);
extern int uma_slab_walk_step(mdb_walk_state_t *);
extern void uma_slab_walk_fini(mdb_walk_state_t *);

#endif  /* _MDB_KERNEL_H_ */
