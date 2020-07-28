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

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_ctf.h>
#include <mdb/mdb_ks.h>

#include "kernel.h"

typedef struct {
	mdb_vm_map_entry_t header;
} mdb_vm_map_t;

typedef struct {
	struct pglist	pq_pl;
} mdb_vm_pagequeue_t;

typedef struct {
	union {
		TAILQ_ENTRY(vm_page) q;
		struct {
			SLIST_ENTRY(vm_page) ss;
			void *pv;
		} s;
		struct {
			u_long p;
			u_long v;
		} memguard;
	} plinks;
} mdb_vm_page_t;

static ssize_t struct_vm_map_entry_size;
static ssize_t struct_vm_page_size;
static ssize_t struct_uma_keg_size;
static ssize_t struct_uma_slab_size;

int
vm_map_walk_init(mdb_walk_state_t *wsp)
{
	mdb_vm_map_t map;

	/*
	 * This walker requires the address of a vm_map as the
	 * starting address.
	 */
	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (struct_vm_map_entry_size == 0)
		struct_vm_map_entry_size = mdb_type_size("struct vm_map_entry");
	if (struct_vm_map_entry_size == -1) {
		mdb_warn("failed to lookup size of 'struct vm_map_entry'");
		return (WALK_ERR);
	}

	if (mdb_ctf_vread(&map, "struct vm_map", "mdb_vm_map_t", wsp->walk_addr,
	    0) == -1) {
		mdb_warn("failed to read struct vm_map at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_data = (void *)wsp->walk_addr;
	wsp->walk_addr = (uintptr_t)map.header.right;

	return (WALK_NEXT);
}

int
vm_map_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtentry[struct_vm_map_entry_size];
	mdb_vm_map_entry_t entry;
	int	status;

	if (wsp->walk_addr == (uintptr_t)wsp->walk_data)
		return (WALK_DONE);

	if (mdb_vread(tgtentry, sizeof (tgtentry), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct vm_map_entry at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&entry, "struct vm_map_entry", "mdb_vm_map_entry_t",
	    tgtentry, 0) == -1) {
		mdb_warn("failed to parse struct vm_map_entry at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtentry, wsp->walk_cbdata);

	
	wsp->walk_addr = (uintptr_t)entry.right;

	return (status);
}

void
vm_map_walk_fini(mdb_walk_state_t *wsp)
{
}

int
vm_pglist_walk_init(mdb_walk_state_t *wsp)
{
	mdb_vm_pagequeue_t pq;

	/*
	 * This walker requires the address of a VM page queue as the
	 * starting address.
	 */
	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (struct_vm_page_size == 0)
		struct_vm_page_size = mdb_type_size("struct vm_page");
	if (struct_vm_page_size == -1) {
		mdb_warn("failed to lookup size of 'struct vm_page'");
		return (WALK_ERR);
	}

	if (mdb_ctf_vread(&pq, "struct vm_pagequeue", "mdb_vm_pagequeue_t",
	    wsp->walk_addr, 0) == -1) {
		mdb_warn("failed to read struct vm_pagequeue at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)TAILQ_FIRST(&pq.pq_pl);

	return (WALK_NEXT);
}

int
vm_pglist_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtpage[struct_vm_page_size];
	mdb_vm_page_t p;
	int	status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(tgtpage, sizeof (tgtpage), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct vm_page at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&p, "struct vm_page", "mdb_vm_page_t", tgtpage,
	    0) == -1) {
		mdb_warn("failed to parse struct vm_page at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtpage, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)TAILQ_NEXT(&p, plinks.q);

	return (status);
}

void
vm_pglist_walk_fini(mdb_walk_state_t *wsp)
{
}

int
uma_keg_walk_init(mdb_walk_state_t *wsp)
{

	if (struct_uma_keg_size == 0)
		struct_uma_keg_size = mdb_type_size("struct uma_keg");
	if (struct_uma_keg_size == -1) {
		mdb_warn("failed to lookup size of 'struct uma_keg'");
		return (WALK_ERR);
	}

	if (wsp->walk_addr == 0) {
		wsp->walk_addr = mdb_list_first("uma_kegs");
		if (wsp->walk_addr == (uintptr_t)-1)
			return (WALK_ERR);
	}
		
	return (WALK_NEXT);
}

int
uma_keg_walk_step(mdb_walk_state_t *wsp)
{
	uint8_t tgtkeg[struct_uma_keg_size];
	mdb_uma_keg_t keg;
	int	status;

	if (wsp->walk_addr == 0)
		return (WALK_DONE);

	if (mdb_vread(tgtkeg, sizeof (tgtkeg), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct uma_keg at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&keg, "struct uma_keg", "mdb_uma_keg_t",
	    tgtkeg, 0) == -1) {
		mdb_warn("failed to parse struct uma_keg at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtkeg, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)LIST_NEXT(&keg, uk_link);

	return (status);
}

void
uma_keg_walk_fini(mdb_walk_state_t *wsp)
{
}

struct uma_domain;

struct slab_walk_state {
	mdb_uma_keg_t keg;
	mdb_uma_domain_t dom;
	int domain_index;
	struct uma_domain *doms;
	enum { FREE, FULL, DONE } state;
};

static int struct_uma_domain_size;
static int vm_ndomains;

int
uma_slab_walk_init(mdb_walk_state_t *wsp)
{
	struct slab_walk_state *ws;
	struct uma_domain *doms;
	size_t size;

	/*
	 * This walker requires the address of a UMA keg as the
	 * starting address.
	 */
	if (wsp->walk_addr == 0)
		return (WALK_ERR);

	if (struct_uma_keg_size == 0)
		struct_uma_keg_size = mdb_type_size("struct uma_keg");
	if (struct_uma_domain_size == 0)
		struct_uma_domain_size = mdb_type_size("struct uma_domain");

	if (vm_ndomains == 0) {
		GElf_Sym sym;
		unsigned long vm_nd_addr;

		if (mdb_lookup_by_name("vm_ndomains", &sym) == -1)
			vm_ndomains = 1;
		else {
			vm_nd_addr = sym.st_value;
			if (mdb_ctf_vread(&vm_ndomains,
				"int", "int", vm_nd_addr, 0) != 0) {
				vm_ndomains = 1;
			}
		}
	}

	size = struct_uma_domain_size * vm_ndomains;
	doms = mdb_alloc(size, UM_SLEEP);
	if (mdb_vread(doms,  size,
		wsp->walk_addr + struct_uma_keg_size) == -1) {
		mdb_warn("failed to read struct uma_domain at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}
	if (struct_uma_slab_size == 0)
		struct_uma_slab_size = mdb_type_size("struct uma_slab");
	if (struct_uma_slab_size == -1) {
		mdb_warn("failed to lookup size of 'struct uma_slab'");
		return (WALK_ERR);
	}

	ws = mdb_alloc(sizeof(*ws), UM_SLEEP);
	if (mdb_ctf_vread(&ws->keg, "struct uma_keg", "mdb_uma_keg_t",
	    wsp->walk_addr, 0) == -1) {
		mdb_warn("failed to read struct uma_keg at %#lr",
		    wsp->walk_addr);
		mdb_free(doms, size);
		mdb_free(ws, sizeof(*ws));
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)&ws->keg.uk_domain;

	if (mdb_ctf_convert(&ws->dom, "struct uma_domain", "mdb_uma_domain_t",
	    doms, 0) == -1) {
		mdb_warn("failed to read struct uma_domain at %#lr",
		    wsp->walk_addr);
		mdb_free(doms, size);
		mdb_free(ws, sizeof(*ws));
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)LIST_FIRST(&ws->dom.ud_part_slab);
	ws->state = FREE;
	ws->doms = doms;
	ws->domain_index = 0;
	wsp->walk_data = ws;

	return (WALK_NEXT);
}

int
uma_slab_walk_step(mdb_walk_state_t *wsp)
{
	struct slab_walk_state *ws;
	uint8_t tgtslab[struct_uma_slab_size];
	mdb_uma_slab_t slab;
	int	status;
	size_t  offset;

again:
	ws = wsp->walk_data;
	while (wsp->walk_addr == 0) {
		switch (ws->state) {
		case FREE:
			wsp->walk_addr = (uintptr_t)LIST_FIRST(
			    &ws->dom.ud_free_slab);
			ws->state = FULL;
			break;
		case FULL:
			wsp->walk_addr = (uintptr_t)LIST_FIRST(
			    &ws->dom.ud_full_slab);
			ws->state = DONE;
			break;
		default:
			ws->domain_index++;
			if (ws->domain_index == vm_ndomains)
				return (WALK_DONE);

			offset = struct_uma_domain_size * ws->domain_index;
			if (mdb_ctf_convert(&ws->dom, "struct uma_domain",
				"mdb_uma_domain_t",
				(char *)ws->doms + offset, 0) == -1) {
				mdb_warn("failed to read struct uma_domain at %#lr",
				    wsp->walk_addr);
				return (WALK_DONE);
			}
			wsp->walk_addr =
				(uintptr_t)LIST_FIRST(&ws->dom.ud_part_slab);
			ws->state = FREE;
			goto again;
		}
	}

	if (mdb_vread(tgtslab, sizeof (tgtslab), wsp->walk_addr) == -1) {
		mdb_warn("failed to read struct uma_slab at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	if (mdb_ctf_convert(&slab, "struct uma_slab", "mdb_uma_slab_t",
	    tgtslab, 0) == -1) {
		mdb_warn("failed to parse struct uma_slab at %#lr",
		    wsp->walk_addr);
		return (WALK_ERR);
	}

	status = wsp->walk_callback(wsp->walk_addr, tgtslab, wsp->walk_cbdata);

	wsp->walk_addr = (uintptr_t)LIST_NEXT(&slab, us_link);

	return (status);
}

void
uma_slab_walk_fini(mdb_walk_state_t *wsp)
{
	struct slab_walk_state *ws;
	size_t size;

	size = struct_uma_domain_size * vm_ndomains;
	ws = wsp->walk_data;
	mdb_free(ws->doms, size);
	mdb_free(ws, sizeof(struct slab_walk_state));
}
