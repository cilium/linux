// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2018 Netronome Systems, Inc. */
/* This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#include <linux/bpf_verifier.h>
#include <linux/list.h>
#include <linux/slab.h>

#include "cfg.h"

struct edge_node {
	struct list_head l;
	struct bb_node *src;
	struct bb_node *dst;
};

struct edge_iter {
	struct list_head *list_head;
	struct edge_node *edge;
};

#define first_edge(e_list)	list_first_entry(e_list, struct edge_node, l)
#define last_edge(e_list)	list_last_entry(e_list, struct edge_node, l)
#define next_edge(e)		list_next_entry(e, l)

static bool ei_end_p(struct edge_iter *ei)
{
	return &ei->edge->l == ei->list_head;
}

static void ei_next(struct edge_iter *ei)
{
	struct edge_node *e = ei->edge;

	ei->edge = next_edge(e);
}

struct bb_node {
	struct list_head l;
	struct list_head e_prevs;
	struct list_head e_succs;
	u16 head;
	u16 idx;
};

#define bb_prev(bb)		list_prev_entry(bb, l)
#define bb_next(bb)		list_next_entry(bb, l)
#define bb_first(bb_list)	list_first_entry(bb_list, struct bb_node, l)
#define bb_last(bb_list)	list_last_entry(bb_list, struct bb_node, l)
#define entry_bb(bb_list)	bb_first(bb_list)
#define exit_bb(bb_list)	bb_last(bb_list)

struct dom_info {
	u16 *dfs_parent;
	u16 *dfs_order;
	struct bb_node **dfs_to_bb;
	/* immediate-dominator */
	u16 *idom;
	/* semi-dominator */
	u16 *sdom;
	u16 *bucket;
	u16 *next_bucket;
	/* best node during path compression. */
	u16 *best;
	/* ancestor along tree edge. */
	u16 *ancestor;
	/* size and child are used for tree balancing. */
	u16 *size;
	u16 *child;

	u16 dfsnum;
};

int subprog_append_bb(struct list_head *bb_list, int head)
{
	struct bb_node *new_bb, *bb;

	list_for_each_entry(bb, bb_list, l) {
		if (bb->head == head)
			return 0;
		else if (bb->head > head)
			break;
	}

	bb = bb_prev(bb);
	new_bb = kzalloc(sizeof(*new_bb), GFP_KERNEL);
	if (!new_bb)
		return -ENOMEM;

	INIT_LIST_HEAD(&new_bb->e_prevs);
	INIT_LIST_HEAD(&new_bb->e_succs);
	new_bb->head = head;
	list_add(&new_bb->l, &bb->l);

	return 0;
}

int subprog_fini_bb(struct list_head *bb_list, int subprog_end)
{
	struct bb_node *bb = kzalloc(sizeof(*bb), GFP_KERNEL);

	if (!bb)
		return -ENOMEM;
	/* entry bb. */
	bb->head = -1;
	INIT_LIST_HEAD(&bb->e_prevs);
	INIT_LIST_HEAD(&bb->e_succs);
	list_add(&bb->l, bb_list);

	bb = kzalloc(sizeof(*bb), GFP_KERNEL);
	if (!bb)
		return -ENOMEM;
	/* exit bb. */
	bb->head = subprog_end;
	INIT_LIST_HEAD(&bb->e_prevs);
	INIT_LIST_HEAD(&bb->e_succs);
	list_add_tail(&bb->l, bb_list);

	return 0;
}

int subprog_init_bb(struct list_head *bb_list, int subprog_start)
{
	int ret;

	INIT_LIST_HEAD(bb_list);
	ret = subprog_append_bb(bb_list, subprog_start);
	if (ret < 0)
		return ret;

	return 0;
}

static struct bb_node *search_bb_with_head(struct list_head *bb_list, int head)
{
	struct bb_node *bb;

	list_for_each_entry(bb, bb_list, l) {
		if (bb->head == head)
			return bb;
	}

	return NULL;
}

int subprog_add_bb_edges(struct bpf_insn *insns, struct list_head *bb_list)
{
	struct bb_node *bb, *exit_bb;
	struct edge_node *edge;
	int bb_num;

	bb = entry_bb(bb_list);
	edge = kcalloc(2, sizeof(*edge), GFP_KERNEL);
	if (!edge)
		return -ENOMEM;
	edge->src = bb;
	edge->dst = bb_next(bb);
	list_add_tail(&edge->l, &bb->e_succs);
	edge[1].src = edge->src;
	edge[1].dst = edge->dst;
	list_add_tail(&edge[1].l, &edge[1].dst->e_prevs);
	bb->idx = -1;

	exit_bb = exit_bb(bb_list);
	exit_bb->idx = -2;
	bb = bb_next(bb);
	bb_num = 0;
	list_for_each_entry_from(bb, &exit_bb->l, l) {
		bool has_fallthrough, only_has_fallthrough;
		bool has_branch, only_has_branch;
		struct bb_node *next_bb = bb_next(bb);
		int tail = next_bb->head - 1;
		struct bpf_insn insn;
		u8 code;

		bb->idx = bb_num++;

		edge = kcalloc(2, sizeof(*edge), GFP_KERNEL);
		if (!edge)
			return -ENOMEM;
		edge->src = bb;
		edge[1].src = bb;

		insn = insns[tail];
		code = insn.code;
		only_has_fallthrough = BPF_CLASS(code) != BPF_JMP ||
				       BPF_OP(code) == BPF_EXIT;
		has_fallthrough = only_has_fallthrough ||
				  (BPF_CLASS(code) == BPF_JMP &&
				   BPF_OP(code) != BPF_CALL &&
				   BPF_OP(code) != BPF_JA);
		only_has_branch = BPF_CLASS(code) == BPF_JMP &&
				  BPF_OP(code) == BPF_JA;
		has_branch = only_has_branch ||
			     (BPF_CLASS(code) == BPF_JMP &&
			      BPF_OP(code) != BPF_EXIT &&
			      BPF_OP(code) != BPF_CALL);

		if (has_fallthrough) {
			if (BPF_CLASS(code) == BPF_JMP &&
			    BPF_OP(code) == BPF_EXIT)
				next_bb = exit_bb;
			edge->dst = next_bb;
			edge[1].dst = next_bb;
			list_add_tail(&edge->l, &bb->e_succs);
			list_add_tail(&edge[1].l, &edge[1].dst->e_prevs);
			edge = NULL;
		}

		if (has_branch) {
			struct bb_node *tgt;

			if (!edge) {
				edge = kcalloc(2, sizeof(*edge), GFP_KERNEL);
				if (!edge)
					return -ENOMEM;
				edge->src = bb;
				edge[1].src = bb;
			}

			tgt = search_bb_with_head(bb_list,
						  tail + insn.off + 1);
			if (!tgt)
				return -EINVAL;

			edge->dst = tgt;
			edge[1].dst = tgt;
			list_add_tail(&edge->l, &bb->e_succs);
			list_add_tail(&edge[1].l, &tgt->e_prevs);
		}
	}

	return bb_num + 2;
}

static int init_dom_info(struct bpf_subprog_info *subprog, struct dom_info *di)
{
	u16 *p, bb_num, i;

	di->dfs_parent = NULL;
	di->dfs_to_bb = NULL;

	bb_num = subprog->bb_num;
	p = kcalloc(10 * bb_num, sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	di->dfs_parent = p;
	di->dfs_order = di->dfs_parent + bb_num;
	di->idom = di->dfs_order + bb_num;
	di->sdom = di->idom + bb_num;
	di->bucket = di->sdom + bb_num;
	di->next_bucket = di->bucket + bb_num;
	di->best = di->next_bucket + bb_num;
	di->ancestor = di->best + bb_num;
	di->size = di->ancestor + bb_num;
	di->child = di->size + bb_num;
	di->dfs_to_bb = kcalloc(bb_num, sizeof(struct bb_node *), GFP_KERNEL);
	di->dfsnum = 1;

	for (i = 0; i < bb_num; i++) {
		di->size[i] = 1;
		di->best[i] = i;
		di->sdom[i] = i;
	}

	return 0;
}

static void compress_path(struct dom_info *di, unsigned int v)
{
	unsigned int parent = di->ancestor[v];

	if (di->ancestor[parent]) {
		compress_path(di, parent);

		if (di->sdom[di->best[parent]] < di->sdom[di->best[v]])
			di->best[v] = di->best[parent];

		di->ancestor[v] = di->ancestor[parent];
	}
}

static unsigned int eval(struct dom_info *di, unsigned int v)
{
	unsigned int ancestor = di->ancestor[v];

	/* v is root. */
	if (!ancestor)
		return di->best[v];

	/* compress path */
	compress_path(di, v);
	ancestor = di->ancestor[v];

	if (di->sdom[di->best[ancestor]] >= di->sdom[di->best[v]])
		return di->best[v];
	else
		return di->best[ancestor];
}

/* Re-balancing the tree before linking. */
static void link(struct dom_info *di, unsigned int v, unsigned int w)
{
	unsigned int s = w;

	while (di->sdom[di->best[w]] < di->sdom[di->best[di->child[s]]]) {
		if (di->size[s] + di->size[di->child[di->child[s]]] >=
			2 * di->size[di->child[s]]) {
			di->ancestor[di->child[s]] = s;
			di->child[s] = di->child[di->child[s]];
		} else {
			di->size[di->child[s]] = di->size[s];
			di->ancestor[s] = di->child[s];
			s = di->child[s];
		}
	}

	di->best[s] = di->best[w];
	di->size[v] += di->size[w];
	if (di->size[v] < 2 * di->size[w]) {
		unsigned int t = s;

		s = di->child[v];
		di->child[v] = t;
	}

	while (s) {
		di->ancestor[s] = v;
		s = di->child[s];
	}
}

static void calc_idoms(struct bpf_subprog_info *subprog, struct dom_info *di,
		       bool reverse)
{
	u16 entry_bb_fake_idx = subprog->bb_num - 2, idx, w, k, par;
	struct list_head *bb_list = &subprog->bbs;
	struct bb_node *entry_bb;
	struct edge_iter ei;

	if (reverse)
		entry_bb = exit_bb(bb_list);
	else
		entry_bb = entry_bb(bb_list);
	idx = di->dfsnum - 1;

	while (idx > 1) {
		struct bb_node *bb = di->dfs_to_bb[idx];
		struct edge_node *e;

		par = di->dfs_parent[idx];
		k = idx;

		if (reverse) {
			ei.edge = first_edge(&bb->e_succs);
			ei.list_head = &bb->e_succs;
		} else {
			ei.edge = first_edge(&bb->e_prevs);
			ei.list_head = &bb->e_prevs;
		}

		while (!ei_end_p(&ei)) {
			struct bb_node *b;
			u16 k1;

			e = ei.edge;
			if (reverse)
				b = e->dst;
			else
				b = e->src;
			ei_next(&ei);

			if (b == entry_bb)
				k1 = di->dfs_order[entry_bb_fake_idx];
			else
				k1 = di->dfs_order[b->idx];

			if (k1 > idx)
				k1 = di->sdom[eval(di, k1)];
			if (k1 < k)
				k = k1;
		}

		di->sdom[idx] = k;
		link(di, par, idx);
		di->next_bucket[idx] = di->bucket[k];
		di->bucket[k] = idx;

		for (w = di->bucket[par]; w; w = di->next_bucket[w]) {
			k = eval(di, w);
			if (di->sdom[k] < di->sdom[w])
				di->idom[w] = k;
			else
				di->idom[w] = par;
		}
		di->bucket[par] = 0;
		idx--;
	}

	di->idom[1] = 0;
	for (idx = 2; idx <= di->dfsnum - 1; idx++)
		if (di->idom[idx] != di->sdom[idx])
			di->idom[idx] = di->idom[di->idom[idx]];
}

static int calc_dfs_tree(struct bpf_subprog_info *subprog, struct dom_info *di,
			 bool reverse)
{
	u16 bb_num = subprog->bb_num, sp = 0, idx, parent_idx;
	struct list_head *bb_list = &subprog->bbs;
	u16 entry_bb_fake_idx = bb_num - 2;
	struct bb_node *entry_bb, *exit_bb;
	struct edge_iter ei, *stack;
	struct edge_node *e;

	di->dfs_order[entry_bb_fake_idx] = di->dfsnum;

	stack = kmalloc_array(bb_num - 1, sizeof(struct edge_iter), GFP_KERNEL);
	if (!stack)
		return -ENOMEM;

	if (reverse) {
		entry_bb = exit_bb(bb_list);
		exit_bb = entry_bb(bb_list);
		di->dfs_to_bb[di->dfsnum++] = exit_bb;
		ei.edge = first_edge(&entry_bb->e_prevs);
		ei.list_head = &entry_bb->e_prevs;
	} else {
		entry_bb = entry_bb(bb_list);
		exit_bb = exit_bb(bb_list);
		di->dfs_to_bb[di->dfsnum++] = entry_bb;
		ei.edge = first_edge(&entry_bb->e_succs);
		ei.list_head = &entry_bb->e_succs;
	}

	while (1) {
		struct bb_node *bb_dst, *bb_src;

		while (!ei_end_p(&ei)) {
			e = ei.edge;

			if (reverse) {
				bb_dst = e->src;
				if (bb_dst == exit_bb ||
				    di->dfs_order[bb_dst->idx]) {
					ei_next(&ei);
					continue;
				}
				bb_src = e->dst;
			} else {
				bb_dst = e->dst;
				if (bb_dst == exit_bb ||
				    di->dfs_order[bb_dst->idx]) {
					ei_next(&ei);
					continue;
				}
				bb_src = e->src;
			}

			if (bb_src != entry_bb)
				parent_idx = di->dfs_order[bb_src->idx];
			else
				parent_idx = di->dfs_order[entry_bb_fake_idx];

			idx = di->dfsnum++;
			di->dfs_order[bb_dst->idx] = idx;
			di->dfs_to_bb[idx] = bb_dst;
			di->dfs_parent[idx] = parent_idx;

			stack[sp++] = ei;
			if (reverse) {
				ei.edge = first_edge(&bb_dst->e_prevs);
				ei.list_head = &bb_dst->e_prevs;
			} else {
				ei.edge = first_edge(&bb_dst->e_succs);
				ei.list_head = &bb_dst->e_succs;
			}
		}

		if (!sp)
			break;

		ei = stack[--sp];
		ei_next(&ei);
	}

	kfree(stack);

	return 0;
}

static int idoms_to_doms(struct bpf_subprog_info *subprog, struct dom_info *di)
{
	int bb_num, i, end_index, bb, bb_idom, lane_len;
	unsigned long *bitmap;

	bb_num = subprog->bb_num - 2;
	lane_len = BITS_TO_LONGS(bb_num);
	bitmap = kcalloc(bb_num, lane_len * sizeof(long), GFP_KERNEL);
	subprog->dtree = bitmap;
	if (!subprog->dtree)
		return -ENOMEM;
	subprog->dtree_avail = true;
	end_index = di->dfs_order[bb_num];

	for (i = 1; i <= di->dfsnum - 1; i++) {
		if (i == end_index)
			continue;

		bb = di->dfs_to_bb[i]->idx;
		if (di->idom[i] && di->idom[i] != end_index) {
			bb_idom = di->dfs_to_bb[di->idom[i]]->idx;
			bitmap_copy(bitmap + bb * lane_len,
				    bitmap + bb_idom * lane_len, bb_num);
		}

		bitmap_set(bitmap + bb * lane_len, bb, 1);
	}

	return 0;
}

/* Build domination information using Lengauer and Tarjan algorithm.
 *
 *   1. dfs on cfg to assign dfs-num for each node(bb).
 *   2. calculate semi-dominator and calculate immediate dominator when
 *      possible.
 *   3. calculate immediate dominator not finished during step 2.
 *   4. build domination bitmap using immediate dominator information.
 *
 * See:
 *   A fast algorithm for finding dominators in a flowgraph.
 *     - 1979, by T Lengauer and R Tarjan
 *
 *   Especially, Appendix B: The Complete Dominators Algorithms.
 *
 * The implementation also referenced GNU GCC 3.0.
 */

int subprog_build_dom_info(struct bpf_subprog_info *subprog)
{
	struct dom_info di;
	int ret;

	ret = init_dom_info(subprog, &di);
	if (ret < 0)
		goto free_dominfo;

	ret = calc_dfs_tree(subprog, &di, false);
	if (ret < 0)
		goto free_dominfo;

	calc_idoms(subprog, &di, false);
	ret = idoms_to_doms(subprog, &di);
	if (ret < 0)
		goto free_dominfo;

	ret = 0;

free_dominfo:
	if (di.dfs_parent)
		kfree(di.dfs_parent);

	return ret;
}

bool subprog_has_loop(struct bpf_subprog_info *subprog)
{
	int lane_len = BITS_TO_LONGS(subprog->bb_num - 2);
	struct list_head *bb_list = &subprog->bbs;
	struct bb_node *bb, *entry_bb;
	struct edge_node *e;

	entry_bb = entry_bb(bb_list);
	bb = bb_next(entry_bb);
	list_for_each_entry_from(bb, &exit_bb(bb_list)->l, l)
		list_for_each_entry(e, &bb->e_prevs, l) {
			struct bb_node *latch = e->src;

			if (latch != entry_bb &&
			    test_bit(bb->idx,
				     subprog->dtree + latch->idx * lane_len))
				return true;
		}

	return false;
}

static void subprog_free_edge(struct bb_node *bb)
{
	struct list_head *succs = &bb->e_succs;
	struct edge_node *e, *tmp;

	/* prevs and succs are allocated as pair, succs is the start addr. */
	list_for_each_entry_safe(e, tmp, succs, l) {
		list_del(&e->l);
		kfree(e);
	}
}

void subprog_free(struct bpf_subprog_info *subprog, int end_idx)
{
	int i = 0;

	for (; i <= end_idx; i++) {
		struct list_head *bbs = &subprog[i].bbs;
		struct bb_node *bb, *tmp, *exit;

		bb = entry_bb(bbs);
		exit = exit_bb(bbs);
		list_for_each_entry_safe_from(bb, tmp, &exit->l, l) {
			subprog_free_edge(bb);
			list_del(&bb->l);
			kfree(bb);
		}

		if (subprog[i].dtree_avail)
			kfree(subprog[i].dtree);
	}
}
