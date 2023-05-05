// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2023 Isovalent */

#include <linux/bpf.h>
#include <linux/bpf_mprog.h>
#include <linux/filter.h>

static int bpf_mprog_replace(struct bpf_mprog_entry *entry,
			     struct bpf_prog *nprog, u32 nid,
			     struct bpf_prog *rprog, u32 aflags)
{
	struct bpf_prog_item *item;
	struct bpf_prog *oprog;
	u32 iflags, id;
	int i;

	for (i = 0; i < bpf_mprog_max(); i++) {
		item = &entry->items[i];
		oprog = READ_ONCE(item->prog);
		if (!oprog)
			break;
		if (oprog != rprog)
			continue;
		iflags = item->flags;
		id = item->id;
		if (id != nid)
			return -EBUSY;
		if ((iflags & BPF_F_FIRST) !=
		    (aflags & BPF_F_FIRST)) {
			iflags = bpf_mprog_flags(iflags, aflags,
						 BPF_F_FIRST);
			if ((iflags & BPF_F_FIRST) &&
			    rprog != bpf_mprog_first(entry))
				return -EACCES;
		}
		if ((iflags & BPF_F_LAST) !=
		    (aflags & BPF_F_LAST)) {
			iflags = bpf_mprog_flags(iflags, aflags,
						 BPF_F_LAST);
			if ((iflags & BPF_F_LAST) &&
			    rprog != bpf_mprog_last(entry))
				return -EACCES;
		}
		bpf_mprog_write(item, nprog, iflags, id);
		if (!id)
			bpf_prog_put(oprog);
		return 0;
	}
	return -ENOENT;
}

static int bpf_mprog_head_tail(struct bpf_mprog_entry *entry,
			       struct bpf_prog *nprog, u32 nid,
			       struct bpf_prog *rprog, u32 rid,
			       u32 aflags)
{
	struct bpf_prog_item *item;
	struct bpf_mprog_entry *peer;
	struct bpf_prog *oprog;
	u32 iflags, items;

	items = bpf_mprog_total(entry);
	peer = bpf_mprog_peer(entry);
	if (aflags & BPF_F_FIRST) {
		item = &entry->items[0];
		iflags = item->flags;
		if (iflags & BPF_F_FIRST)
			return -EBUSY;
		if (aflags & BPF_F_LAST) {
			if (items)
				return -EBUSY;
			bpf_mprog_entry_clear(peer);
			item = &peer->items[0];
			bpf_mprog_write(item, nprog,
					BPF_F_FIRST | BPF_F_LAST, nid);
			return BPF_MPROG_SWAP;
		}
		if (aflags & BPF_F_BEFORE) {
			oprog = READ_ONCE(item->prog);
			if (oprog != rprog ||
			    (rid && item->id != rid))
				return -EBUSY;
		}
		if (items >= bpf_mprog_max())
			return -ENOSPC;
		bpf_mprog_entry_clear(peer);
		item = &peer->items[0];
		bpf_mprog_write(item, nprog, BPF_F_FIRST, nid);
		memcpy(&peer->items[1], &entry->items[0],
		       items * sizeof(*item));
		return BPF_MPROG_SWAP;
	}
	if (aflags & BPF_F_LAST) {
		if (items) {
			item = &entry->items[items - 1];
			iflags = item->flags;
			if (iflags & BPF_F_LAST)
				return -EBUSY;
			if (aflags & BPF_F_AFTER) {
				oprog = READ_ONCE(item->prog);
				if (oprog != rprog ||
				    (rid && item->id != rid))
					return -EBUSY;
			}
			if (items >= bpf_mprog_max())
				return -ENOSPC;
		}
		bpf_mprog_entry_clear(peer);
		item = &peer->items[items];
		bpf_mprog_write(item, nprog, BPF_F_LAST, nid);
		memcpy(&peer->items[0], &entry->items[0],
		       items * sizeof(*item));
		return BPF_MPROG_SWAP;
	}
	return -ENOENT;
}

static int bpf_mprog_add(struct bpf_mprog_entry *entry,
			 struct bpf_prog *nprog, u32 nid,
			 struct bpf_prog *rprog, u32 rid,
			 u32 aflags)
{
	bool found = false;
	struct bpf_prog_item *item, *tmp;
	struct bpf_mprog_entry *peer;
	struct bpf_prog *oprog;
	u32 iflags, id, items;
	int i, j;

	items = bpf_mprog_total(entry);
	if (items >= bpf_mprog_max())
		return -ENOSPC;
	peer = bpf_mprog_peer(entry);
	bpf_mprog_entry_clear(peer);
	for (i = 0, j = 0; i < bpf_mprog_max(); i++, j++) {
		item = &entry->items[i];
		tmp  = &peer->items[j];
		iflags = item->flags;
		id = item->id;
		oprog = READ_ONCE(item->prog);
		if (!oprog) {
			if (i == j) {
				if (i > 0) {
					item = &entry->items[i - 1];
					iflags = item->flags;
					id = item->id;
					oprog = READ_ONCE(item->prog);
					if (iflags & BPF_F_LAST) {
						if (iflags & BPF_F_FIRST)
							return -EBUSY;
						bpf_mprog_write(tmp, oprog,
								iflags, id);
						tmp = &peer->items[--j];
					}
				}
				bpf_mprog_write(tmp, nprog, 0, nid);
			}
			break;
		}
		if (aflags & (BPF_F_BEFORE | BPF_F_AFTER)) {
			if (oprog != rprog || (rid && id != rid))
				goto next;
			found = true;
			if (aflags & BPF_F_BEFORE) {
				if (iflags & BPF_F_FIRST)
					return -EBUSY;
				bpf_mprog_write(tmp, nprog, 0, nid);
				tmp = &peer->items[++j];
				goto next;
			}
			if (aflags & BPF_F_AFTER) {
				if (iflags & BPF_F_LAST)
					return -EBUSY;
				bpf_mprog_write(tmp, oprog, iflags, id);
				tmp = &peer->items[++j];
				bpf_mprog_write(tmp, nprog, 0, nid);
				continue;
			}
		}
next:
		bpf_mprog_write(tmp, oprog, iflags, id);
	}
	if (rprog && !found)
		return -ENOENT;
	return BPF_MPROG_SWAP;
}

static int bpf_mprog_del(struct bpf_mprog_entry *entry,
			 struct bpf_prog *dprog, u32 did,
			 struct bpf_prog *rprog, u32 rid,
			 u32 dflags)
{
	struct bpf_prog_item *item, *tmp;
	struct bpf_mprog_entry *peer;
	struct bpf_prog *oprog;
	int i, j, ret;

	if (dflags & BPF_F_FIRST) {
		oprog = bpf_mprog_first(entry);
		if (dprog && dprog != oprog)
			return -ENOENT;
		dprog = oprog;
	}
	if (dflags & BPF_F_LAST) {
		oprog = bpf_mprog_last(entry);
		if (dprog && dprog != oprog)
			return -ENOENT;
		dprog = oprog;
	}
	for (i = 0; i < bpf_mprog_max(); i++) {
		item = &entry->items[i];
		oprog = READ_ONCE(item->prog);
		if (!oprog)
			break;
		if (dflags & (BPF_F_BEFORE | BPF_F_AFTER)) {
			if (oprog != rprog || (rid && item->id != rid))
				continue;
			if (dflags & BPF_F_BEFORE) {
				item = &entry->items[--i];
				oprog = READ_ONCE(item->prog);
				if (dprog && dprog != oprog)
					return -ENOENT;
				dprog = oprog;
				break;
			}
			if (dflags & BPF_F_AFTER) {
				item = &entry->items[++i];
				oprog = READ_ONCE(item->prog);
				if (dprog && dprog != oprog)
					return -ENOENT;
				dprog = oprog;
				break;
			}
		}
	}
	if (!dprog)
		return -ENOENT;
	peer = bpf_mprog_peer(entry);
	bpf_mprog_entry_clear(peer);
	ret = -ENOENT;
	for (i = 0, j = 0; i < bpf_mprog_max(); i++) {
		item = &entry->items[i];
		tmp  = &peer->items[j];
		oprog = READ_ONCE(item->prog);
		if (!oprog)
			break;
		if (oprog != dprog) {
			bpf_mprog_write(tmp, oprog, item->flags, item->id);
			j++;
		} else {
			if (item->id != did)
				return -EBUSY;
			if (!item->id)
				bpf_mprog_mark_ref(entry, dprog);
			ret = BPF_MPROG_SWAP;
		}
	}
	if (!bpf_mprog_total(peer))
		ret = BPF_MPROG_FREE;
	return ret;
}

int bpf_mprog_attach(struct bpf_mprog_entry *entry, struct bpf_prog *nprog,
		     u32 nid, u32 expected_revision, u32 aflags, u32 relobj)
{
	struct bpf_tuple rtuple;
	struct bpf_prog *rprog;
	int ret;
	u32 rid;

	if (expected_revision &&
	    expected_revision != bpf_mprog_revision(entry))
		return -ESTALE;
	if (!bpf_mprog_flags_ok(aflags, true))
		return -EINVAL;
	ret = bpf_mprog_tuple_relative(&rtuple, relobj, aflags, nprog->type);
	if (ret)
		return ret;
	rprog = rtuple.prog;
	rid = rtuple.link ? rtuple.link->id : 0;
	if (!bpf_mprog_rprog_ok(aflags, rprog)) {
		ret = -EINVAL;
		goto out;
	}
	if (aflags & BPF_F_REPLACE)
		ret = bpf_mprog_replace(entry, nprog, nid, rprog, aflags);
	else if (aflags & (BPF_F_FIRST | BPF_F_LAST))
		ret = bpf_mprog_head_tail(entry, nprog, nid, rprog, rid, aflags);
	else
		ret = bpf_mprog_add(entry, nprog, nid, rprog, rid, aflags);
out:
	bpf_mprog_tuple_put(&rtuple);
	return ret;
}

int bpf_mprog_detach(struct bpf_mprog_entry *entry, struct bpf_prog *dprog,
		     u32 did, u32 expected_revision, u32 dflags, u32 relobj)
{
	struct bpf_tuple rtuple;
	struct bpf_prog *rprog;
	int ret;
	u32 rid;

	if (expected_revision &&
	    expected_revision != bpf_mprog_revision(entry))
		return -ESTALE;
	if (!bpf_mprog_flags_ok(dflags, false))
		return -EINVAL;
	ret = bpf_mprog_tuple_relative(&rtuple, relobj, dflags, dprog->type);
	if (ret)
		return ret;
	rprog = rtuple.prog;
	rid = rtuple.link ? rtuple.link->id : 0;
	if (!bpf_mprog_rprog_ok(dflags, rprog)) {
		ret = -EINVAL;
		goto out;
	}
	ret = bpf_mprog_del(entry, dprog, did, rprog, rid, dflags);
out:
	bpf_mprog_tuple_put(&rtuple);
	return ret;
}

int bpf_mprog_query(const union bpf_attr *attr, union bpf_attr __user *uattr,
		    struct bpf_mprog_entry *entry)
{
	u32 __user *uprog_id, __user *uprog_af;
	u32 __user *ulink_id, __user *ulink_af;
	u32 i, id, flags = 0, count, revision;
	struct bpf_prog_item *item;
	struct bpf_prog *prog;
	int ret = 0;

	if (attr->query.query_flags || attr->query.attach_flags)
		return -EINVAL;
	revision = bpf_mprog_revision(entry);
	count = bpf_mprog_total(entry);
	if (copy_to_user(&uattr->query.attach_flags, &flags, sizeof(flags)))
		return -EFAULT;
	if (copy_to_user(&uattr->query.revision, &revision, sizeof(revision)))
		return -EFAULT;
	if (copy_to_user(&uattr->query.count, &count, sizeof(count)))
		return -EFAULT;
	uprog_id = u64_to_user_ptr(attr->query.prog_ids);
	if (attr->query.count == 0 || !uprog_id || !count)
		return 0;
	if (attr->query.count < count) {
		count = attr->query.count;
		ret = -ENOSPC;
	}
	uprog_af = u64_to_user_ptr(attr->query.prog_attach_flags);
	ulink_id = u64_to_user_ptr(attr->query.link_ids);
	ulink_af = u64_to_user_ptr(attr->query.link_attach_flags);
	for (i = 0; i < ARRAY_SIZE(entry->items); i++) {
		item = &entry->items[i];
		prog = READ_ONCE(item->prog);
		if (!prog)
			break;
		id = prog->aux->id;
		if (copy_to_user(uprog_id + i, &id, sizeof(id)))
			return -EFAULT;
		id = item->id;
		if (ulink_id &&
		    copy_to_user(ulink_id + i, &id, sizeof(id)))
			return -EFAULT;
		flags = item->flags;
		if (uprog_af && !id &&
		    copy_to_user(uprog_af + i, &flags, sizeof(flags)))
			return -EFAULT;
		if (ulink_af && id &&
		    copy_to_user(ulink_af + i, &flags, sizeof(flags)))
			return -EFAULT;
		if (i + 1 == count)
			break;
	}
	return ret;
}
