// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2026 Isovalent
 */

#include <linux/rculist.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/bpf.h>
#include <linux/bpf_local_storage.h>
#include <linux/fs.h>
#include <uapi/linux/btf.h>
#include <linux/bpf_lsm.h>
#include <linux/btf_ids.h>
#include <linux/rcupdate_trace.h>

DEFINE_BPF_STORAGE_CACHE(sb_cache);

static struct bpf_local_storage __rcu **
sb_storage_ptr(void *owner)
{
	struct super_block *sb = owner;
	struct bpf_storage_blob *bsb;

	bsb = bpf_sb(sb);
	if (!bsb)
		return NULL;
	return &bsb->storage;
}

static struct bpf_local_storage_data *sb_storage_lookup(struct super_block *sb,
							struct bpf_map *map,
							bool cacheit_lockit)
{
	struct bpf_local_storage *sb_storage;
	struct bpf_local_storage_map *smap;
	struct bpf_storage_blob *bsb;

	bsb = bpf_sb(sb);
	if (!bsb)
		return NULL;

	sb_storage =
		rcu_dereference_check(bsb->storage, bpf_rcu_lock_held());
	if (!sb_storage)
		return NULL;

	smap = (struct bpf_local_storage_map *)map;
	return bpf_local_storage_lookup(sb_storage, smap, cacheit_lockit);
}

void bpf_sb_storage_free(struct super_block *sb)
{
	struct bpf_local_storage *local_storage;
	struct bpf_storage_blob *bsb;

	bsb = bpf_sb(sb);
	if (!bsb)
		return;

	rcu_read_lock_dont_migrate();

	local_storage = rcu_dereference(bsb->storage);
	if (!local_storage)
		goto out;

	bpf_local_storage_destroy(local_storage);
out:
	rcu_read_unlock_migrate();
}

/*
 * A super_block has no file descriptor of its own, so userspace addresses one
 * through any file living on it.
 */
static struct super_block *sb_from_fd(struct fd f)
{
	return file_inode(fd_file(f))->i_sb;
}

static void *bpf_fd_sb_storage_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_local_storage_data *sdata;
	CLASS(fd_raw, f)(*(int *)key);

	if (fd_empty(f))
		return ERR_PTR(-EBADF);

	sdata = sb_storage_lookup(sb_from_fd(f), map, true);
	return sdata ? sdata->data : NULL;
}

static long bpf_fd_sb_storage_update_elem(struct bpf_map *map, void *key,
					  void *value, u64 map_flags)
{
	struct bpf_local_storage_data *sdata;
	CLASS(fd_raw, f)(*(int *)key);

	if (fd_empty(f))
		return -EBADF;
	if (!sb_storage_ptr(sb_from_fd(f)))
		return -EBADF;

	sdata = bpf_local_storage_update(sb_from_fd(f),
					 (struct bpf_local_storage_map *)map,
					 value, map_flags, false);
	return PTR_ERR_OR_ZERO(sdata);
}

static int sb_storage_delete(struct super_block *sb, struct bpf_map *map)
{
	struct bpf_local_storage_data *sdata;

	sdata = sb_storage_lookup(sb, map, false);
	if (!sdata)
		return -ENOENT;

	return bpf_selem_unlink(SELEM(sdata));
}

static long bpf_fd_sb_storage_delete_elem(struct bpf_map *map, void *key)
{
	CLASS(fd_raw, f)(*(int *)key);

	if (fd_empty(f))
		return -EBADF;
	return sb_storage_delete(sb_from_fd(f), map);
}

BPF_CALL_4(bpf_sb_storage_get, struct bpf_map *, map, struct super_block *, sb,
	   void *, value, u64, flags)
{
	struct bpf_local_storage_data *sdata;

	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (flags & ~(BPF_LOCAL_STORAGE_GET_F_CREATE))
		return (unsigned long)NULL;

	/*
	 * explicitly check that the sb_storage_ptr is not NULL as
	 * sb_storage_lookup returns NULL in this case and
	 * bpf_local_storage_update expects the owner to have a valid storage
	 * pointer.
	 */
	if (!sb || !sb_storage_ptr(sb))
		return (unsigned long)NULL;

	sdata = sb_storage_lookup(sb, map, true);
	if (sdata)
		return (unsigned long)sdata->data;

	/*
	 * This helper must only be called from where the super_block is
	 * guaranteed to be alive and cannot be freed.
	 */
	if (flags & BPF_LOCAL_STORAGE_GET_F_CREATE) {
		sdata = bpf_local_storage_update(
			sb, (struct bpf_local_storage_map *)map, value,
			BPF_NOEXIST, false);
		return IS_ERR(sdata) ? (unsigned long)NULL :
					     (unsigned long)sdata->data;
	}

	return (unsigned long)NULL;
}

BPF_CALL_2(bpf_sb_storage_delete,
	   struct bpf_map *, map, struct super_block *, sb)
{
	WARN_ON_ONCE(!bpf_rcu_lock_held());
	if (!sb)
		return -EINVAL;

	/*
	 * This helper must only be called from where the super_block is
	 * guaranteed to be alive and cannot be freed.
	 */
	return sb_storage_delete(sb, map);
}

static int notsupp_get_next_key(struct bpf_map *map, void *key,
				void *next_key)
{
	return -ENOTSUPP;
}

static struct bpf_map *sb_storage_map_alloc(union bpf_attr *attr)
{
	/*
	 * Do not allow allocation of BPF_MAP_TYPE_SB_STORAGE if the BPF LSM
	 * was not initialized by the LSM framework at boot. Without proper
	 * initialization, the BPF superblock security blob offset remains
	 * unprepared, causing bpf_sb() to calculate an invalid memory offset
	 * and corrupt sb->s_security.
	 */
	if (!bpf_lsm_initialized)
		return ERR_PTR(-EOPNOTSUPP);
	return bpf_local_storage_map_alloc(attr, &sb_cache);
}

static void sb_storage_map_free(struct bpf_map *map)
{
	bpf_local_storage_map_free(map, &sb_cache);
}

const struct bpf_map_ops sb_storage_map_ops = {
	.map_meta_equal = bpf_map_meta_equal,
	.map_alloc_check = bpf_local_storage_map_alloc_check,
	.map_alloc = sb_storage_map_alloc,
	.map_free = sb_storage_map_free,
	.map_get_next_key = notsupp_get_next_key,
	.map_lookup_elem = bpf_fd_sb_storage_lookup_elem,
	.map_update_elem = bpf_fd_sb_storage_update_elem,
	.map_delete_elem = bpf_fd_sb_storage_delete_elem,
	.map_check_btf = bpf_local_storage_map_check_btf,
	.map_mem_usage = bpf_local_storage_map_mem_usage,
	.map_btf_id = &bpf_local_storage_map_btf_id[0],
	.map_owner_storage_ptr = sb_storage_ptr,
};

BTF_ID_LIST_SINGLE(bpf_sb_storage_btf_ids, struct, super_block)

const struct bpf_func_proto bpf_sb_storage_get_proto = {
	.func		= bpf_sb_storage_get,
	.gpl_only	= false,
	.ret_type	= RET_PTR_TO_MAP_VALUE_OR_NULL,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_sb_storage_btf_ids[0],
	.arg3_type	= ARG_PTR_TO_MAP_VALUE_OR_NULL,
	.arg4_type	= ARG_ANYTHING,
};

const struct bpf_func_proto bpf_sb_storage_delete_proto = {
	.func		= bpf_sb_storage_delete,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_PTR_TO_BTF_ID_OR_NULL,
	.arg2_btf_id	= &bpf_sb_storage_btf_ids[0],
};
