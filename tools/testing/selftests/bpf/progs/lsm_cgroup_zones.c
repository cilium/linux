// SPDX-License-Identifier: GPL-2.0
/*
 * W^X and code provenance, scoped by the zone of the cgroup a task runs in.
 *
 * A cgroup only ever comes into existence through a mkdir(2) in cgroupfs, so a
 * manager creating one for a container, whether directly or by way of a
 * transient unit, ends up in kernfs_init_security. The root of the managed tree
 * carries a security.bpf.zone label, and the hook pushes it onto every cgroup
 * created below before the node is linked in: a container's cgroups are
 * labelled from their first instant, and a mkdir in a delegated subtree cannot
 * produce an unlabelled one.
 *
 * Every other hook asks the current task's cgroup for its zone. In the
 * "trusted" zone nothing is enforced. In any other zone the task is held to
 * W^X, no mapping both writable and executable and no memory made executable
 * after it was writable, and to code provenance: a file is mapped executable,
 * or made executable later, only if it carries the trusted zone label itself.
 * The one label thus serves both ways: on a cgroup it says which zone the
 * tasks in it run in, on a file which zone the code came from. A cgroup with
 * no zone at all is outside the policy; a deployment labels the root cgroup
 * at boot so that none exists.
 *
 * A program on inode_init_security stamps every new inode with the zone of
 * the task creating it, atomically with the inode's own creation. What a
 * default-zone task writes thus carries "default" from its first instant and
 * can never be mapped executable there, while what the trusted zone installs
 * carries "trusted" and can. No administrator has to label files afterwards.
 *
 * The label is the policy's own control plane, so only the trusted zone may
 * write or remove it, on a cgroup or a file alike: the default zone cannot
 * promote itself or its code, and a task in no zone cannot either. Migration
 * is gated directly on task_cgroup_attach, which sees both the task and its
 * destination cgroup: nothing enters the trusted zone from outside it, by
 * cgroup.procs write or by clone3 alike, and an enforced task cannot escape
 * into an unlabelled cgroup to shed enforcement. What the label protects is
 * held the same way. A trusted file cannot be opened for writing or truncated
 * from outside, nor received as a writable descriptor, so the code the
 * default zone may run cannot be changed by it, and a mkdir below a trusted
 * cgroup is refused. The tree is brought up before the policy attaches, the
 * root labelled "default" and a first pod "trusted", and from then on trust
 * is only minted from inside.
 *
 * Two ways around W^X never reach the mapping hooks: a tracer and a write
 * through /proc/PID/mem copy attacker data into a private page of an
 * executable mapping with FOLL_FORCE, and a script is opened and run by its
 * interpreter. So attaching is refused from the default zone, and from no
 * zone to a trusted task; a writable open of /proc/PID/mem is refused in
 * the default zone by the identity of its file operations; and exec, as
 * well as the check an interpreter makes with AT_EXECVE_CHECK before running
 * a script, is held to the same provenance as a mapping.
 *
 * What the trusted zone opens for writing, or writes to through a descriptor
 * it holds, is labelled trusted on the spot with bpf_set_file_xattr(), so it
 * becomes code the default zone may run and can no longer open for writing.
 * And a unix socket belongs to the cgroup it was created in, which the kernel
 * records on the sock, so its zone is read like a task's; one of the trusted
 * zone cannot be connected or sent to from any other zone, and a stream
 * connection is checked again on every send, so a descriptor handed to the
 * default zone or kept across a zone change carries nothing either.
 *
 * A file's zone is read by the sleepable hooks and cached in inode local
 * storage, keyed by the inode, because file_mprotect runs under mmap_lock and
 * cannot read the xattr itself. It reaches the backing file with
 * bpf_get_vma_file() and enforces the cached verdict, failing closed when
 * there is none.
 */
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "bpf_kfuncs.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define PROT_WRITE	0x2
#define PROT_EXEC	0x4
#define VM_EXEC		0x00000004
#define FMODE_WRITE	0x2
#define ATTR_SIZE	0x8
#define PTRACE_MODE_ATTACH 0x2
#define MAY_WRITE	0x2
#define AF_UNIX		1
#define SOCK_STREAM	1
#define SOCK_SEQPACKET	5
#define S_IFMT		0170000
#define S_IFREG		0100000

#define ZONE_MAX	32

enum {
	ZONE_NONE,	/* no label on the cgroup: outside the policy */
	ZONE_DEFAULT,	/* any label but "trusted": enforced */
	ZONE_TRUSTED,
};

extern struct cgroup *bpf_cgroup_from_id(__u64 cgid) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgrp) __ksym;
extern struct file *bpf_get_vma_file(struct vm_area_struct *vma) __ksym;
/* The file operations of /proc/PID/mem: its identity, without a path. */
extern const void proc_mem_operations __ksym;

const char xattr_zone[] = "security.bpf.zone";
static const char label_trusted[] = "trusted";

struct verdict {
	__u8 trusted;
};

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct verdict);
} file_zone SEC(".maps");

/* Per-task scratch for the xattr reads. A buffer shared between tasks would
 * let one task's read overwrite another's between the read and the compare.
 */
struct scratch {
	char zone[ZONE_MAX];
	char file[64];
	char name[32];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct scratch);
} scratch_map SEC(".maps");

/* What labelling at creation did, of cgroups, their files, and inodes. */
__u32 nr_labelled;
__u32 nr_labelled_files;
__s32 label_err = 1;
__u32 nr_stamped;
__s32 stamp_err = 1;
/* What enforcement did. */
__u32 wx_denied;
__u32 code_denied;
__u32 relabel_denied;
__u32 write_denied;
__u32 grow_denied;
__u32 enter_denied;
__u32 recv_denied;
__u32 socket_denied;
__u32 nr_claimed;
__u32 ptrace_denied;
__u32 exec_denied;
__u32 allowed;

static __always_inline struct scratch *scratch(void)
{
	return bpf_task_storage_get(&scratch_map, bpf_get_current_task_btf(), 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline bool is_trusted(const char *label, int len)
{
	return len == sizeof(label_trusted) &&
	       !bpf_strncmp(label, sizeof(label_trusted), label_trusted);
}

/* Read the current task's zone label into the scratch and return its length.
 * The label sits on the cgroup itself, so no walk up the hierarchy is needed.
 */
static __always_inline int current_zone_label(struct scratch *s)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	int len;

	cgrp = bpf_cgroup_from_id(bpf_get_current_cgroup_id());
	if (!cgrp)
		return -ENOENT;
	bpf_dynptr_from_mem(s->zone, sizeof(s->zone), 0, &value);
	len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	bpf_cgroup_release(cgrp);
	return len;
}

static __always_inline int zone_of_label(struct scratch *s, int len)
{
	if (len <= 0)
		return ZONE_NONE;
	if (is_trusted(s->zone, len))
		return ZONE_TRUSTED;
	return ZONE_DEFAULT;
}

static __always_inline int current_zone(struct scratch *s)
{
	if (!s)
		return ZONE_DEFAULT;	/* cannot tell: fail closed */
	return zone_of_label(s, current_zone_label(s));
}

/* The zone of another task, read off its cgroup under RCU. */
static __always_inline int task_zone(struct scratch *s, struct task_struct *task)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	int len = -ENOENT;

	if (!s)
		return ZONE_DEFAULT;
	bpf_dynptr_from_mem(s->zone, sizeof(s->zone), 0, &value);
	bpf_rcu_read_lock();
	cgrp = task->cgroups->dfl_cgrp;
	if (cgrp)
		len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	bpf_rcu_read_unlock();
	return zone_of_label(s, len);
}

/* The cgroup a socket was created in, which the kernel records on a full
 * sock only: a request or timewait minisock shares just the common header,
 * so the record is read past its end. Those carry no cgroup here, as they
 * carry none for the kernel's own socket cgroup helper.
 */
static __always_inline __u64 sock_cgroup_id(struct sock *sk)
{
	__u8 state;

	if (!sk)
		return 0;
	state = BPF_CORE_READ(sk, __sk_common.skc_state);
	if (state == TCP_TIME_WAIT || state == TCP_NEW_SYN_RECV)
		return 0;
	return BPF_CORE_READ(sk, sk_cgrp_data.cgroup, kn, id);
}

/* The zone of the cgroup a socket was created in, read like a task's, off
 * that cgroup's own label.
 */
static __always_inline int sock_zone(struct scratch *s, struct sock *sk)
{
	struct bpf_dynptr value;
	struct cgroup *cgrp;
	__u64 id;
	int len;

	if (!s)
		return ZONE_DEFAULT;
	id = sock_cgroup_id(sk);
	cgrp = id ? bpf_cgroup_from_id(id) : NULL;
	if (!cgrp)
		return ZONE_NONE;
	bpf_dynptr_from_mem(s->zone, sizeof(s->zone), 0, &value);
	len = bpf_cgroup_read_xattr(cgrp, xattr_zone, &value);
	bpf_cgroup_release(cgrp);
	return zone_of_label(s, len);
}

/*
 * Push the zone of the cgroup a new node is created under onto the node
 * itself, the cgroup directory and its control files alike, so that a hook
 * holding an open control file can tell which zone its cgroup is in. A new
 * cgroup in the trusted zone may only be created from inside it.
 */
SEC("lsm.s/kernfs_init_security")
int BPF_PROG(inherit_zone, struct kernfs_node *kn_dir, struct kernfs_node *kn)
{
	struct bpf_dynptr value;
	struct scratch *s;
	int len;

	s = scratch();
	if (!s)
		return -ENOMEM;	/* rather no node than an unlabelled one */

	bpf_dynptr_from_mem(s->file, sizeof(s->file), 0, &value);
	len = bpf_get_kernfs_xattr(kn_dir, xattr_zone, &value);
	if (len <= 0 || len > ZONE_MAX)
		return 0;
	if ((kn->flags & KERNFS_DIR) && is_trusted(s->file, len) &&
	    current_zone(s) != ZONE_TRUSTED) {
		grow_denied++;
		return -EPERM;
	}

	bpf_dynptr_from_mem(s->file, len, 0, &value);
	label_err = bpf_set_kernfs_xattr(kn, xattr_zone, &value);
	if (label_err)
		return 0;
	if (kn->flags & KERNFS_DIR)
		nr_labelled++;
	else
		nr_labelled_files++;
	return 0;
}

/*
 * Stamp a new inode with the zone of the task creating it, in the same
 * transaction as the inode itself. Nothing is stamped for a task outside the
 * policy, and nothing on a filesystem that takes no xattrs at creation.
 */
SEC("lsm/inode_init_security")
int BPF_PROG(stamp_zone, struct inode *inode, struct inode *dir,
	     const struct qstr *qstr, struct xattr *xattrs, int *xattr_count)
{
	struct bpf_dynptr value;
	struct scratch *s;
	int len;

	if (!xattrs)
		return 0;
	s = scratch();
	if (!s)
		return 0;
	len = current_zone_label(s);
	if (len <= 0 || len > ZONE_MAX)
		return 0;

	bpf_dynptr_from_mem(s->zone, len, 0, &value);
	stamp_err = bpf_init_inode_xattr(xattrs, xattr_count, xattr_zone, &value);
	if (!stamp_err)
		nr_stamped++;
	return 0;
}

/* Sleepable only: read the file's zone and cache the verdict on the inode. */
static __always_inline struct verdict *measure(struct scratch *s,
					       struct file *file)
{
	struct bpf_dynptr value;
	struct verdict *v;
	int ret;

	if (!s)
		return NULL;
	v = bpf_inode_storage_get(&file_zone, file->f_inode, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!v)
		return NULL;

	bpf_dynptr_from_mem(s->file, sizeof(s->file), 0, &value);
	ret = bpf_get_file_xattr(file, xattr_zone, &value);
	v->trusted = is_trusted(s->file, ret);
	return v;
}

/* What the trusted zone writes becomes trusted code: label a regular file
 * and refresh the cached verdict, once.
 */
static __always_inline void claim(struct scratch *s, struct file *file)
{
	struct bpf_dynptr value;
	struct verdict *v;

	if (!s || (file->f_inode->i_mode & S_IFMT) != S_IFREG)
		return;
	v = bpf_inode_storage_get(&file_zone, file->f_inode, 0,
				  BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (v && v->trusted)
		return;
	__builtin_memcpy(s->file, label_trusted, sizeof(label_trusted));
	bpf_dynptr_from_mem(s->file, sizeof(label_trusted), 0, &value);
	if (bpf_set_file_xattr(file, xattr_zone, &value, 0))
		return;
	if (v)
		v->trusted = 1;
	nr_claimed++;
}

/* A descriptor the trusted zone writes through is claimed too, whichever
 * zone opened it.
 */
SEC("lsm.s/file_permission")
int BPF_PROG(claim_on_write, struct file *file, int mask)
{
	struct scratch *s;

	if (!(mask & MAY_WRITE))
		return 0;
	s = scratch();
	if (current_zone(s) == ZONE_TRUSTED)
		claim(s, file);
	return 0;
}

/* Measure what the default zone opens, and from any zone but the trusted one
 * refuse to open a trusted object for writing: a file whose code the default
 * zone may run, or a control file of a trusted cgroup. Nothing can be told
 * about an object that could not be measured, so that is refused as well.
 */
SEC("lsm.s/file_open")
int BPF_PROG(guard_open, struct file *file)
{
	struct scratch *s = scratch();
	unsigned long fop = 0;
	struct verdict *v;
	int zone = current_zone(s);

	if (zone == ZONE_TRUSTED) {
		if (file->f_mode & FMODE_WRITE)
			claim(s, file);
		return 0;
	}
	/* Writing through /proc/PID/mem forces a copy of a private page past
	 * its protection, and to one's own mem file no ptrace check applies.
	 */
	bpf_probe_read_kernel(&fop, sizeof(fop), &file->f_op);
	if (zone == ZONE_DEFAULT && (file->f_mode & FMODE_WRITE) &&
	    fop == (unsigned long)&proc_mem_operations) {
		ptrace_denied++;
		return -EPERM;
	}
	if (zone == ZONE_NONE && !(file->f_mode & FMODE_WRITE))
		return 0;
	v = measure(s, file);
	if ((file->f_mode & FMODE_WRITE) && (!v || v->trusted)) {
		write_denied++;
		return -EPERM;
	}
	return 0;
}

/* Truncation needs no writable descriptor, so cover it too. */
SEC("lsm.s/inode_setattr")
int BPF_PROG(guard_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct iattr *attr)
{
	struct scratch *s = scratch();
	struct bpf_dynptr value;
	int ret;

	if (!(attr->ia_valid & ATTR_SIZE))
		return 0;
	if (current_zone(s) == ZONE_TRUSTED)
		return 0;
	if (!s)
		return -EPERM;
	bpf_dynptr_from_mem(s->file, sizeof(s->file), 0, &value);
	ret = bpf_get_dentry_xattr(dentry, xattr_zone, &value);
	if (is_trusted(s->file, ret)) {
		write_denied++;
		return -EPERM;
	}
	return 0;
}

SEC("lsm.s/mmap_file")
int BPF_PROG(guard_mmap, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	struct scratch *s = scratch();
	struct verdict *v;

	if (current_zone(s) != ZONE_DEFAULT)
		return 0;
	if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
		wx_denied++;
		return -EPERM;
	}
	/* Anonymous memory mapped executable holds zero pages only. It cannot
	 * be written without giving up PROT_EXEC, and cannot get it back below.
	 */
	if (!file)
		return 0;

	/* Every file-backed mapping is measured, so that a later mprotect on
	 * it finds a verdict whichever cgroup opened the file.
	 */
	v = measure(s, file);
	if (!(prot & PROT_EXEC))
		return 0;
	if (v && v->trusted) {
		allowed++;
		return 0;
	}
	code_denied++;
	return -EPERM;
}

/* Non-sleepable, runs under mmap_lock: enforce what the sleepable hooks cached. */
SEC("lsm/file_mprotect")
int BPF_PROG(guard_mprotect, struct vm_area_struct *vma, unsigned long reqprot,
	     unsigned long prot)
{
	struct scratch *s = scratch();
	struct verdict *v;
	struct file *file;
	int ret = -EPERM;

	if (current_zone(s) != ZONE_DEFAULT)
		return 0;
	if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) {
		wx_denied++;
		return -EPERM;
	}
	if (!(prot & PROT_EXEC) || (vma->vm_flags & VM_EXEC))
		return 0;

	/* Memory becoming executable. Anonymous memory and a private file
	 * mapping written through have both been writable, so W^X refuses
	 * them; a clean file mapping follows the file's cached zone.
	 */
	file = bpf_get_vma_file(vma);
	if (!file || vma->anon_vma) {
		if (file)
			bpf_put_file(file);
		wx_denied++;
		return -EPERM;
	}
	v = bpf_inode_storage_get(&file_zone, file->f_inode, 0, 0);
	if (v && v->trusted) {
		allowed++;
		ret = 0;
	} else {
		code_denied++;
	}
	bpf_put_file(file);
	return ret;
}

/* A tracer writes into private mappings past every protection, as does
 * process_vm_writev(): no attaching from the default zone at all, and none
 * from outside the policy to a task in the trusted zone.
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(guard_ptrace, struct task_struct *child, unsigned int mode)
{
	struct scratch *s;
	int zone;

	if (!(mode & PTRACE_MODE_ATTACH))
		return 0;
	s = scratch();
	zone = current_zone(s);
	if (zone == ZONE_TRUSTED)
		return 0;
	if (zone == ZONE_NONE && task_zone(s, child) != ZONE_TRUSTED)
		return 0;
	ptrace_denied++;
	return -EPERM;
}

/* Migration is gated where it happens, with the task and its destination
 * cgroup both in hand: this covers a cgroup.procs/threads write and a
 * clone3(CLONE_INTO_CGROUP) alike, whichever way a task changes cgroup. The
 * trusted zone is the control plane and may place a task anywhere; otherwise
 * nothing enters the trusted zone from outside it, and an enforced task may
 * not drop into an unlabelled cgroup to shed enforcement.
 */
SEC("lsm/task_cgroup_attach")
int BPF_PROG(guard_migrate, struct task_struct *task, struct cgroup *dst_cgrp)
{
	struct scratch *s = scratch();
	struct bpf_dynptr value;
	int mover, dst, len;

	/* The decision is the mover's to make: for a cgroup.procs write that is
	 * the writer, for clone3(CLONE_INTO_CGROUP) the forking parent. The
	 * moved task is not a reliable source zone, since a clone child already
	 * carries the destination cgroup by the time this hook runs.
	 */
	mover = current_zone(s);
	if (mover == ZONE_TRUSTED)
		return 0;		/* the control plane may place anything */
	if (!s)
		return -EPERM;		/* cannot read the destination: fail closed */

	if (task_zone(s, task) == ZONE_TRUSTED) {
		enter_denied++;		/* only the trusted zone moves trusted tasks */
		return -EPERM;
	}
	bpf_dynptr_from_mem(s->zone, sizeof(s->zone), 0, &value);
	len = bpf_cgroup_read_xattr(dst_cgrp, xattr_zone, &value);
	dst = zone_of_label(s, len);
	if (dst == ZONE_TRUSTED) {
		enter_denied++;		/* no entry into the trusted zone */
		return -EPERM;
	}
	if (mover == ZONE_DEFAULT && dst == ZONE_NONE) {
		enter_denied++;		/* no escape out of enforcement */
		return -EPERM;
	}
	return 0;
}

/* A writable descriptor to a trusted file, or to an unmeasurable one, must
 * not enter the default zone by SCM_RIGHTS: it would let code the default
 * zone may run be rewritten from within it, past the file_open write gate.
 */
SEC("lsm.s/file_receive")
int BPF_PROG(guard_receive, struct file *file)
{
	struct scratch *s = scratch();
	struct verdict *v;

	if (current_zone(s) != ZONE_DEFAULT)
		return 0;
	if (!(file->f_mode & FMODE_WRITE))
		return 0;
	v = measure(s, file);
	if (!v || v->trusted) {
		recv_denied++;
		return -EPERM;
	}
	return 0;
}

/* Connecting or sending to a unix socket of the trusted zone from any other
 * is refused; the trusted zone may still connect outward.
 */
static __always_inline int guard_peer(struct sock *other)
{
	struct scratch *s = scratch();

	if (sock_zone(s, other) != ZONE_TRUSTED)
		return 0;
	if (current_zone(s) == ZONE_TRUSTED)
		return 0;
	socket_denied++;
	return -EPERM;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(guard_unix_connect, struct sock *sock, struct sock *other,
	     struct sock *newsk)
{
	return guard_peer(other);
}

SEC("lsm/unix_may_send")
int BPF_PROG(guard_unix_send, struct socket *sock, struct socket *other)
{
	return guard_peer(BPF_CORE_READ(other, sk));
}

/* A connected unix stream has no hook of its own per message, so check the
 * peer again on every send: a connection made before the policy attached,
 * or handed over, or kept by a task moved out of the trusted zone, carries
 * nothing to a trusted socket.
 */
SEC("lsm/socket_sendmsg")
int BPF_PROG(guard_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
	struct sock *sk = BPF_CORE_READ(sock, sk), *peer;
	__u16 family, type;

	if (!sk)
		return 0;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	type = BPF_CORE_READ(sk, sk_type);
	if (family != AF_UNIX || (type != SOCK_STREAM && type != SOCK_SEQPACKET))
		return 0;
	peer = BPF_CORE_READ((struct unix_sock *)sk, peer);
	if (!peer)
		return 0;
	return guard_peer(peer);
}

/* Exec, and the check an interpreter makes with AT_EXECVE_CHECK before it
 * runs a script, follow the file's zone like a mapping would.
 */
SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(guard_exec, struct linux_binprm *bprm)
{
	struct scratch *s = scratch();
	struct verdict *v;

	if (current_zone(s) != ZONE_DEFAULT)
		return 0;
	v = measure(s, bprm->file);
	if (v && v->trusted) {
		allowed++;
		return 0;
	}
	exec_denied++;
	return -EPERM;
}

/* Keep a cached verdict consistent when the file is relabeled after it was
 * measured. Reading the xattr with __vfs_getxattr does not take i_rwsem, so
 * it is safe here even though inode_post_setxattr holds it.
 */
SEC("lsm.s/inode_post_setxattr")
int BPF_PROG(refresh_on_setxattr, struct dentry *dentry, const char *name,
	     const void *val, __u64 size, int flags)
{
	struct scratch *s = scratch();
	struct bpf_dynptr value;
	struct verdict *v;
	int ret;

	v = bpf_inode_storage_get(&file_zone, dentry->d_inode, 0, 0);
	if (!v)
		return 0;
	if (!s) {
		v->trusted = 0;	/* cannot re-read the label: drop the trust */
		return 0;
	}

	bpf_dynptr_from_mem(s->file, sizeof(s->file), 0, &value);
	ret = bpf_get_dentry_xattr(dentry, xattr_zone, &value);
	v->trusted = is_trusted(s->file, ret);
	return 0;
}

/* Only the trusted zone writes or removes the label, on a file or a cgroup
 * alike. A name that cannot be read is refused rather than let through.
 */
static __always_inline int guard_relabel(const char *name)
{
	struct scratch *s = scratch();

	if (!s)
		return -EPERM;
	if (bpf_probe_read_kernel_str(s->name, sizeof(s->name), name) < 0)
		return -EPERM;
	if (bpf_strncmp(s->name, sizeof(xattr_zone), xattr_zone))
		return 0;
	if (current_zone(s) == ZONE_TRUSTED)
		return 0;
	relabel_denied++;
	return -EPERM;
}

SEC("lsm/inode_setxattr")
int BPF_PROG(guard_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, __u64 size, int flags)
{
	return guard_relabel(name);
}

SEC("lsm/inode_removexattr")
int BPF_PROG(guard_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name)
{
	return guard_relabel(name);
}

/* Claim the label for the capability check: writing or removing it is
 * decided by the zone above, not by CAP_SYS_ADMIN. Every other security.
 * name keeps that requirement.
 */
SEC("lsm/inode_xattr_skipcap")
int BPF_PROG(skipcap_label, const char *name)
{
	struct scratch *s = scratch();

	if (!s)
		return 0;
	if (bpf_probe_read_kernel_str(s->name, sizeof(s->name), name) < 0)
		return 0;
	return !bpf_strncmp(s->name, sizeof(xattr_zone), xattr_zone);
}
