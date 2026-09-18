// SPDX-License-Identifier: GPL-2.0
/* An executable's security.bpf.zone label, taken at exec and carried onto
 * the sockets the program opens.
 *
 * Three steps, each on the hook that can afford it:
 *
 *   bprm_committed_creds  is sleepable, and is the one moment a task's
 *                         executable is in hand, so the label is read off
 *                         the file there -- once per exec -- and kept in
 *                         task storage.
 *   socket_post_create    is sleepable too, and sees the socket before the
 *                         application has a descriptor for it. The label
 *                         goes onto the socket's inode here, out of task
 *                         storage, with no filesystem read.
 *   socket_connect,       are not sleepable, and do not need to be: the
 *   socket_sendmsg        label is a lookup on the socket's own inode,
 *                         under RCU.
 *
 * A task with no label on its executable gets no task storage, so its
 * sockets are never labelled and read back as unlabelled rather than as
 * some default. An accepted socket is a new socket with a new inode, so
 * socket_accept copies the listener's label onto it.
 */
#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_kfuncs.h"
#include "bpf_experimental.h"

char _license[] SEC("license") = "GPL";

#define ZONE_MAX	32

const char xattr_zone[] = "security.bpf.zone";

struct task_zone {
	char value[ZONE_MAX];
	/* bpf_dynptr_from_mem() takes a map value, not a stack buffer, and a
	 * buffer shared between tasks would let one task's read land in
	 * another's between the read and the write.
	 */
	char scratch[ZONE_MAX];
	int len;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_zone);
} task_zone SEC(".maps");

/* The test process, which is not labelled: only for the unlabelled case. */
__u32 monitored_pid;

int exec_ret = -999;		/* the zone read off the executable */
int create_ret = -999;		/* labelling the socket at creation */
int accept_ret = -999;		/* labelling the accepted socket */
int connect_ret = -999;		/* reading it back at connect */
int sendmsg_ret = -999;		/* and on the data path */
int unlabelled_ret = -999;	/* what an unlabelled socket reads back */
char exec_zone[ZONE_MAX];
char connect_zone[ZONE_MAX];
char sendmsg_zone[ZONE_MAX];

/* The executable's label, read once, at the moment the task becomes it. */
SEC("lsm.s/bprm_committed_creds")
int BPF_PROG(zone_at_exec, struct linux_binprm *bprm)
{
	struct bpf_dynptr value;
	struct task_zone *z;
	int len;

	z = bpf_task_storage_get(&task_zone, bpf_get_current_task_btf(), NULL,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!z)
		return 0;

	bpf_dynptr_from_mem(z->value, sizeof(z->value), 0, &value);
	len = bpf_get_file_xattr(bprm->file, xattr_zone, &value);
	if (len <= 0) {
		/* Not a labelled program: leave nothing behind for the
		 * socket hooks to find.
		 */
		bpf_task_storage_delete(&task_zone, bpf_get_current_task_btf());
		return 0;
	}
	z->len = len;

	exec_ret = len;
	__builtin_memcpy(exec_zone, z->value, ZONE_MAX);
	return 0;
}

/* The socket exists and has no descriptor yet: the one place a label may be
 * written, and the last place it can be written unnoticed.
 */
SEC("lsm.s/socket_post_create")
int BPF_PROG(label_at_create, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	struct bpf_dynptr value;
	struct task_zone *z;

	z = bpf_task_storage_get(&task_zone, bpf_get_current_task_btf(), NULL, 0);
	if (!z || z->len <= 0 || z->len > (int)sizeof(z->value))
		return 0;

	/* bpf_dynptr_from_mem() takes a size the verifier can bound, so the
	 * dynptr is made over the whole buffer and then trimmed to the label.
	 */
	bpf_dynptr_from_mem(z->value, sizeof(z->value), 0, &value);
	bpf_dynptr_adjust(&value, 0, z->len);
	create_ret = bpf_set_sock_xattr(sock, xattr_zone, &value);
	return 0;
}

/* A passively opened connection has no inode until accept(2) makes one, so
 * the label has to be copied across here or the socket comes out bare.
 */
SEC("lsm.s/socket_accept")
int BPF_PROG(label_on_accept, struct socket *sock, struct socket *newsock)
{
	struct bpf_dynptr value;
	struct task_zone *z;
	int len;

	/* Only a labelled task has storage, and only its sockets have a
	 * label to copy.
	 */
	z = bpf_task_storage_get(&task_zone, bpf_get_current_task_btf(), NULL, 0);
	if (!z)
		return 0;

	bpf_dynptr_from_mem(z->scratch, sizeof(z->scratch), 0, &value);
	len = bpf_get_sock_xattr(sock, xattr_zone, &value);
	if (len <= 0 || len > (int)sizeof(z->scratch))
		return 0;

	bpf_dynptr_adjust(&value, 0, len);
	accept_ret = bpf_set_sock_xattr(newsock, xattr_zone, &value);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(read_at_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct bpf_dynptr value;
	int ret;

	bpf_dynptr_from_mem(connect_zone, sizeof(connect_zone), 0, &value);
	ret = bpf_get_sock_xattr(sock, xattr_zone, &value);
	if (ret > 0)
		connect_ret = ret;
	else if ((bpf_get_current_pid_tgid() >> 32) == monitored_pid)
		unlabelled_ret = ret;
	return 0;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(read_at_sendmsg, struct socket *sock, struct msghdr *msg, int size)
{
	struct bpf_dynptr value;
	int ret;

	bpf_dynptr_from_mem(sendmsg_zone, sizeof(sendmsg_zone), 0, &value);
	ret = bpf_get_sock_xattr(sock, xattr_zone, &value);
	if (ret > 0)
		sendmsg_ret = ret;
	return 0;
}
