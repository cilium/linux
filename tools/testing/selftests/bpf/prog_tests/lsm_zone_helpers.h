/* SPDX-License-Identifier: GPL-2.0 */
/* Shared runner side of the lsm_zone_* tests: the cgroup tree a container
 * manager would build, brought up and labelled before a policy attaches, the
 * manager helper parked in the trusted zone that places tasks afterwards,
 * and the file, socket and mapping helpers the tests use.
 *
 * Each test keeps its own /tmp prefix, so they do not share files.
 */
#ifndef __LSM_ZONE_HELPERS_H
#define __LSM_ZONE_HELPERS_H

#include <limits.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/xattr.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <test_progs.h>
#include "cgroup_helpers.h"

#define ZONE_XATTR	"security.bpf.zone"
#define ZONE_DEFAULT	"default"
#define ZONE_TRUSTED	"trusted"

/* Below the cgroup work directory, so the tree is torn down with it. */
#define ROOT_CG		"/zoned/"
#define POD_CG		ROOT_CG "pod0/"
#define PAYLOAD_CG	POD_CG "payload/"
#define POD1_CG		ROOT_CG "pod1/"
#define TRUSTED_CG	ROOT_CG "trusted/"
#define TRUSTED_PAYLOAD_CG TRUSTED_CG "payload/"
#define PLAIN_CG	"/unzoned/"
#define PLAIN_POD_CG	PLAIN_CG "pod0/"

#define MAPLEN		4096

#ifndef AT_EXECVE_CHECK
#define AT_EXECVE_CHECK	0x10000
#endif
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

/* The clone3 argument block, to the size that carries a cgroup. */
struct clone3_args {
	__u64 flags, pidfd, child_tid, parent_tid, exit_signal, stack;
	__u64 stack_size, tls, set_tid, set_tid_size, cgroup;
};

struct zone_env {
	int root_fd;		/* zoned root, labelled "default" */
	int trusted_fd;		/* trusted pod below it */
	int plain_fd;		/* unzoned root */
};

static inline int zone_copy_file(const char *src, const char *dst)
{
	char buf[4096];
	int in, out, n, ret = 0;

	in = open(src, O_RDONLY);
	if (in < 0)
		return -errno;
	out = open(dst, O_CREAT | O_WRONLY | O_TRUNC, 0755);
	if (out < 0) {
		close(in);
		return -errno;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		if (write(out, buf, n) != n) {
			ret = -EIO;
			break;
		}
	}
	close(in);
	close(out);
	return ret;
}

/* A file holding one zeroed page, executable, for the mapping cases. */
static inline int make_page_file(const char *path)
{
	char page[MAPLEN] = {};
	int fd, err;

	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0755);
	if (fd < 0)
		return -errno;
	err = write(fd, page, sizeof(page));
	close(fd);
	return err == sizeof(page) ? 0 : -EIO;
}

static inline int set_zone(const char *path, const char *value)
{
	return setxattr(path, ZONE_XATTR, value, strlen(value) + 1, 0) ? -errno : 0;
}

static inline int set_cg_zone(const char *cg, const char *value)
{
	return set_cgroup_xattr(cg, ZONE_XATTR, value) ? -errno : 0;
}

static inline int read_zone(int cgroup_fd, char *buf, size_t sz)
{
	int ret = fgetxattr(cgroup_fd, ZONE_XATTR, buf, sz);

	return ret < 0 ? -errno : ret;
}

static inline void assert_zone(int cgroup_fd, const char *zone, const char *what)
{
	char buf[64] = {};

	if (ASSERT_EQ(read_zone(cgroup_fd, buf, sizeof(buf)),
		      (int)strlen(zone) + 1, what))
		ASSERT_STREQ(buf, zone, what);
}

static inline void assert_file_zone(const char *path, const char *zone,
				    const char *what)
{
	char buf[64] = {};
	int ret;

	ret = getxattr(path, ZONE_XATTR, buf, sizeof(buf));
	if (ASSERT_EQ(ret < 0 ? -errno : ret, (int)strlen(zone) + 1, what))
		ASSERT_STREQ(buf, zone, what);
}

/* open @name relative to @dirfd with @flags: 0 or -errno, nothing kept open. */
static inline int try_open(int dirfd, const char *name, int flags)
{
	int fd = openat(dirfd, name, flags);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

/* Abstract unix socket names, one per test process. */
static inline int abstract_addr(struct sockaddr_un *sa, const char *tag, pid_t pid)
{
	int n;

	memset(sa, 0, sizeof(*sa));
	sa->sun_family = AF_UNIX;
	n = snprintf(sa->sun_path + 1, sizeof(sa->sun_path) - 1, "zones_%d_%s",
		     pid, tag);
	return offsetof(struct sockaddr_un, sun_path) + 1 + n;
}

/* A listening stream socket, or a bound datagram socket: fd or -errno. */
static inline int unix_listen(const char *tag, pid_t pid, int type)
{
	struct sockaddr_un sa;
	int fd, len = abstract_addr(&sa, tag, pid);

	fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (bind(fd, (struct sockaddr *)&sa, len) ||
	    (type == SOCK_STREAM && listen(fd, 8))) {
		close(fd);
		return -errno;
	}
	return fd;
}

/* connect() a stream socket to an abstract name and keep it: fd or -errno. */
static inline int unix_connect(const char *tag, pid_t pid)
{
	struct sockaddr_un sa;
	int fd, len = abstract_addr(&sa, tag, pid);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (connect(fd, (struct sockaddr *)&sa, len)) {
		close(fd);
		return -errno;
	}
	return fd;
}

/* write() one byte: 0 or -errno. */
static inline int send_byte(int fd)
{
	return write(fd, "x", 1) == 1 ? 0 : -errno;
}

/* connect() a stream socket, or sendto() a datagram: 0 or -errno. */
static inline int unix_reach(const char *tag, pid_t pid, int type)
{
	struct sockaddr_un sa;
	int fd, ret = 0, len = abstract_addr(&sa, tag, pid);

	fd = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (type == SOCK_STREAM ?
	    connect(fd, (struct sockaddr *)&sa, len) < 0 :
	    sendto(fd, "x", 1, 0, (struct sockaddr *)&sa, len) < 0)
		ret = -errno;
	close(fd);
	return ret;
}

/* Send @fd over unix socket @sock via SCM_RIGHTS. */
static inline int send_fd(int sock, int fd)
{
	char c = 'x';
	char cbuf[CMSG_SPACE(sizeof(int))] = {};
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1,
			    .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cm = CMSG_FIRSTHDR(&m);

	cm->cmsg_level = SOL_SOCKET;
	cm->cmsg_type = SCM_RIGHTS;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &fd, sizeof(int));
	return sendmsg(sock, &m, 0) < 0 ? -errno : 0;
}

/* Receive one fd from @sock: the fd, or -errno. A refusal by file_receive
 * delivers the message without the fd, so that reads as -ENOMSG.
 */
static inline int recv_fd(int sock)
{
	char c;
	char cbuf[CMSG_SPACE(sizeof(int))] = {};
	struct iovec iov = { .iov_base = &c, .iov_len = 1 };
	struct msghdr m = { .msg_iov = &iov, .msg_iovlen = 1,
			    .msg_control = cbuf, .msg_controllen = sizeof(cbuf) };
	struct cmsghdr *cm;
	int fd;

	if (recvmsg(sock, &m, 0) < 0)
		return -errno;
	cm = CMSG_FIRSTHDR(&m);
	if (!cm || cm->cmsg_type != SCM_RIGHTS)
		return -ENOMSG;
	memcpy(&fd, CMSG_DATA(cm), sizeof(int));
	return fd;
}

/* The manager: a helper parked in the trusted zone before the policy attaches,
 * which places the test process wherever it asks, since afterwards only the
 * trusted zone may write a trusted cgroup's cgroup.procs. It also holds a
 * listening stream socket and a datagram socket, the trusted zone's, and
 * opens files O_RDWR on request and passes the descriptor over SCM_RIGHTS.
 */
static int mover_req[2] = { -1, -1 }, mover_rep[2] = { -1, -1 };
static int fdpass[2] = { -1, -1 };
static pid_t mover = -1;

static inline int start_mover(void)
{
	int err;

	if (pipe(mover_req) || pipe(mover_rep) ||
	    socketpair(AF_UNIX, SOCK_STREAM, 0, fdpass))
		return -errno;
	mover = fork();
	if (mover < 0)
		return -errno;
	if (mover == 0) {
		char cg[PATH_MAX], pid[16];
		int n;

		close(mover_req[1]);
		close(mover_rep[0]);
		close(fdpass[0]);
		mover_req[1] = -1;
		mover_rep[0] = -1;
		fdpass[0] = -1;
		snprintf(pid, sizeof(pid), "%d", getppid());
		err = join_parent_cgroup(TRUSTED_CG) ? -EIO : 0;
		if (!err && (unix_listen("stream", getppid(), SOCK_STREAM) < 0 ||
			     unix_listen("dgram", getppid(), SOCK_DGRAM) < 0))
			err = -EIO;
		if (write(mover_rep[1], &err, sizeof(err)) != sizeof(err))
			_exit(1);
		while ((n = read(mover_req[0], cg, sizeof(cg) - 1)) > 0) {
			cg[n] = 0;
			if (!strncmp(cg, "FD:", 3)) {
				int ffd = open(cg + 3, O_RDWR);

				err = ffd < 0 ? -errno : 0;
				if (!err) {
					send_fd(fdpass[1], ffd);
					close(ffd);
				}
			} else {
				err = write_cgroup_file_parent(cg, "cgroup.procs",
							       pid) ? -EIO : 0;
			}
			if (write(mover_rep[1], &err, sizeof(err)) != sizeof(err))
				_exit(1);
		}
		_exit(0);
	}
	close(mover_req[0]);
	close(mover_rep[1]);
	close(fdpass[1]);
	mover_req[0] = -1;
	mover_rep[1] = -1;
	fdpass[1] = -1;
	if (read(mover_rep[0], &err, sizeof(err)) != sizeof(err))
		return -EIO;
	return err;
}

static inline void stop_mover(void)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (mover_req[i] >= 0)
			close(mover_req[i]);
		if (mover_rep[i] >= 0)
			close(mover_rep[i]);
		if (fdpass[i] >= 0)
			close(fdpass[i]);
		mover_req[i] = mover_rep[i] = fdpass[i] = -1;
	}
	if (mover > 0)
		waitpid(mover, NULL, 0);
	mover = -1;
}

/* Have the manager place the test process into @cg: 0 or -errno. */
static inline int enter(const char *cg)
{
	int err;

	if (write(mover_req[1], cg, strlen(cg)) != strlen(cg))
		return -EIO;
	if (read(mover_rep[0], &err, sizeof(err)) != sizeof(err))
		return -EIO;
	return err;
}

/* Ask the manager to open @path O_RDWR and pass the fd; return it or -errno.
 * file_receive fires in the caller's zone.
 */
static inline int request_fd(const char *path)
{
	char req[PATH_MAX + 3];
	int err, n = snprintf(req, sizeof(req), "FD:%s", path);

	if (write(mover_req[1], req, n) != n)
		return -EIO;
	if (read(mover_rep[0], &err, sizeof(err)) != sizeof(err))
		return -EIO;
	if (err)
		return err;
	return recv_fd(fdpass[0]);
}

/* Write our own pid into @cg's cgroup.procs, i.e. self-migrate: 0 or -errno. */
static inline int self_enter(const char *cg)
{
	char pid[16];

	snprintf(pid, sizeof(pid), "%d", getpid());
	return write_cgroup_file(cg, "cgroup.procs", pid) ? -errno : 0;
}

/* Write our own tid into @cg's cgroup.threads: 0 or -errno. */
static inline int self_enter_thread(const char *cg)
{
	char tid[16];

	snprintf(tid, sizeof(tid), "%d", (int)syscall(__NR_gettid));
	return write_cgroup_file(cg, "cgroup.threads", tid) ? -errno : 0;
}

/* clone3 a child straight into the cgroup behind @cgfd: 0 or -errno. */
static inline int clone_into(int cgfd)
{
	struct clone3_args args = {
		.flags = CLONE_INTO_CGROUP,
		.exit_signal = SIGCHLD,
		.cgroup = cgfd,
	};
	pid_t pid;

	pid = syscall(__NR_clone3, &args, sizeof(args));
	if (pid < 0)
		return -errno;
	if (pid == 0)
		_exit(0);
	waitpid(pid, NULL, 0);
	return 0;
}

/* Attach to @pid, wait for it to stop, detach: 0 or -errno. */
static inline int attach_pid(pid_t pid)
{
	int status;

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL))
		return -errno;
	if (waitpid(pid, &status, __WALL) != pid)
		return -EIO;
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	return 0;
}

/* Attach to a child of our own parked in pause(): 0 or -errno. */
static inline int attach_child(void)
{
	pid_t pid = fork();
	int ret;

	if (pid < 0)
		return -errno;
	if (pid == 0) {
		for (;;)
			pause();
	}
	ret = attach_pid(pid);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return ret;
}

/* Ask, as an interpreter would before running a script, whether @path may be
 * executed, without executing it: 0 or -errno.
 */
static inline int exec_check(const char *path)
{
	char *const argv[] = { (char *)"check", NULL };
	char *const envp[] = { NULL };
	int fd, ret;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	ret = syscall(__NR_execveat, fd, "", argv, envp,
		      AT_EMPTY_PATH | AT_EXECVE_CHECK) ? -errno : 0;
	close(fd);
	return ret;
}

/* Map @path executable, the way loading code does: 0 if the mapping was
 * admitted, else -errno.
 */
static inline int map_exec(const char *path)
{
	int fd, ret = 0;
	void *p;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	p = mmap(NULL, MAPLEN, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		ret = -errno;
	else
		munmap(p, MAPLEN);
	close(fd);
	return ret;
}

/* Map anonymous memory writable and executable at once: 0 or -errno. */
static inline int map_rwx(void)
{
	void *p;

	p = mmap(NULL, MAPLEN, PROT_READ | PROT_WRITE | PROT_EXEC,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return -errno;
	munmap(p, MAPLEN);
	return 0;
}

/* Write into anonymous memory, then make it executable: 0 or -errno. */
static inline int anon_then_exec(void)
{
	int ret = 0;
	char *p;

	p = mmap(NULL, MAPLEN, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return -errno;
	p[0] = 0xc3;
	if (mprotect(p, MAPLEN, PROT_READ | PROT_EXEC))
		ret = -errno;
	munmap(p, MAPLEN);
	return ret;
}

/* Write through a private mapping of @path, then make it executable. */
static inline int cow_then_exec(const char *path)
{
	int fd, ret = 0;
	char *p;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	p = mmap(NULL, MAPLEN, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		close(fd);
		return -errno;
	}
	p[0] = 0xc3;
	if (mprotect(p, MAPLEN, PROT_READ | PROT_EXEC))
		ret = -errno;
	munmap(p, MAPLEN);
	close(fd);
	return ret;
}

/* The administrator's bootstrap, before a policy attaches: the zoned root
 * stands in for the root cgroup the manager's slices live under, labelled
 * "default", with a first trusted pod below it labelled "trusted", control
 * files that move tasks included; the unzoned root for a tree the policy
 * never labelled. Returns 0, -EOPNOTSUPP when cgroups take no such label
 * (skip), or another -errno.
 */
static inline int zone_bootstrap(struct zone_env *env)
{
	int err;

	env->root_fd = env->trusted_fd = env->plain_fd = -1;
	if (setup_cgroup_environment())
		return -EIO;
	env->root_fd = create_and_get_cgroup(ROOT_CG);
	if (env->root_fd < 0)
		return -EIO;
	env->plain_fd = create_and_get_cgroup(PLAIN_CG);
	if (env->plain_fd < 0)
		return -EIO;
	err = set_cg_zone(ROOT_CG, ZONE_DEFAULT);
	if (err)
		return err;
	env->trusted_fd = create_and_get_cgroup(TRUSTED_CG);
	if (env->trusted_fd < 0)
		return -EIO;
	err = set_cg_zone(TRUSTED_CG, ZONE_TRUSTED);
	if (!err)
		err = set_cg_zone(TRUSTED_CG "cgroup.procs", ZONE_TRUSTED);
	if (!err)
		err = set_cg_zone(TRUSTED_CG "cgroup.threads", ZONE_TRUSTED);
	if (err)
		return err;
	return start_mover();
}

static inline void zone_teardown(struct zone_env *env)
{
	stop_mover();
	if (env->trusted_fd >= 0)
		close(env->trusted_fd);
	if (env->plain_fd >= 0)
		close(env->plain_fd);
	if (env->root_fd >= 0)
		close(env->root_fd);
	env->root_fd = env->trusted_fd = env->plain_fd = -1;
	cleanup_cgroup_environment();
}

#endif /* __LSM_ZONE_HELPERS_H */
