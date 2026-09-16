// SPDX-License-Identifier: GPL-2.0
/*
 * W^X and code provenance, scoped by cgroup zone.
 *
 * A container manager carves a container out of the cgroup tree with plain
 * mkdirs: systemd-nspawn asks the service manager for a machine-<name>.scope
 * and creates the "payload" and "supervisor" cgroups below it, and the
 * payload's own init subdivides from there. The root of that tree carries a
 * security.bpf.zone label, and a program on kernfs_init_security pushes it
 * onto every cgroup created below, so a container's cgroups are labelled from
 * the instant they exist. The policy holds every task in a "default" zone to
 * W^X and to code provenance, where an executable mapping needs the trusted
 * zone label on the file itself, and leaves a "trusted" zone alone. Every
 * inode a task creates is stamped with its zone, so what the default zone
 * writes can never run there and what the trusted zone installs can. Only the
 * trusted zone may write or remove the label, on a cgroup or a file alike, or
 * write to what it protects: a trusted cgroup's control files, and with them
 * the migration of tasks into the trusted zone, and trusted code itself. The
 * two ways around W^X the mapping hooks never see, a tracer or a write
 * through /proc/PID/mem, are closed to the default zone as well, and exec,
 * or an interpreter's check before running a script, follows the file's
 * zone like a mapping does. What the trusted zone writes is labelled trusted
 * as it is written, and a trusted zone's unix sockets cannot be reached from
 * outside.
 *
 * The cgroup work directory stands in for the root cgroup, since labelling the
 * real root would put the whole test VM under policy. The administrator brings
 * the tree up before the policy attaches: the root labelled "default" and a
 * first pod "trusted", since afterwards trust is only minted from inside, and
 * a helper parked in that pod plays the manager that places tasks. The
 * code under test is libxz_ifunc.so, a stand-in for the backdoored liblzma of
 * CVE-2024-3094 that runs code the moment it is mapped, in byte-identical
 * copies with and without a trusted label plus one on ramfs, where the label
 * cannot be read at all.
 */
#include <dlfcn.h>
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
#include "cap_helpers.h"
#include "lsm_cgroup_zones.skel.h"

#define ZONE_XATTR	"security.bpf.zone"
#define ZONE_DEFAULT	"default"
#define ZONE_TRUSTED	"trusted"

/* Relative to the cgroup work directory, which stands in for the root. */
#define ROOT_CG		"zoned/"
#define POD_CG		ROOT_CG "pod0/"
#define PAYLOAD_CG	POD_CG "payload/"
#define POD1_CG		ROOT_CG "pod1/"
#define TRUSTED_CG	ROOT_CG "trusted/"
#define TRUSTED_PAYLOAD_CG TRUSTED_CG "payload/"
#define PLAIN_CG	"unzoned/"
#define PLAIN_POD_CG	PLAIN_CG "pod0/"

#define TMP		"/tmp/test_progs_zones_"
#define LIB_SRC		"./libxz_ifunc.so"
#define LIB_UNTRUSTED	TMP "untrusted.so"
#define LIB_TRUSTED	TMP "trusted.so"
#define NOXATTR_DIR	TMP "noxattr"
#define LIB_NOXATTR	NOXATTR_DIR "/libxz.so"
#define FILE_COW	TMP "cow"
#define FILE_GUARDED	TMP "guarded"
#define FILE_RELABEL_A	TMP "relabel_a"
#define FILE_RELABEL_B	TMP "relabel_b"
#define FILE_MADE_PLAIN	TMP "made_plain"
#define FILE_MADE_DEFAULT	TMP "made_default"
#define FILE_MADE_TRUSTED	TMP "made_trusted"
#define FILE_CLAIM_OPEN	TMP "claim_open"
#define FILE_CLAIM_WRITE	TMP "claim_write"
#define FILE_CAPLESS	TMP "capless"
#define MARKER		TMP "marker"
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

/* Step at which a sequence joins the enforced cgroup; before it, the task
 * runs in an unzoned one.
 */
enum { AT_OPEN, AT_MMAP, AT_MPROTECT };

static const struct scoped {
	const char *path;
	bool trusted;
	int from;
	int expect;
	const char *name;
} scoped[] = {
	/* Measured at open. */
	{ TMP "open_u", false, AT_OPEN, -EPERM,
	  "default: untrusted, measured at open: denied" },
	{ TMP "open_t", true, AT_OPEN, 0,
	  "default: trusted, measured at open: allowed" },
	/* Opened outside the zone, measured at mmap. */
	{ TMP "mmap_u", false, AT_MMAP, -EPERM,
	  "default: untrusted, measured at mmap: denied" },
	{ TMP "mmap_t", true, AT_MMAP, 0,
	  "default: trusted, measured at mmap: allowed" },
	/* Opened and mapped outside the zone: no verdict, fail closed. */
	{ TMP "miss_t", true, AT_MPROTECT, -EPERM,
	  "default: trusted, never measured: denied" },
};

static int copy_file(const char *src, const char *dst)
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

static int make_page_file(const char *path)
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

static int set_zone(const char *path, const char *value)
{
	return setxattr(path, ZONE_XATTR, value, strlen(value) + 1, 0) ? -errno : 0;
}

static int set_cg_zone(const char *cg, const char *value)
{
	return set_cgroup_xattr(cg, ZONE_XATTR, value) ? -errno : 0;
}

/* Abstract unix socket names, one per test process. */
static int abstract_addr(struct sockaddr_un *sa, const char *tag, pid_t pid)
{
	int n;

	memset(sa, 0, sizeof(*sa));
	sa->sun_family = AF_UNIX;
	n = snprintf(sa->sun_path + 1, sizeof(sa->sun_path) - 1, "zones_%d_%s",
		     pid, tag);
	return offsetof(struct sockaddr_un, sun_path) + 1 + n;
}

/* A listening stream socket, or a bound datagram socket: fd or -errno. */
static int unix_listen(const char *tag, pid_t pid, int type)
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
static int unix_connect(const char *tag, pid_t pid)
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
static int send_byte(int fd)
{
	return write(fd, "x", 1) == 1 ? 0 : -errno;
}

/* connect() a stream socket, or sendto() a datagram: 0 or -errno. */
static int unix_reach(const char *tag, pid_t pid, int type)
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

static int mover_req[2] = { -1, -1 }, mover_rep[2] = { -1, -1 };
static int fdpass[2] = { -1, -1 };

/* Send @fd over unix socket @sock via SCM_RIGHTS. */
static int send_fd(int sock, int fd)
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

/* Receive one fd from @sock: the fd, or -errno (file_receive may refuse it). */
static int recv_fd(int sock)
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
static pid_t mover = -1;

/* The manager: a helper parked in the trusted zone before the policy attaches,
 * which places the test process wherever it asks, since afterwards only the
 * trusted zone may write a trusted cgroup's cgroup.procs. It also holds a
 * listening stream socket and a datagram socket, the trusted zone's.
 */
static int start_mover(void)
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

static void stop_mover(void)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (mover_req[i] >= 0)
			close(mover_req[i]);
		if (mover_rep[i] >= 0)
			close(mover_rep[i]);
	}
	if (mover > 0)
		waitpid(mover, NULL, 0);
}

/* Ask the manager to open @path O_RDWR and pass the fd; return it or -errno. */
static int request_fd(const char *path)
{
	char req[PATH_MAX + 3];
	int err, n = snprintf(req, sizeof(req), "FD:%s", path);

	if (write(mover_req[1], req, n) != n)
		return -EIO;
	if (read(mover_rep[0], &err, sizeof(err)) != sizeof(err))
		return -EIO;
	if (err)
		return err;
	return recv_fd(fdpass[0]);	/* file_receive fires here, in our zone */
}

/* Write our own pid into @cg's cgroup.procs, i.e. self-migrate. */
static int self_enter(const char *cg)
{
	char pid[16];

	snprintf(pid, sizeof(pid), "%d", getpid());
	return write_cgroup_file(cg, "cgroup.procs", pid) ? -errno : 0;
}

/* Have the manager place the test process into @cg. */
static int enter(const char *cg)
{
	int err;

	if (write(mover_req[1], cg, strlen(cg)) != strlen(cg))
		return -EIO;
	if (read(mover_rep[0], &err, sizeof(err)) != sizeof(err))
		return -EIO;
	return err;
}

/* Attach to @pid, wait for it to stop, detach: 0 or -errno. */
static int attach_pid(pid_t pid)
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
static int attach_child(void)
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

/* clone3 a child straight into the cgroup behind @cgfd: 0 or -errno. */
static int clone_into(int cgfd)
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

/* Ask, as an interpreter would before running a script, whether @path may be
 * executed, without executing it: 0 or -errno.
 */
static int exec_check(const char *path)
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

/* open @name relative to @dirfd with @flags: 0 or -errno, nothing kept open. */
static int try_open(int dirfd, const char *name, int flags)
{
	int fd = openat(dirfd, name, flags);

	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

static int read_zone(int cgroup_fd, char *buf, size_t sz)
{
	int ret = fgetxattr(cgroup_fd, ZONE_XATTR, buf, sz);

	return ret < 0 ? -errno : ret;
}

static void assert_zone(int cgroup_fd, const char *zone, const char *what)
{
	char buf[64] = {};

	if (ASSERT_EQ(read_zone(cgroup_fd, buf, sizeof(buf)),
		      (int)strlen(zone) + 1, what))
		ASSERT_STREQ(buf, zone, what);
}

static void assert_file_zone(const char *path, const char *zone,
			     const char *what)
{
	char buf[64] = {};
	int ret;

	ret = getxattr(path, ZONE_XATTR, buf, sizeof(buf));
	if (ASSERT_EQ(ret < 0 ? -errno : ret, (int)strlen(zone) + 1, what))
		ASSERT_STREQ(buf, zone, what);
}

static bool marker_present(void)
{
	struct stat st;

	return stat(MARKER, &st) == 0;
}

/* dlopen @path: 0 if its code was admitted and ran, -EPERM if it was refused
 * before its first instruction, -EIO if the two disagree.
 */
static int load_lib(const char *path)
{
	void *h;

	remove(MARKER);
	h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!h)
		return marker_present() ? -EIO : -EPERM;
	dlclose(h);
	return marker_present() ? 0 : -EIO;
}

/* Map anonymous memory writable and executable at once. */
static int map_rwx(void)
{
	void *p;

	p = mmap(NULL, MAPLEN, PROT_READ | PROT_WRITE | PROT_EXEC,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED)
		return -errno;
	munmap(p, MAPLEN);
	return 0;
}

/* Write into anonymous memory, then make it executable. */
static int anon_then_exec(void)
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

/* Write through a private mapping of a trusted file, then make it executable. */
static int cow_then_exec(const char *path)
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

/* open, map read-only, then mprotect(+PROT_EXEC), joining @cg at step @from so
 * that the steps before it run in an unzoned cgroup. Returns 0 if the exec
 * transition was allowed, else -errno.
 */
static int map_then_exec(const char *path, const char *cg, int from)
{
	int fd, ret = 0;
	void *p;

	if (enter(from == AT_OPEN ? cg : PLAIN_POD_CG))
		return -EIO;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	if (from == AT_MMAP && enter(cg)) {
		ret = -EIO;
		goto out_fd;
	}
	p = mmap(NULL, MAPLEN, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		ret = -errno;
		goto out_fd;
	}
	if (from == AT_MPROTECT && enter(cg)) {
		ret = -EIO;
		goto out_map;
	}
	if (mprotect(p, MAPLEN, PROT_READ | PROT_EXEC))
		ret = -errno;
out_map:
	munmap(p, MAPLEN);
out_fd:
	close(fd);
	return ret;
}

/* open and map read-only in the default zone, relabel the file to @newval from
 * the trusted zone, then mprotect(+PROT_EXEC) back in the default zone.
 * Returns 0 if the exec transition was allowed, else -errno.
 */
static int map_relabel_exec(const char *path, const char *newval)
{
	int fd, ret;
	void *p;

	if (enter(PAYLOAD_CG))
		return -EIO;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	p = mmap(NULL, MAPLEN, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) {
		close(fd);
		return -errno;
	}
	ret = enter(TRUSTED_PAYLOAD_CG) ? -EIO : set_zone(path, newval);
	if (!ret && enter(PAYLOAD_CG))
		ret = -EIO;
	if (!ret && mprotect(p, MAPLEN, PROT_READ | PROT_EXEC))
		ret = -errno;
	munmap(p, MAPLEN);
	close(fd);
	return ret;
}

static void cleanup_files(void)
{
	int i;

	remove(MARKER);
	remove(LIB_UNTRUSTED);
	remove(LIB_TRUSTED);
	remove(FILE_COW);
	remove(FILE_GUARDED);
	remove(FILE_RELABEL_A);
	remove(FILE_RELABEL_B);
	remove(FILE_MADE_PLAIN);
	remove(FILE_MADE_DEFAULT);
	remove(FILE_MADE_TRUSTED);
	remove(FILE_CLAIM_OPEN);
	remove(FILE_CLAIM_WRITE);
	remove(FILE_CAPLESS);
	for (i = 0; i < ARRAY_SIZE(scoped); i++)
		remove(scoped[i].path);
}

void test_lsm_cgroup_zones(void)
{
	int root_fd = -1, pod_fd = -1, payload_fd = -1, pod1_fd = -1;
	int trusted_fd = -1, trusted_payload_fd = -1, procs_fd;
	int plain_fd = -1, plain_pod_fd = -1, lfd = -1, wfd = -1, cfd = -1;
	struct lsm_cgroup_zones *skel = NULL;
	bool noxattr_mounted = false;
	char buf[64] = {};
	int i, err, stamped;
	__u64 caps = 0;

	if (!ASSERT_OK(setup_cgroup_environment(), "setup_cgroup_environment"))
		return;

	/* The administrator's bootstrap, before the policy attaches: the zoned
	 * root stands in for the root cgroup the manager's slices live under,
	 * with a first trusted pod below it; the unzoned root for a tree the
	 * policy never labelled. What exists before the policy attaches is
	 * labelled by hand, the control files that move tasks included.
	 */
	root_fd = create_and_get_cgroup(ROOT_CG);
	if (!ASSERT_OK_FD(root_fd, "create zoned root"))
		goto out;
	plain_fd = create_and_get_cgroup(PLAIN_CG);
	if (!ASSERT_OK_FD(plain_fd, "create unzoned root"))
		goto out;
	if (set_cg_zone(ROOT_CG, ZONE_DEFAULT)) {
		printf("%s:SKIP:cannot set %s on a cgroup (errno %d)\n",
		       __func__, ZONE_XATTR, errno);
		test__skip();
		goto out;
	}
	trusted_fd = create_and_get_cgroup(TRUSTED_CG);
	if (!ASSERT_OK_FD(trusted_fd, "create trusted pod"))
		goto out;
	if (!ASSERT_OK(set_cg_zone(TRUSTED_CG, ZONE_TRUSTED), "label trusted pod") ||
	    !ASSERT_OK(set_cg_zone(TRUSTED_CG "cgroup.procs", ZONE_TRUSTED),
		       "label trusted pod procs") ||
	    !ASSERT_OK(set_cg_zone(TRUSTED_CG "cgroup.threads", ZONE_TRUSTED),
		       "label trusted pod threads"))
		goto out;

	/* Byte-identical code with and without the trusted zone label. */
	if (!ASSERT_OK(copy_file(LIB_SRC, LIB_UNTRUSTED), "copy untrusted lib"))
		goto out;
	if (!ASSERT_OK(copy_file(LIB_SRC, LIB_TRUSTED), "copy trusted lib"))
		goto out;
	err = set_zone(LIB_TRUSTED, ZONE_TRUSTED);
	if (err == -EOPNOTSUPP || err == -EPERM) {
		printf("%s:SKIP:cannot set %s on a file (errno %d)\n",
		       __func__, ZONE_XATTR, -err);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "label trusted lib"))
		goto out;

	/* A copy on ramfs, which has no xattr handlers: there the label is not
	 * absent but unreadable, and "cannot tell" must not become "allow".
	 */
	if (mkdir(NOXATTR_DIR, 0755) && errno != EEXIST) {
		ASSERT_OK(-errno, "mkdir noxattr");
		goto out;
	}
	if (!ASSERT_OK(mount("ramfs", NOXATTR_DIR, "ramfs", 0, NULL), "mount ramfs"))
		goto out;
	noxattr_mounted = true;
	if (!ASSERT_OK(copy_file(LIB_SRC, LIB_NOXATTR), "copy noxattr lib"))
		goto out;
	err = getxattr(LIB_NOXATTR, ZONE_XATTR, NULL, 0) < 0 ? -errno : 0;
	if (!ASSERT_EQ(err, -EOPNOTSUPP, "label unreadable on ramfs"))
		goto out;

	/* Page files for the mprotect paths. */
	for (i = 0; i < ARRAY_SIZE(scoped); i++) {
		if (!ASSERT_OK(make_page_file(scoped[i].path), "make page file"))
			goto out;
		if (scoped[i].trusted &&
		    !ASSERT_OK(set_zone(scoped[i].path, ZONE_TRUSTED), "label page file"))
			goto out;
	}
	if (!ASSERT_OK(make_page_file(FILE_COW), "make cow file") ||
	    !ASSERT_OK(set_zone(FILE_COW, ZONE_TRUSTED), "label cow file"))
		goto out;
	if (!ASSERT_OK(make_page_file(FILE_RELABEL_A), "make relabel A") ||
	    !ASSERT_OK(set_zone(FILE_RELABEL_A, ZONE_TRUSTED), "label relabel A"))
		goto out;
	if (!ASSERT_OK(make_page_file(FILE_RELABEL_B), "make relabel B"))
		goto out;
	if (!ASSERT_OK(make_page_file(FILE_GUARDED), "make guarded file") ||
	    !ASSERT_OK(set_zone(FILE_GUARDED, ZONE_TRUSTED), "label guarded file"))
		goto out;

	if (!ASSERT_OK(start_mover(), "start manager in trusted pod"))
		goto out;

	setenv("XZ_BACKDOOR_MARKER", MARKER, 1);

	skel = lsm_cgroup_zones__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto out;
	if (!ASSERT_OK(lsm_cgroup_zones__attach(skel), "skel attach"))
		goto out;

	/* Cgroups created under policy: pods and their payloads come up
	 * carrying the zone of what they were created under, control files
	 * included, a pod outside the zoned tree stays unlabelled, and one in
	 * the trusted zone can only be created from inside it.
	 */
	pod_fd = create_and_get_cgroup(POD_CG);
	if (!ASSERT_OK_FD(pod_fd, "create pod"))
		goto out;
	ASSERT_OK(skel->data->label_err, "label_err");
	assert_zone(pod_fd, ZONE_DEFAULT, "pod inherits default");
	payload_fd = create_and_get_cgroup(PAYLOAD_CG);
	if (!ASSERT_OK_FD(payload_fd, "create payload"))
		goto out;
	assert_zone(payload_fd, ZONE_DEFAULT, "payload inherits default");
	procs_fd = openat(payload_fd, "cgroup.procs", O_RDONLY);
	if (ASSERT_OK_FD(procs_fd, "open payload procs")) {
		assert_zone(procs_fd, ZONE_DEFAULT, "payload procs inherits default");
		close(procs_fd);
	}
	pod1_fd = create_and_get_cgroup(POD1_CG);
	if (!ASSERT_OK_FD(pod1_fd, "create second pod"))
		goto out;
	assert_zone(pod1_fd, ZONE_DEFAULT, "second pod inherits default");
	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted pod"))
		goto out;
	trusted_payload_fd = create_and_get_cgroup(TRUSTED_PAYLOAD_CG);
	if (!ASSERT_OK_FD(trusted_payload_fd, "create trusted payload"))
		goto out;
	assert_zone(trusted_payload_fd, ZONE_TRUSTED, "trusted payload inherits trusted");
	procs_fd = openat(trusted_payload_fd, "cgroup.procs", O_RDONLY);
	if (ASSERT_OK_FD(procs_fd, "open trusted payload procs")) {
		assert_zone(procs_fd, ZONE_TRUSTED, "trusted payload procs inherits trusted");
		close(procs_fd);
	}
	plain_pod_fd = create_and_get_cgroup(PLAIN_POD_CG);
	if (!ASSERT_OK_FD(plain_pod_fd, "create unzoned pod"))
		goto out;
	ASSERT_EQ(read_zone(plain_pod_fd, buf, sizeof(buf)), -ENODATA,
		  "unzoned pod stays unlabelled");
	ASSERT_EQ(skel->bss->nr_labelled, 4, "nr_labelled");
	ASSERT_GE(skel->bss->nr_labelled_files, 4, "nr_labelled_files");

	/* Default zone: W^X and provenance are enforced. */
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload"))
		goto out;
	ASSERT_EQ(map_rwx(), -EPERM, "default: W+X mapping denied");
	ASSERT_EQ(anon_then_exec(), -EPERM, "default: written anon made exec denied");
	ASSERT_EQ(cow_then_exec(FILE_COW), -EPERM,
		  "default: written file mapping made exec denied");
	ASSERT_EQ(load_lib(LIB_UNTRUSTED), -EPERM, "default: unlabeled lib refused");
	ASSERT_OK(load_lib(LIB_TRUSTED), "default: labeled lib admitted");
	ASSERT_EQ(load_lib(LIB_NOXATTR), -EPERM, "default: unreadable-label lib refused");

	/* Entering the zone at open, at mmap, or only at mprotect. */
	for (i = 0; i < ARRAY_SIZE(scoped); i++)
		ASSERT_EQ(map_then_exec(scoped[i].path, PAYLOAD_CG, scoped[i].from),
			  scoped[i].expect, scoped[i].name);

	/* Relabeled by the trusted zone after it was measured, before it is
	 * made executable.
	 */
	ASSERT_EQ(map_relabel_exec(FILE_RELABEL_A, ZONE_DEFAULT), -EPERM,
		  "default: relabeled away: denied");
	ASSERT_OK(map_relabel_exec(FILE_RELABEL_B, ZONE_TRUSTED),
		  "default: relabeled trusted: allowed");

	/* Files created under policy are stamped with their creator's zone:
	 * none outside it, "default" in the default zone, where such a file
	 * can then never be run, and "trusted" in the trusted zone, whose
	 * files the default zone may run.
	 */
	stamped = skel->bss->nr_stamped;
	if (!ASSERT_OK(enter(PLAIN_POD_CG), "join unzoned pod"))
		goto out;
	if (!ASSERT_OK(make_page_file(FILE_MADE_PLAIN), "make file unzoned"))
		goto out;
	err = getxattr(FILE_MADE_PLAIN, ZONE_XATTR, buf, sizeof(buf)) < 0 ? -errno : 0;
	ASSERT_EQ(err, -ENODATA, "unzoned: file left unlabelled");
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload to create"))
		goto out;
	if (!ASSERT_OK(make_page_file(FILE_MADE_DEFAULT), "make file default"))
		goto out;
	assert_file_zone(FILE_MADE_DEFAULT, ZONE_DEFAULT, "default: file stamped default");
	ASSERT_EQ(map_then_exec(FILE_MADE_DEFAULT, PAYLOAD_CG, AT_OPEN), -EPERM,
		  "default: file written here: denied");
	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "join trusted payload to create"))
		goto out;
	if (!ASSERT_OK(make_page_file(FILE_MADE_TRUSTED), "make file trusted"))
		goto out;
	assert_file_zone(FILE_MADE_TRUSTED, ZONE_TRUSTED, "trusted: file stamped trusted");
	ASSERT_OK(map_then_exec(FILE_MADE_TRUSTED, PAYLOAD_CG, AT_OPEN),
		  "default: file installed from trusted zone: allowed");
	ASSERT_OK(skel->data->stamp_err, "stamp_err");
	ASSERT_EQ(skel->bss->nr_stamped - stamped, 2, "nr_stamped");

	/* Only the trusted zone may write or remove the label, or write to
	 * what it protects: the default zone cannot promote its own cgroup or
	 * its own file, nor strip their labels, nor enter or extend the
	 * trusted zone, nor change trusted code; a task in no zone cannot
	 * either. Its own files it may write.
	 */
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload to relabel"))
		goto out;
	ASSERT_EQ(try_open(trusted_payload_fd, "cgroup.procs", O_WRONLY), -EPERM,
		  "default: write trusted payload procs: denied");
	ASSERT_EQ(try_open(trusted_fd, "cgroup.procs", O_WRONLY), -EPERM,
		  "default: write trusted pod procs: denied");
	ASSERT_OK(try_open(trusted_payload_fd, "cgroup.procs", O_RDONLY),
		  "default: read trusted payload procs: allowed");
	ASSERT_EQ(mkdirat(trusted_fd, "evil", 0755) ? -errno : 0, -EPERM,
		  "default: mkdir below trusted pod: denied");
	ASSERT_EQ(clone_into(trusted_payload_fd), -EPERM,
		  "default: clone3 into trusted payload: denied");
	ASSERT_EQ(try_open(AT_FDCWD, LIB_TRUSTED, O_WRONLY), -EPERM,
		  "default: open trusted lib for write: denied");
	ASSERT_EQ(try_open(AT_FDCWD, LIB_TRUSTED, O_RDWR), -EPERM,
		  "default: open trusted lib read-write: denied");
	ASSERT_OK(try_open(AT_FDCWD, LIB_TRUSTED, O_RDONLY),
		  "default: open trusted lib read-only: allowed");
	ASSERT_EQ(truncate(FILE_GUARDED, 0) ? -errno : 0, -EPERM,
		  "default: truncate trusted file: denied");
	ASSERT_OK(try_open(AT_FDCWD, FILE_MADE_DEFAULT, O_WRONLY),
		  "default: open own file for write: allowed");
	ASSERT_EQ(set_cg_zone(PAYLOAD_CG, ZONE_TRUSTED), -EPERM,
		  "default: relabel own cgroup: denied");
	ASSERT_EQ(fremovexattr(payload_fd, ZONE_XATTR) ? -errno : 0, -EPERM,
		  "default: strip own cgroup label: denied");
	ASSERT_EQ(set_zone(FILE_MADE_DEFAULT, ZONE_TRUSTED), -EPERM,
		  "default: relabel own file: denied");
	ASSERT_EQ(removexattr(FILE_MADE_DEFAULT, ZONE_XATTR) ? -errno : 0, -EPERM,
		  "default: strip own file label: denied");
	assert_zone(payload_fd, ZONE_DEFAULT, "default: cgroup label intact");
	assert_file_zone(FILE_MADE_DEFAULT, ZONE_DEFAULT, "default: file label intact");
	if (!ASSERT_OK(enter(PLAIN_POD_CG), "join unzoned pod to relabel"))
		goto out;
	ASSERT_EQ(set_cg_zone(PLAIN_POD_CG, ZONE_TRUSTED), -EPERM,
		  "unzoned: mint trust: denied");
	ASSERT_EQ(try_open(trusted_payload_fd, "cgroup.procs", O_WRONLY), -EPERM,
		  "unzoned: write trusted payload procs: denied");
	ASSERT_EQ(mkdirat(trusted_fd, "evil", 0755) ? -errno : 0, -EPERM,
		  "unzoned: mkdir below trusted pod: denied");
	ASSERT_EQ(clone_into(trusted_payload_fd), -EPERM,
		  "unzoned: clone3 into trusted payload: denied");
	ASSERT_EQ(try_open(AT_FDCWD, FILE_GUARDED, O_WRONLY), -EPERM,
		  "unzoned: open trusted file for write: denied");
	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "join trusted payload to relabel"))
		goto out;
	ASSERT_OK(set_cg_zone(POD1_CG, ZONE_TRUSTED), "trusted: relabel a pod: allowed");
	ASSERT_OK(clone_into(trusted_payload_fd),
		  "trusted: clone3 into trusted payload: allowed");
	assert_zone(pod1_fd, ZONE_TRUSTED, "trusted: pod relabeled");
	ASSERT_OK(try_open(trusted_payload_fd, "cgroup.procs", O_WRONLY),
		  "trusted: write trusted payload procs: allowed");
	ASSERT_OK(try_open(AT_FDCWD, FILE_GUARDED, O_WRONLY),
		  "trusted: open trusted file for write: allowed");
	ASSERT_OK(truncate(FILE_GUARDED, MAPLEN) ? -errno : 0,
		  "trusted: truncate trusted file: allowed");
	/* The policy claims the label for the capability check, so a trusted
	 * task relabels a file and a cgroup without CAP_SYS_ADMIN, while any
	 * other security. name still needs it.
	 */
	if (!ASSERT_OK(make_page_file(FILE_CAPLESS), "make capless file") ||
	    !ASSERT_OK(cap_disable_effective(1ULL << CAP_SYS_ADMIN, &caps),
		       "drop CAP_SYS_ADMIN"))
		goto out;
	ASSERT_OK(set_zone(FILE_CAPLESS, ZONE_DEFAULT),
		  "trusted, no CAP_SYS_ADMIN: relabel file: allowed");
	assert_file_zone(FILE_CAPLESS, ZONE_DEFAULT,
			 "trusted, no CAP_SYS_ADMIN: file relabeled");
	ASSERT_OK(removexattr(FILE_CAPLESS, ZONE_XATTR) ? -errno : 0,
		  "trusted, no CAP_SYS_ADMIN: strip file label: allowed");
	ASSERT_OK(set_cg_zone(POD1_CG, ZONE_TRUSTED),
		  "trusted, no CAP_SYS_ADMIN: relabel a pod: allowed");
	ASSERT_EQ(setxattr(FILE_CAPLESS, "security.bpf.other", "x", 2, 0) ?
		  -errno : 0, -EPERM,
		  "trusted, no CAP_SYS_ADMIN: unowned name: denied");
	ASSERT_OK(cap_enable_effective(caps, NULL), "restore CAP_SYS_ADMIN");
	ASSERT_GE(skel->bss->relabel_denied, 5, "relabel_denied");
	ASSERT_GE(skel->bss->write_denied, 7, "write_denied");
	ASSERT_GE(skel->bss->grow_denied, 2, "grow_denied");

	/* A default task cannot migrate itself into an unlabelled cgroup to
	 * shed enforcement: task_cgroup_attach refuses the downgrade even
	 * though the destination's cgroup.procs carries no label to block the
	 * open. The trusted zone placed us; only we can try to leave.
	 */
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload to escape"))
		goto out;
	/* Writing our pid into an unlabelled cgroup.procs is refused at
	 * file_open, which will not open an unmeasurable control file for
	 * writing, so the escape never even reaches the migration hook.
	 */
	ASSERT_LT(self_enter(PLAIN_POD_CG), 0,
		  "default: self-migrate into unlabelled cgroup: denied");
	/* clone3 into an unlabelled cgroup opens no control file, so it goes
	 * straight to task_cgroup_attach, which refuses the escape out of
	 * enforcement. Confirm the hook itself is what blocks and records it.
	 */
	stamped = skel->bss->enter_denied;
	ASSERT_EQ(clone_into(plain_pod_fd), -EPERM,
		  "default: clone3 into unlabelled cgroup: denied");
	ASSERT_GT(skel->bss->enter_denied, stamped,
		  "escape refused by task_cgroup_attach");
	ASSERT_EQ(map_rwx(), -EPERM,
		  "default: still enforced after the escape attempts");

	/* What the mapping hooks never see: a tracer, a write through the own
	 * mem file, and a script run by its interpreter, which asks for an
	 * exec check first. All refused in the default zone; outside the
	 * policy only attaching to a trusted task is.
	 */
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload to subvert"))
		goto out;
	ASSERT_EQ(try_open(AT_FDCWD, "/proc/self/mem", O_RDWR), -EPERM,
		  "default: open own mem for write: denied");
	ASSERT_OK(try_open(AT_FDCWD, "/proc/self/mem", O_RDONLY),
		  "default: open own mem for read: allowed");
	ASSERT_EQ(attach_child(), -EPERM, "default: ptrace attach: denied");
	ASSERT_EQ(exec_check(FILE_MADE_DEFAULT), -EPERM,
		  "default: exec check of file written here: denied");
	ASSERT_OK(exec_check(FILE_MADE_TRUSTED),
		  "default: exec check of trusted file: allowed");
	if (!ASSERT_OK(enter(PLAIN_POD_CG), "join unzoned pod to subvert"))
		goto out;
	ASSERT_OK(attach_child(), "unzoned: ptrace attach own child: allowed");
	ASSERT_EQ(attach_pid(mover), -EPERM, "unzoned: ptrace attach trusted task: denied");
	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "join trusted payload to subvert"))
		goto out;
	ASSERT_OK(try_open(AT_FDCWD, "/proc/self/mem", O_RDWR),
		  "trusted: open own mem for write: allowed");
	ASSERT_OK(attach_child(), "trusted: ptrace attach: allowed");
	ASSERT_OK(exec_check(FILE_MADE_DEFAULT),
		  "trusted: exec check of default-zone file: allowed");
	ASSERT_GE(skel->bss->ptrace_denied, 3, "ptrace_denied");
	ASSERT_GE(skel->bss->exec_denied, 1, "exec_denied");

	/* A unix socket belongs to the cgroup it was created in: the manager's
	 * are the trusted zone's and cannot be reached from any other, while
	 * the trusted zone may still connect to a default-zone socket.
	 */
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload for sockets"))
		goto out;
	ASSERT_EQ(unix_reach("stream", getpid(), SOCK_STREAM), -EPERM,
		  "default: connect to trusted socket: denied");
	ASSERT_EQ(unix_reach("dgram", getpid(), SOCK_DGRAM), -EPERM,
		  "default: send to trusted socket: denied");
	lfd = unix_listen("default", getpid(), SOCK_STREAM);
	ASSERT_OK_FD(lfd, "default: listen");
	if (!ASSERT_OK(enter(PLAIN_POD_CG), "join unzoned pod for sockets"))
		goto out;
	ASSERT_EQ(unix_reach("stream", getpid(), SOCK_STREAM), -EPERM,
		  "unzoned: connect to trusted socket: denied");
	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "join trusted payload for sockets"))
		goto out;
	ASSERT_OK(unix_reach("stream", getpid(), SOCK_STREAM),
		  "trusted: connect to trusted socket: allowed");
	ASSERT_OK(unix_reach("dgram", getpid(), SOCK_DGRAM),
		  "trusted: send to trusted socket: allowed");
	ASSERT_OK(unix_reach("default", getpid(), SOCK_STREAM),
		  "trusted: connect to default-zone socket: allowed");

	/* A connection the trusted zone made is checked again on every send:
	 * moved to the default zone with it, the task can no longer use it,
	 * while a connection to a default-zone socket keeps working.
	 */
	cfd = unix_connect("stream", getpid());
	if (!ASSERT_OK_FD(cfd, "trusted: connect and keep"))
		goto out;
	ASSERT_OK(send_byte(cfd), "trusted: send on connection to trusted socket: allowed");
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload with connection"))
		goto out;
	ASSERT_EQ(send_byte(cfd), -EPERM,
		  "default: send on kept connection to trusted socket: denied");
	close(cfd);
	cfd = unix_connect("default", getpid());
	if (ASSERT_OK_FD(cfd, "default: connect to default-zone socket"))
		ASSERT_OK(send_byte(cfd),
			  "default: send on connection to default-zone socket: allowed");
	ASSERT_GE(skel->bss->socket_denied, 4, "socket_denied");

	/* What the trusted zone writes becomes trusted: a file the default zone
	 * made is claimed when the trusted zone opens it for writing, or writes
	 * through a descriptor opened elsewhere, and from then on the default
	 * zone may still read it but no longer write to it.
	 */
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload to make files"))
		goto out;
	if (!ASSERT_OK(make_page_file(FILE_CLAIM_OPEN), "make claim-open file") ||
	    !ASSERT_OK(make_page_file(FILE_CLAIM_WRITE), "make claim-write file"))
		goto out;
	assert_file_zone(FILE_CLAIM_OPEN, ZONE_DEFAULT, "default: file starts default");
	wfd = open(FILE_CLAIM_WRITE, O_WRONLY);
	if (!ASSERT_OK_FD(wfd, "default: open own file for write"))
		goto out;
	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "join trusted payload to claim"))
		goto out;
	ASSERT_OK(try_open(AT_FDCWD, FILE_CLAIM_OPEN, O_WRONLY),
		  "trusted: open default-zone file for write: allowed");
	assert_file_zone(FILE_CLAIM_OPEN, ZONE_TRUSTED, "trusted: file claimed on open");
	ASSERT_EQ(write(wfd, "x", 1), 1, "trusted: write through inherited descriptor");
	assert_file_zone(FILE_CLAIM_WRITE, ZONE_TRUSTED, "trusted: file claimed on write");
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload after claim"))
		goto out;
	ASSERT_EQ(try_open(AT_FDCWD, FILE_CLAIM_OPEN, O_WRONLY), -EPERM,
		  "default: open claimed file for write: denied");
	ASSERT_EQ(try_open(AT_FDCWD, FILE_CLAIM_WRITE, O_WRONLY), -EPERM,
		  "default: open written-to file for write: denied");
	ASSERT_OK(try_open(AT_FDCWD, FILE_CLAIM_OPEN, O_RDONLY),
		  "default: open claimed file for read: allowed");
	ASSERT_GE(skel->bss->nr_claimed, 2, "nr_claimed");

	/* A writable descriptor to a trusted file, passed by the trusted zone
	 * over SCM_RIGHTS, is refused at file_receive in the default zone but
	 * accepted in the trusted one: the default zone cannot be handed a way
	 * to rewrite trusted code that the file_open write gate would refuse.
	 */
	if (!ASSERT_OK(enter(PAYLOAD_CG), "join default payload to receive"))
		goto out;
	ASSERT_LT(request_fd(FILE_GUARDED), 0,
		  "default: receive writable fd to trusted file: denied");
	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "join trusted payload to receive"))
		goto out;
	err = request_fd(FILE_GUARDED);
	if (ASSERT_GE(err, 0, "trusted: receive writable fd to trusted file: allowed"))
		close(err);
	ASSERT_GE(skel->bss->recv_denied, 1, "recv_denied");

	/* Trusted zone: the same code and the same transitions go through. */
	if (!ASSERT_OK(enter(TRUSTED_PAYLOAD_CG), "join trusted payload"))
		goto out;
	ASSERT_OK(map_rwx(), "trusted: W+X mapping allowed");
	ASSERT_OK(anon_then_exec(), "trusted: written anon made exec allowed");
	ASSERT_OK(cow_then_exec(FILE_COW),
		  "trusted: written file mapping made exec allowed");
	ASSERT_OK(load_lib(LIB_UNTRUSTED), "trusted: unlabeled lib admitted");
	ASSERT_OK(load_lib(LIB_NOXATTR), "trusted: unreadable-label lib admitted");

	ASSERT_GE(skel->bss->wx_denied, 3, "wx_denied");
	ASSERT_GE(skel->bss->code_denied, 7, "code_denied");
	ASSERT_GE(skel->bss->allowed, 5, "allowed");
out:
	lsm_cgroup_zones__destroy(skel);
	stop_mover();
	if (lfd >= 0)
		close(lfd);
	if (wfd >= 0)
		close(wfd);
	if (cfd >= 0)
		close(cfd);
	if (fdpass[0] >= 0)
		close(fdpass[0]);
	if (trusted_payload_fd >= 0)
		close(trusted_payload_fd);
	if (trusted_fd >= 0)
		close(trusted_fd);
	if (pod1_fd >= 0)
		close(pod1_fd);
	if (payload_fd >= 0)
		close(payload_fd);
	if (pod_fd >= 0)
		close(pod_fd);
	if (plain_pod_fd >= 0)
		close(plain_pod_fd);
	if (plain_fd >= 0)
		close(plain_fd);
	if (root_fd >= 0)
		close(root_fd);
	cleanup_files();
	remove(LIB_NOXATTR);
	if (noxattr_mounted)
		umount(NOXATTR_DIR);
	rmdir(NOXATTR_DIR);
	unsetenv("XZ_BACKDOOR_MARKER");
	cleanup_cgroup_environment();
}
