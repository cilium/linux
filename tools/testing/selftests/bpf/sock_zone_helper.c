// SPDX-License-Identifier: GPL-2.0
/* The application in the lsm_sock_zone test.
 *
 * Its executable carries a security.bpf.zone label, which the policy reads
 * at exec and puts on every socket this program opens. All this program does
 * is open sockets and ask what they ended up carrying -- it never writes a
 * label, and one of the things it checks is that it could not.
 *
 * argv[1] is the zone the caller expects. The exit status says which step
 * disagreed, so the test can tell a missing label from a forged one.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/xattr.h>

#define ZONE_XATTR	"security.bpf.zone"

enum {
	OK			= 0,
	E_SOCKET		= 1,
	E_LABEL_MISSING		= 2,
	E_LABEL_WRONG		= 3,
	E_FORGED		= 4,	/* fsetxattr(2) was not refused */
	E_LABEL_CHANGED		= 5,
	E_NET			= 6,
	E_ACCEPT		= 7,
	E_ACCEPTED_LABEL	= 8,
};

static int label_is(int fd, const char *zone)
{
	char buf[64] = {};
	ssize_t len;

	len = fgetxattr(fd, ZONE_XATTR, buf, sizeof(buf));
	if (len < 0)
		return E_LABEL_MISSING;
	if ((size_t)len != strlen(zone) + 1 || strcmp(buf, zone))
		return E_LABEL_WRONG;
	return OK;
}

/* The socket this program just opened carries the label, and this program
 * cannot change it.
 */
static int check_own_socket(const char *zone)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(1),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int fd, ret;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return E_SOCKET;

	/* Expected to fail; only the socket_connect hook matters. */
	connect(fd, (struct sockaddr *)&addr, sizeof(addr));

	ret = label_is(fd, zone);
	if (ret)
		goto out;
	if (!fsetxattr(fd, ZONE_XATTR, "forged", sizeof("forged"), 0)) {
		ret = E_FORGED;
		goto out;
	}
	ret = label_is(fd, zone) ? E_LABEL_CHANGED : OK;
out:
	close(fd);
	return ret;
}

/* An accepted socket is a new socket with a new inode, and carries the
 * label the policy copied onto it from the listener.
 */
static int check_accepted_socket(const char *zone)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int srv = -1, cli = -1, acc = -1, ret = E_NET;
	socklen_t len = sizeof(addr);

	srv = socket(AF_INET, SOCK_STREAM, 0);
	cli = socket(AF_INET, SOCK_STREAM, 0);
	if (srv < 0 || cli < 0) {
		ret = E_SOCKET;
		goto out;
	}
	if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) ||
	    listen(srv, 1) ||
	    getsockname(srv, (struct sockaddr *)&addr, &len) ||
	    connect(cli, (struct sockaddr *)&addr, sizeof(addr)))
		goto out;

	acc = accept(srv, NULL, NULL);
	if (acc < 0) {
		ret = E_ACCEPT;
		goto out;
	}
	if (label_is(acc, zone)) {
		ret = E_ACCEPTED_LABEL;
		goto out;
	}
	/* Send from the accepted socket, so the sendmsg hook sees its label. */
	ret = send(acc, "x", 1, 0) == 1 ? OK : E_NET;
out:
	if (acc >= 0)
		close(acc);
	if (cli >= 0)
		close(cli);
	if (srv >= 0)
		close(srv);
	return ret;
}

int main(int argc, char **argv)
{
	const char *zone = argc > 1 ? argv[1] : "prod";
	int ret;

	ret = check_own_socket(zone);
	if (ret)
		return ret;
	return check_accepted_socket(zone);
}
