// SPDX-License-Identifier: GPL-2.0
/* Unix sockets, scoped by cgroup zone. The manager parked in the trusted pod
 * holds a listening stream socket and a bound datagram socket, so those are
 * the trusted zone's; the test process, placed by the manager, plays the
 * default zone from the zoned root, the trusted zone from the trusted pod,
 * and no zone from the unzoned root.
 */
#define ZONE_TMP	"/tmp/test_progs_zone_unix_"
#include "lsm_zone_helpers.h"
#include "lsm_zone_unix.skel.h"

#define DEFAULT_CG	ROOT_CG
#define UNZONED_CG	PLAIN_CG

/* A trusted zone's stream socket cannot be connected to from any other. */
static void test_default_connect_to_trusted_denied(struct lsm_zone_unix *skel)
{
	__u32 denied = skel->bss->socket_denied;

	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(unix_reach("stream", getpid(), SOCK_STREAM), -EPERM,
		  "default: connect to trusted socket: denied");
	if (!ASSERT_OK(enter(UNZONED_CG), "enter unzoned"))
		return;
	ASSERT_EQ(unix_reach("stream", getpid(), SOCK_STREAM), -EPERM,
		  "unzoned: connect to trusted socket: denied");
	ASSERT_EQ(skel->bss->socket_denied - denied, 2, "socket_denied");
}

/* Nor can a datagram be sent to its datagram socket. */
static void test_default_send_to_trusted_denied(struct lsm_zone_unix *skel)
{
	__u32 denied = skel->bss->socket_denied;

	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	ASSERT_EQ(unix_reach("dgram", getpid(), SOCK_DGRAM), -EPERM,
		  "default: send to trusted socket: denied");
	if (!ASSERT_OK(enter(UNZONED_CG), "enter unzoned"))
		return;
	ASSERT_EQ(unix_reach("dgram", getpid(), SOCK_DGRAM), -EPERM,
		  "unzoned: send to trusted socket: denied");
	ASSERT_EQ(skel->bss->socket_denied - denied, 2, "socket_denied");
}

/* From inside the trusted zone both are reached. */
static void test_trusted_connect_to_trusted_allowed(struct lsm_zone_unix *skel)
{
	__u32 denied = skel->bss->socket_denied;

	if (!ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		return;
	ASSERT_OK(unix_reach("stream", getpid(), SOCK_STREAM),
		  "trusted: connect to trusted socket: allowed");
	ASSERT_OK(unix_reach("dgram", getpid(), SOCK_DGRAM),
		  "trusted: send to trusted socket: allowed");
	ASSERT_EQ(skel->bss->socket_denied, denied, "socket_denied unchanged");
}

/* The trusted zone may still connect and send outward, to sockets of the
 * default zone.
 */
static void test_trusted_connect_outward_allowed(struct lsm_zone_unix *skel)
{
	int lfd, dfd;

	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	lfd = unix_listen("outward", getpid(), SOCK_STREAM);
	dfd = unix_listen("outward_dgram", getpid(), SOCK_DGRAM);
	if (ASSERT_OK_FD(lfd, "default: listen") &&
	    ASSERT_OK_FD(dfd, "default: bind datagram") &&
	    ASSERT_OK(enter(TRUSTED_CG), "enter trusted")) {
		ASSERT_OK(unix_reach("outward", getpid(), SOCK_STREAM),
			  "trusted: connect to default-zone socket: allowed");
		ASSERT_OK(unix_reach("outward_dgram", getpid(), SOCK_DGRAM),
			  "trusted: send to default-zone socket: allowed");
	}
	if (lfd >= 0)
		close(lfd);
	if (dfd >= 0)
		close(dfd);
}

/* A connection the trusted zone made is checked again on every send: moved
 * to the default zone with it, the task can no longer send to the trusted
 * socket, while a connection to a default-zone socket keeps working.
 */
static void test_kept_connection_rechecked_on_send(struct lsm_zone_unix *skel)
{
	__u32 denied = skel->bss->socket_denied;
	int lfd, tfd = -1, dfd = -1;

	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	lfd = unix_listen("kept", getpid(), SOCK_STREAM);
	if (!ASSERT_OK_FD(lfd, "default: listen") ||
	    !ASSERT_OK(enter(TRUSTED_CG), "enter trusted"))
		goto out;
	tfd = unix_connect("stream", getpid());
	if (!ASSERT_OK_FD(tfd, "trusted: connect to trusted socket and keep"))
		goto out;
	ASSERT_OK(send_byte(tfd), "trusted: send on connection to trusted socket: allowed");
	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default with the connection"))
		goto out;
	ASSERT_EQ(send_byte(tfd), -EPERM,
		  "default: send on kept connection to trusted socket: denied");
	/* A connection to a default-zone socket, made here so that both ends
	 * belong to this zone, keeps working.
	 */
	dfd = unix_connect("kept", getpid());
	if (!ASSERT_OK_FD(dfd, "default: connect to default-zone socket"))
		goto out;
	ASSERT_OK(send_byte(dfd),
		  "default: send on connection to default-zone socket: allowed");
	ASSERT_EQ(skel->bss->socket_denied - denied, 1, "socket_denied");
out:
	if (tfd >= 0)
		close(tfd);
	if (dfd >= 0)
		close(dfd);
	if (lfd >= 0)
		close(lfd);
}

/* Sockets of the default zone are reached from the default zone as ever. */
static void test_default_to_default_allowed(struct lsm_zone_unix *skel)
{
	__u32 denied = skel->bss->socket_denied;
	int lfd, dfd, cfd = -1;

	if (!ASSERT_OK(enter(DEFAULT_CG), "enter default"))
		return;
	lfd = unix_listen("own", getpid(), SOCK_STREAM);
	dfd = unix_listen("own_dgram", getpid(), SOCK_DGRAM);
	if (!ASSERT_OK_FD(lfd, "default: listen") ||
	    !ASSERT_OK_FD(dfd, "default: bind datagram"))
		goto out;
	cfd = unix_connect("own", getpid());
	if (ASSERT_OK_FD(cfd, "default: connect to default-zone socket: allowed"))
		ASSERT_OK(send_byte(cfd),
			  "default: send on connection to default-zone socket: allowed");
	ASSERT_OK(unix_reach("own_dgram", getpid(), SOCK_DGRAM),
		  "default: send to default-zone socket: allowed");
	ASSERT_EQ(skel->bss->socket_denied, denied, "socket_denied unchanged");
out:
	if (cfd >= 0)
		close(cfd);
	if (lfd >= 0)
		close(lfd);
	if (dfd >= 0)
		close(dfd);
}

void test_lsm_zone_unix(void)
{
	struct lsm_zone_unix *skel = NULL;
	struct zone_env env = { -1, -1, -1 };
	int err;

	err = zone_bootstrap(&env);
	if (err == -EOPNOTSUPP) {
		printf("%s:SKIP:cannot set %s on a cgroup\n", __func__, ZONE_XATTR);
		test__skip();
		goto out;
	}
	if (!ASSERT_OK(err, "zone_bootstrap"))
		goto out;

	skel = lsm_zone_unix__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open_and_load"))
		goto out;
	skel->bss->monitored_pid = getpid();
	if (!ASSERT_OK(lsm_zone_unix__attach(skel), "skel attach"))
		goto out;

	if (test__start_subtest("default_connect_to_trusted_denied"))
		test_default_connect_to_trusted_denied(skel);
	if (test__start_subtest("default_send_to_trusted_denied"))
		test_default_send_to_trusted_denied(skel);
	if (test__start_subtest("trusted_connect_to_trusted_allowed"))
		test_trusted_connect_to_trusted_allowed(skel);
	if (test__start_subtest("trusted_connect_outward_allowed"))
		test_trusted_connect_outward_allowed(skel);
	if (test__start_subtest("kept_connection_rechecked_on_send"))
		test_kept_connection_rechecked_on_send(skel);
	if (test__start_subtest("default_to_default_allowed"))
		test_default_to_default_allowed(skel);
out:
	lsm_zone_unix__destroy(skel);
	zone_teardown(&env);
}
