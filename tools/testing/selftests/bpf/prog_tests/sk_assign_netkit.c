// SPDX-License-Identifier: GPL-2.0
#include <uapi/linux/if_link.h>
#include <net/if.h>
#include <test_progs.h>
#include "network_helpers.h"
#include "netlink_helpers.h"
#include "sk_assign_netkit.skel.h"

#define NS_HOST "sk_assign_host"
#define NS_POD "sk_assign_pod"
#define HOST_DEV "nk_host"
#define POD_DEV "nk_pod"
#define SERVICE_ADDR4 "198.18.0.99"
#define SERVICE_ADDR6 "2001:db8:99::99"
#define SERVICE_PORT 18080
#define PROXY_PORT 15001
#define TEST_DATA "test"
#define IO_TIMEOUT_MS 1000

struct iplink_req {
	struct nlmsghdr n;
	struct ifinfomsg i;
	char buf[512];
};

static int transparent_socket(int fd, void *opts)
{
	int family = *(int *)opts;
	int one = 1;

	if (family == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one,
			       sizeof(one)))
			return -1;
		return setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &one,
				  sizeof(one));
	}
	return setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one));
}

static int create_netkit(void)
{
	struct rtattr *linkinfo, *data, *peer_info;
	struct rtnl_handle rth = { .fd = -1 };
	struct iplink_req req = {};
	int err;

	err = rtnl_open(&rth, 0);
	if (err)
		return err;

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;
	addattr_l(&req.n, sizeof(req), IFLA_IFNAME, HOST_DEV,
		  strlen(HOST_DEV));
	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, "netkit", 6);
	data = addattr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_MODE, NETKIT_L2);
	peer_info = addattr_nest(&req.n, sizeof(req), IFLA_NETKIT_PEER_INFO);
	req.n.nlmsg_len += sizeof(struct ifinfomsg);
	addattr_l(&req.n, sizeof(req), IFLA_IFNAME, POD_DEV,
		  strlen(POD_DEV));
	addattr_nest_end(&req.n, peer_info);
	addattr_nest_end(&req.n, data);
	addattr_nest_end(&req.n, linkinfo);

	errno = 0;
	err = rtnl_talk(&rth, &req.n, NULL);
	if (err && errno)
		err = -errno;
	rtnl_close(&rth);
	return err;
}

static bool setup_netkit(int family)
{
	SYS(fail, "ip link set %s netns %s", POD_DEV, NS_POD);
	SYS(fail, "ip link set %s up", HOST_DEV);
	SYS(fail, "ip -n %s link set %s up", NS_POD, POD_DEV);
	if (family == AF_INET) {
		SYS(fail, "ip addr add 10.88.0.1/24 dev %s", HOST_DEV);
		SYS(fail, "ip -n %s addr add 10.88.0.2/24 dev %s",
		    NS_POD, POD_DEV);
		SYS(fail, "ip -n %s route add default via 10.88.0.1", NS_POD);
		SYS(fail, "ip route add local " SERVICE_ADDR4 "/32 dev lo");
	} else {
		SYS(fail, "ip -6 addr add fd88::1/64 dev %s nodad", HOST_DEV);
		SYS(fail, "ip -n %s -6 addr add fd88::2/64 dev %s nodad",
		    NS_POD, POD_DEV);
		SYS(fail, "ip -n %s -6 route add default via fd88::1", NS_POD);
		SYS(fail, "ip -6 route add local " SERVICE_ADDR6 "/128 dev lo");
	}
	return true;
fail:
	return false;
}

static void run_netkit(int family, int type)
{
	const char *dest = family == AF_INET ? SERVICE_ADDR4 : SERVICE_ADDR6;
	const char *bind_addr = family == AF_INET ? "0.0.0.0" : "::";
	struct sockaddr_storage expected, actual, peer;
	struct bpf_link *link = NULL, *egress = NULL;
	int server = -1, client = -1, accepted = -1;
	struct netns_obj *host = NULL, *pod = NULL;
	struct sk_assign_netkit *skel = NULL;
	socklen_t len, actual_len, peer_len;
	struct network_helper_opts opts = {
		.timeout_ms = IO_TIMEOUT_MS,
		.post_socket_cb = transparent_socket,
		.cb_opts = &family,
	};
	char buf[sizeof(TEST_DATA) - 1];
	struct nstoken *tok;
	int err;

	host = netns_new(NS_HOST, true);
	if (!ASSERT_OK_PTR(host, "host_netns"))
		return;
	pod = netns_new(NS_POD, false);
	if (!ASSERT_OK_PTR(pod, "pod_netns"))
		goto cleanup;
	err = create_netkit();
	if (err == -EOPNOTSUPP || err == -ENODEV) {
		printf("%s:SKIP: CONFIG_NETKIT is unavailable\n", __func__);
		test__skip();
		goto cleanup;
	}
	if (!ASSERT_OK(err, "create_netkit") || !setup_netkit(family))
		goto cleanup;

	server = start_server_str(family, type, bind_addr, PROXY_PORT,
				  &opts);
	if (!ASSERT_GE(server, 0, "start_server"))
		goto cleanup;
	skel = sk_assign_netkit__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;
	skel->rodata->service_port = SERVICE_PORT;
	skel->rodata->proxy_port = PROXY_PORT;
	skel->rodata->udp = type == SOCK_DGRAM;
	if (!ASSERT_OK(sk_assign_netkit__load(skel), "skel_load"))
		goto cleanup;
	link = bpf_program__attach_netkit(skel->progs.assign_proxy,
					  if_nametoindex(HOST_DEV), NULL);
	if (!ASSERT_OK_PTR(link, "attach_netkit"))
		goto cleanup;
	egress = bpf_program__attach_tcx(skel->progs.egress_assign,
					 if_nametoindex(HOST_DEV), NULL);
	if (!ASSERT_OK_PTR(egress, "attach_tcx_egress"))
		goto cleanup;
	if (!ASSERT_OK(make_sockaddr(family, dest, SERVICE_PORT, &expected,
				     &len), "make_sockaddr"))
		goto cleanup;

	tok = open_netns(NS_POD);
	if (!ASSERT_OK_PTR(tok, "open_pod"))
		goto cleanup;
	opts.post_socket_cb = NULL;
	client = connect_to_addr(type, &expected, len, &opts);
	close_netns(tok);
	if (!ASSERT_GE(client, 0, "connect_client"))
		goto cleanup;
	if (type == SOCK_DGRAM) {
		peer_len = sizeof(peer);
		if (!ASSERT_EQ(send(client, TEST_DATA, sizeof(buf), 0),
			       sizeof(buf), "send_client") ||
		    !ASSERT_EQ(recvfrom(server, buf, sizeof(buf), 0,
					(void *)&peer, &peer_len),
			       sizeof(buf), "recv_server") ||
		    !ASSERT_EQ(sendto(server, buf, sizeof(buf), 0,
				      (void *)&peer, peer_len),
			       sizeof(buf), "send_server"))
			goto cleanup;
		goto out;
	}
	accepted = accept(server, NULL, NULL);
	if (!ASSERT_GE(accepted, 0, "accept"))
		goto cleanup;
	memset(&actual, 0, sizeof(actual));
	actual_len = sizeof(actual);
	if (!ASSERT_OK(getsockname(accepted, (void *)&actual, &actual_len),
		       "getsockname") ||
	    !ASSERT_EQ(actual_len, len, "original_address_len") ||
	    !ASSERT_MEMEQ(&actual, &expected, len, "original_destination"))
		goto cleanup;
out:
	ASSERT_GE(skel->bss->assigned, 1, "assigned");
	ASSERT_EQ(skel->bss->errors, 0, "errors");
	ASSERT_EQ(skel->data->clone_ret, 0, "clone_redirect");
	ASSERT_EQ(skel->data->egress_ret, -EOPNOTSUPP, "egress_rejected");
cleanup:
	bpf_link__destroy(egress);
	bpf_link__destroy(link);
	if (accepted >= 0)
		close(accepted);
	if (client >= 0)
		close(client);
	if (server >= 0)
		close(server);
	sk_assign_netkit__destroy(skel);
	netns_free(pod);
	netns_free(host);
}

void test_sk_assign_netkit(void)
{
	static const struct {
		const char *name;
		int family;
		int type;
	} tests[] = {
		{ "tcpv4", AF_INET, SOCK_STREAM },
		{ "tcpv6", AF_INET6, SOCK_STREAM },
		{ "udpv4", AF_INET, SOCK_DGRAM },
		{ "udpv6", AF_INET6, SOCK_DGRAM },
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(tests); i++)
		if (test__start_subtest(tests[i].name))
			run_netkit(tests[i].family, tests[i].type);
}
