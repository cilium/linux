// SPDX-License-Identifier: GPL-2.0
#include <net/if.h>
#include <netinet/tcp.h>
#include <uapi/linux/if_link.h>
#include <test_progs.h>
#include <stdint.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include "netlink_helpers.h"
#include "network_helpers.h"
#include "unpriv_helpers.h"
#include "sk_assign_netkit.skel.h"
#include "sk_assign_lifetime.skel.h"

#define NS_HOST "sk_assign_host"
#define NS_POD "sk_assign_pod"
#define HOST_DEV "nk_host"
#define POD_DEV "nk_pod"
#define DEST_PORT 18080
#define PROXY_PORT 15001
#define TEST_DATA "test"
#define TEST_ITERATIONS 8
#define IO_TIMEOUT_MS 1000
#define POLL_RETRIES 5000
#define POLL_INTERVAL_US 1000
#define QUEUE_TIMEOUT_MS 5000
#define QUEUE_CLIENT_TIMEOUT_MS 10000
#define DUMMY_DEV "nk_dummy"

enum {
	AFTER_ASSIGN_PASS,
	AFTER_ASSIGN_DROP,
	AFTER_ASSIGN_REDIRECT,
};

struct queue_request {
	struct nlmsghdr n;
	struct nfgenmsg g;
	char buf[512];
};

struct netkit_request {
	struct nlmsghdr n;
	struct ifinfomsg i;
	char buf[1024];
};

struct queue_worker {
	struct sk_assign_lifetime *skel;
	__u64 *measurement_done;
	__u64 *blocked_syns;
	pthread_t thread;
	bool wait_retransmit;
	int reference_errors;
	int error;
	int fd;
};

static int queue_config(int fd, int type, const void *data, int len)
{
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	struct queue_request req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg)),
		.n.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG,
		.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
		.g.version = NFNETLINK_V0,
	};
	struct nlmsgerr *err;
	char reply[512];
	int ret;

	addattr_l(&req.n, sizeof(req), type, data, len);
	ret = sendto(fd, &req, req.n.nlmsg_len, 0, (void *)&addr, sizeof(addr));
	if (ret < 0)
		return -errno;
	ret = recv(fd, reply, sizeof(reply), 0);
	if (ret < 0)
		return -errno;
	if (ret < NLMSG_LENGTH(sizeof(*err)))
		return -EIO;
	if (((struct nlmsghdr *)reply)->nlmsg_type != NLMSG_ERROR)
		return -EPROTO;
	err = NLMSG_DATA((struct nlmsghdr *)reply);
	return err->error;
}

static int queue_open(void)
{
	struct nfqnl_msg_config_cmd cmd = { .command = NFQNL_CFG_CMD_BIND };
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	struct nfqnl_msg_config_params params = {
		.copy_range = htonl(UINT16_MAX),
		.copy_mode = NFQNL_COPY_PACKET,
	};
	int fd, err;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (fd < 0)
		return -errno;
	if (bind(fd, (void *)&addr, sizeof(addr)) ||
	    settimeo(fd, QUEUE_TIMEOUT_MS)) {
		err = -errno;
		goto out;
	}
	err = queue_config(fd, NFQA_CFG_CMD, &cmd, sizeof(cmd));
	if (err)
		goto out;
	err = queue_config(fd, NFQA_CFG_PARAMS, &params, sizeof(params));
	if (!err)
		return fd;
out:
	close(fd);
	return err;
}

static bool queue_tracing_target(struct bpf_program *prog, const char *name)
{
	int err;

	err = bpf_program__set_attach_target(prog, 0, name);
	if (err == -ESRCH || err == -ENOENT) {
		printf("SKIP: %s BTF is unavailable\n", name);
		test__skip();
		return false;
	}
	return ASSERT_OK(err, "tracing_target");
}

static void *queue_verdict(void *arg)
{
	struct nfqnl_msg_verdict_hdr verdict = { .verdict = htonl(NF_ACCEPT) };
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };
	struct queue_worker *worker = arg;
	struct nfqnl_msg_packet_hdr *hdr;
	struct queue_request req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg)),
		.n.nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT,
		.n.nlmsg_flags = NLM_F_REQUEST,
		.g.version = NFNETLINK_V0,
	};
	char buf[UINT16_MAX + 1];
	__u32 errors, mark = 0;
	struct nlmsghdr *nlh;
	bool packet = false;
	struct rtattr *attr;
	int fd, ret, len, i;

	ret = recv(worker->fd, buf, sizeof(buf), 0);
	if (ret < 0) {
		worker->error = -errno;
		return NULL;
	}
	nlh = (void *)buf;
	if (!NLMSG_OK(nlh, ret) ||
	    nlh->nlmsg_type != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET)) {
		worker->error = -EPROTO;
		return NULL;
	}
	len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct nfgenmsg));
	attr = (void *)((char *)NLMSG_DATA(nlh) +
		       NLMSG_ALIGN(sizeof(struct nfgenmsg)));
	for (; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
		switch (attr->rta_type & NLA_TYPE_MASK) {
		case NFQA_PACKET_HDR:
			if (RTA_PAYLOAD(attr) < sizeof(*hdr))
				goto invalid;
			hdr = RTA_DATA(attr);
			verdict.id = hdr->packet_id;
			packet = true;
			break;
		case NFQA_MARK:
			if (RTA_PAYLOAD(attr) != sizeof(mark))
				goto invalid;
			memcpy(&mark, RTA_DATA(attr), sizeof(mark));
			mark = ntohl(mark);
			break;
		}
	}
	if (!packet || !mark)
		goto invalid;
	if (worker->wait_retransmit) {
		for (i = 0; i < POLL_RETRIES; i++) {
			if (__atomic_load_n(worker->blocked_syns, __ATOMIC_RELAXED))
				break;
			usleep(POLL_INTERVAL_US);
		}
		if (i == POLL_RETRIES)
			worker->error = -ETIMEDOUT;
	}
	fd = bpf_map__fd(worker->skel->maps.observed);
	ret = bpf_map_lookup_elem(fd, &mark, &errors);
	if (ret) {
		worker->error = -errno;
	} else {
		worker->reference_errors = errors;
		if (bpf_map_delete_elem(fd, &mark))
			worker->error = -errno;
	}
	__atomic_store_n(worker->measurement_done, 1, __ATOMIC_RELEASE);
	addattr_l(&req.n, sizeof(req), NFQA_VERDICT_HDR, &verdict, sizeof(verdict));
	ret = sendto(worker->fd, &req, req.n.nlmsg_len, 0,
		     (void *)&addr, sizeof(addr));
	if (ret < 0)
		worker->error = -errno;
	return NULL;
invalid:
	worker->error = -EPROTO;
	return NULL;
}

static bool setup_nfqueue(struct sk_assign_netkit *skel,
			  struct queue_worker *worker, int server, int family,
			  bool retransmit)
{
	const char *nft_family = family == AF_INET ? "ip" : "ip6";
	socklen_t cookie_len = sizeof(__u64);
	struct sk_assign_lifetime *lifetime;
	__u64 cookie;

	if (!kernel_config_has("CONFIG_LTO_NONE=y")) {
		printf("SKIP: queue tracing requires a confirmed non-LTO kernel\n");
		test__skip();
		return false;
	}
	if (!kernel_config_has("CONFIG_DYNAMIC_FTRACE=y")) {
		printf("SKIP: queue tracing requires dynamic ftrace\n");
		test__skip();
		return false;
	}
	if (kernel_config_disabled("CONFIG_NF_TABLES") ||
	    kernel_config_disabled("CONFIG_NFT_QUEUE") ||
	    kernel_config_disabled(family == AF_INET ? "CONFIG_NF_TABLES_IPV4" :
						    "CONFIG_NF_TABLES_IPV6")) {
		printf("SKIP: nftables queue or family support is disabled\n");
		test__skip();
		return false;
	}
	worker->fd = queue_open();
	if (worker->fd == -EPROTONOSUPPORT || worker->fd == -EOPNOTSUPP ||
	    worker->fd == -EINVAL) {
		printf("SKIP: NFQUEUE is unavailable\n");
		test__skip();
		return false;
	}
	if (!ASSERT_GE(worker->fd, 0, "queue_open"))
		return false;
	if (!ASSERT_OK(getsockopt(server, SOL_SOCKET, SO_COOKIE, &cookie,
				  &cookie_len), "listener_cookie"))
		return false;
	worker->skel = sk_assign_lifetime__open();
	lifetime = worker->skel;
	if (!ASSERT_OK_PTR(lifetime, "lifetime_open"))
		return false;
	lifetime->rodata->listener_cookie = cookie;
	bpf_program__set_autoload(lifetime->progs.release_enter, false);
	bpf_program__set_autoload(lifetime->progs.release_exit, false);
	bpf_program__set_autoload(lifetime->progs.release_put, false);
	if (!queue_tracing_target(lifetime->progs.queue_enter, "nf_queue") ||
	    !queue_tracing_target(lifetime->progs.queue_observe,
				  "nfqnl_enqueue_packet"))
		return false;
	if (!ASSERT_OK(sk_assign_lifetime__load(lifetime), "lifetime_load"))
		return false;
	if (!ASSERT_OK(sk_assign_lifetime__attach(lifetime), "lifetime_attach"))
		return false;
	worker->measurement_done = &skel->bss->measurement_done;
	worker->blocked_syns = &skel->bss->blocked_syns;
	worker->wait_retransmit = retransmit;
	SYS(out, "nft add table %s sk_assign", nft_family);
	SYS(out, "nft add chain %s sk_assign pre '%s'", nft_family,
	    "{ type filter hook prerouting priority 0; }");
	SYS(out, "nft add rule %s sk_assign pre meta mark 1 queue num 0",
	    nft_family);
	return ASSERT_OK(pthread_create(&worker->thread, NULL, queue_verdict,
				       worker), "queue_thread");
out:
	return false;
}

static int create_netkit(void)
{
	struct rtattr *linkinfo, *data, *peer_info;
	struct rtnl_handle rth = { .fd = -1 };
	struct netkit_request req = {};
	int err;

	err = rtnl_open(&rth, 0);
	if (err)
		return err;
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;
	addattrstrz(&req.n, sizeof(req), IFLA_IFNAME, HOST_DEV);
	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattrstrz(&req.n, sizeof(req), IFLA_INFO_KIND, "netkit");
	data = addattr_nest(&req.n, sizeof(req), IFLA_INFO_DATA);
	addattr32(&req.n, sizeof(req), IFLA_NETKIT_MODE, NETKIT_L2);
	peer_info = addattr_nest(&req.n, sizeof(req), IFLA_NETKIT_PEER_INFO);
	req.n.nlmsg_len += sizeof(struct ifinfomsg);
	addattrstrz(&req.n, sizeof(req), IFLA_IFNAME, POD_DEV);
	addattr_nest_end(&req.n, peer_info);
	addattr_nest_end(&req.n, data);
	addattr_nest_end(&req.n, linkinfo);
	rth.flags |= RTNL_HANDLE_F_SUPPRESS_NLERR;
	err = rtnl_talk(&rth, &req.n, NULL);
	if (err)
		err = -errno;
	rtnl_close(&rth);
	return err;
}

static int transparent_socket(int fd, void *opts)
{
	int family = *(int *)opts;
	int one = 1;

	if (family == AF_INET6) {
		if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one)))
			return -1;
		return setsockopt(fd, IPPROTO_IPV6, IPV6_TRANSPARENT, &one,
				  sizeof(one));
	}
	return setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one));
}

static void check_test_run_assign(struct sk_assign_netkit *skel, int family)
{
	struct __sk_buff ctx = { .ifindex = if_nametoindex(HOST_DEV) };
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	);
	int fd;

	memset(&skel->bss->probe_tuple, 0, sizeof(skel->bss->probe_tuple));
	if (family == AF_INET) {
		skel->bss->probe_tuple.ipv4.dport = htons(PROXY_PORT);
		skel->bss->probe_len = sizeof(skel->bss->probe_tuple.ipv4);
		opts.data_in = &pkt_v4;
		opts.data_size_in = sizeof(pkt_v4);
	} else {
		skel->bss->probe_tuple.ipv6.dport = htons(PROXY_PORT);
		skel->bss->probe_len = sizeof(skel->bss->probe_tuple.ipv6);
		opts.data_in = &pkt_v6;
		opts.data_size_in = sizeof(pkt_v6);
	}
	skel->bss->probe_state = 0;
	skel->bss->probe_result = 0;
	fd = bpf_program__fd(skel->progs.probe_timewait);
	if (!ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "test_run_assign"))
		return;
	ASSERT_EQ(skel->bss->probe_state, BPF_TCP_LISTEN, "test_run_listener");
	ASSERT_EQ(skel->bss->probe_result, -EOPNOTSUPP, "test_run_rejected");
}

static void check_timewait(struct sk_assign_netkit *skel, int family,
			   int accepted, int client)
{
	struct __sk_buff ctx = { .ifindex = if_nametoindex(HOST_DEV) };
	DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
		.data_in = &pkt_v4,
		.data_size_in = sizeof(pkt_v4),
		.ctx_in = &ctx,
		.ctx_size_in = sizeof(ctx),
	);
	struct sockaddr_storage local, peer;
	socklen_t len = sizeof(local);
	struct sockaddr_in6 *l6, *p6;
	struct sockaddr_in *l4, *p4;
	int i, fd;
	char buf;

	if (!ASSERT_OK(getsockname(accepted, (void *)&local, &len),
		       "timewait_local"))
		return;
	len = sizeof(peer);
	if (!ASSERT_OK(getpeername(accepted, (void *)&peer, &len),
		       "timewait_peer"))
		return;
	if (family == AF_INET) {
		l4 = (void *)&local;
		p4 = (void *)&peer;
		skel->bss->probe_tuple.ipv4.saddr = p4->sin_addr.s_addr;
		skel->bss->probe_tuple.ipv4.daddr = l4->sin_addr.s_addr;
		skel->bss->probe_tuple.ipv4.sport = p4->sin_port;
		skel->bss->probe_tuple.ipv4.dport = l4->sin_port;
		skel->bss->probe_len = sizeof(skel->bss->probe_tuple.ipv4);
	} else {
		l6 = (void *)&local;
		p6 = (void *)&peer;
		memcpy(skel->bss->probe_tuple.ipv6.saddr, &p6->sin6_addr,
		       sizeof(p6->sin6_addr));
		memcpy(skel->bss->probe_tuple.ipv6.daddr, &l6->sin6_addr,
		       sizeof(l6->sin6_addr));
		skel->bss->probe_tuple.ipv6.sport = p6->sin6_port;
		skel->bss->probe_tuple.ipv6.dport = l6->sin6_port;
		skel->bss->probe_len = sizeof(skel->bss->probe_tuple.ipv6);
	}
	if (!ASSERT_OK(shutdown(accepted, SHUT_WR), "server_shutdown") ||
	    !ASSERT_EQ(recv(client, &buf, 1, 0), 0, "client_eof") ||
	    !ASSERT_OK(shutdown(client, SHUT_WR), "client_shutdown") ||
	    !ASSERT_EQ(recv(accepted, &buf, 1, 0), 0, "server_eof"))
		return;
	fd = bpf_program__fd(skel->progs.probe_timewait);
	for (i = 0; i < POLL_RETRIES; i++) {
		if (!ASSERT_OK(bpf_prog_test_run_opts(fd, &opts), "probe_timewait"))
			return;
		if (skel->bss->probe_state == BPF_TCP_TIME_WAIT)
			break;
		usleep(POLL_INTERVAL_US);
	}
	ASSERT_EQ(skel->bss->probe_state, BPF_TCP_TIME_WAIT, "timewait_found");
	ASSERT_EQ(skel->bss->probe_result, -EOPNOTSUPP, "timewait_rejected");
}

static int enable_netns_ipv6(const char *name)
{
	struct nstoken *token;
	int err;

	token = open_netns(name);
	if (!token)
		return -1;
	err = write_sysctl("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0");
	if (!err)
		err = write_sysctl("/proc/sys/net/ipv6/conf/default/disable_ipv6",
				   "0");
	close_netns(token);
	return err;
}

static bool setup_netkit(int family, struct netns_obj **host,
			 struct netns_obj **pod)
{
	int err;

	err = socket(family, SOCK_STREAM, 0);
	if (err < 0 && errno == EAFNOSUPPORT) {
		printf("SKIP: address family %d is unavailable\n", family);
		test__skip();
		return false;
	}
	if (!ASSERT_GE(err, 0, "family_probe"))
		return false;
	close(err);
	*host = netns_new(NS_HOST, true);
	if (!ASSERT_NEQ(*host, NULL, "host_netns"))
		return false;
	*pod = netns_new(NS_POD, false);
	if (!ASSERT_NEQ(*pod, NULL, "pod_netns"))
		return false;
	if (family == AF_INET6 &&
	    (!ASSERT_OK(enable_netns_ipv6(NS_HOST), "host_ipv6") ||
	     !ASSERT_OK(enable_netns_ipv6(NS_POD), "pod_ipv6")))
		return false;
	err = create_netkit();
	if (err == -EOPNOTSUPP) {
		printf("SKIP: netkit is unavailable\n");
		test__skip();
		return false;
	}
	if (!ASSERT_OK(err, "create_netkit"))
		return false;
	SYS(fail, "ip link set %s netns %s", POD_DEV, NS_POD);
	SYS(fail, "ip link set %s up", HOST_DEV);
	SYS(fail, "ip -n %s link set %s up", NS_POD, POD_DEV);
	if (family == AF_INET) {
		SYS(fail, "ip addr add 10.88.0.1/24 dev %s", HOST_DEV);
		SYS(fail, "ip -n %s addr add 10.88.0.2/24 dev %s", NS_POD, POD_DEV);
		SYS(fail, "ip -n %s route add default via 10.88.0.1", NS_POD);
		SYS(fail, "ip route add local 198.18.0.99/32 dev lo");
		if (!ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/conf/all/rp_filter", "0"),
			       "rp_filter_all") ||
		    !ASSERT_OK(write_sysctl("/proc/sys/net/ipv4/conf/" HOST_DEV
				   "/rp_filter", "0"),
			       "rp_filter_host"))
			return false;
	} else {
		SYS(fail, "ip -6 addr add fd88::1/64 dev %s nodad", HOST_DEV);
		SYS(fail, "ip -n %s -6 addr add fd88::2/64 dev %s nodad", NS_POD, POD_DEV);
		SYS(fail, "ip -n %s -6 route add default via fd88::1", NS_POD);
		SYS(fail, "ip -6 route add local 2001:db8:99::99/128 dev lo");
	}
	return true;
fail:
	return false;
}

static int connect_pod(const struct sockaddr_storage *addr, socklen_t len,
		       const struct network_helper_opts *opts)
{
	struct nstoken *tok;
	int fd;

	tok = open_netns(NS_POD);
	if (!ASSERT_NEQ(tok, NULL, "open_pod"))
		return -1;
	fd = connect_to_addr(SOCK_STREAM, addr, len, opts);
	close_netns(tok);
	return fd;
}

static void run_netkit(int family, bool nfqueue, bool retransmit)
{
	const char *dest = family == AF_INET ? "198.18.0.99" : "2001:db8:99::99";
	struct queue_worker worker = { .reference_errors = -1, .fd = -1 };
	const char *bind_addr = family == AF_INET ? "0.0.0.0" : "::";
	int server = -1, client = -1, accepted = -1;
	struct netns_obj *host = NULL, *pod = NULL;
	struct network_helper_opts client_opts = {
		.timeout_ms = IO_TIMEOUT_MS,
	};
	struct sockaddr_storage expected, actual;
	struct sk_assign_netkit *skel = NULL;
	struct network_helper_opts opts = {
		.timeout_ms = IO_TIMEOUT_MS,
		.post_socket_cb = transparent_socket,
		.cb_opts = &family,
	};
	char buf[sizeof(TEST_DATA) - 1];
	struct bpf_link *link = NULL;
	bool worker_started = false;
	socklen_t len, actual_len;
	int i;

	if (nfqueue && SYS_NOFAIL("nft -v")) {
		printf("Missing required nft tool\n");
		test__skip();
		return;
	}
	if (!setup_netkit(family, &host, &pod))
		goto cleanup;

	server = start_server_str(family, SOCK_STREAM, bind_addr, PROXY_PORT, &opts);
	if (!ASSERT_GE(server, 0, "start_server"))
		goto cleanup;
	skel = sk_assign_netkit__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;
	skel->rodata->dest_port = DEST_PORT;
	skel->rodata->proxy_port = PROXY_PORT;
	skel->rodata->measure_queue = nfqueue;
	if (!ASSERT_OK(sk_assign_netkit__load(skel), "skel_load"))
		goto cleanup;
	check_test_run_assign(skel, family);
	link = bpf_program__attach_netkit(skel->progs.assign_socket,
					  if_nametoindex(HOST_DEV), NULL);
	if (!ASSERT_OK_PTR(link, "attach_netkit"))
		goto cleanup;
	if (!ASSERT_OK(make_sockaddr(family, dest, DEST_PORT, &expected, &len),
		       "make_sockaddr"))
		goto cleanup;

	if (nfqueue) {
		if (!setup_nfqueue(skel, &worker, server, family, retransmit))
			goto cleanup;
		worker_started = true;
		client_opts.timeout_ms = QUEUE_CLIENT_TIMEOUT_MS;
	}

	for (i = 0; i < (nfqueue ? 1 : TEST_ITERATIONS); i++) {
		client = connect_pod(&expected, len, &client_opts);
		if (!ASSERT_GE(client, 0, "connect_client"))
			goto cleanup;
		accepted = accept(server, NULL, NULL);
		if (!ASSERT_GE(accepted, 0, "accept"))
			goto cleanup;
		if (!ASSERT_OK(settimeo(accepted, IO_TIMEOUT_MS),
			       "accepted_timeout"))
			goto cleanup;
		memset(&actual, 0, sizeof(actual));
		actual_len = sizeof(actual);
		if (!ASSERT_OK(getsockname(accepted, (void *)&actual, &actual_len),
			       "getsockname"))
			goto cleanup;
		ASSERT_EQ(actual_len, len, "original_address_len");
		ASSERT_MEMEQ(&actual, &expected, len, "original_destination");
		if (!ASSERT_EQ(send(client, TEST_DATA, sizeof(buf), 0),
			       sizeof(buf), "send_client") ||
		    !ASSERT_EQ(recv(accepted, buf, sizeof(buf), MSG_WAITALL),
			       sizeof(buf), "recv_server") ||
		    !ASSERT_MEMEQ(buf, TEST_DATA, sizeof(buf), "server_data") ||
		    !ASSERT_EQ(send(accepted, buf, sizeof(buf), 0), sizeof(buf),
			       "send_server") ||
		    !ASSERT_EQ(recv(client, buf, sizeof(buf), MSG_WAITALL),
			       sizeof(buf), "recv_client") ||
		    !ASSERT_MEMEQ(buf, TEST_DATA, sizeof(buf), "client_data"))
			goto cleanup;
		if (i == TEST_ITERATIONS - 1)
			check_timewait(skel, family, accepted, client);
		close(accepted);
		accepted = -1;
		close(client);
		client = -1;
	}
	if (!ASSERT_OK(bpf_link__detach(link), "detach_netkit"))
		goto cleanup;
	ASSERT_GE(skel->bss->listener_assignments,
		  nfqueue ? 1 : TEST_ITERATIONS, "listener_assignments");
	ASSERT_GT(skel->bss->established_assignments, 0, "established_assignments");
	ASSERT_GT(skel->bss->request_rejections, 0, "request_rejections");
	ASSERT_EQ(skel->bss->assign_errors, 0, "assign_errors");
	if (retransmit)
		ASSERT_GT(skel->bss->blocked_syns, 0, "retransmitted_syn_blocked");
cleanup:
	if (worker_started) {
		ASSERT_OK(pthread_join(worker.thread, NULL), "queue_join");
		ASSERT_OK(worker.error, "queue_verdict");
		ASSERT_EQ(worker.reference_errors, 0, "queue_references");
		ASSERT_EQ(worker.skel->bss->queue_errors, 0, "queue_map_errors");
	}
	if (worker.fd >= 0)
		close(worker.fd);
	sk_assign_lifetime__destroy(worker.skel);
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

static __u64 socket_cookie(int fd)
{
	socklen_t len = sizeof(__u64);
	__u64 cookie = 0;

	ASSERT_OK(getsockopt(fd, SOL_SOCKET, SO_COOKIE, &cookie, &len),
		  "socket_cookie");
	return cookie;
}

static struct sk_assign_lifetime *open_release_trace(int server)
{
	static const char * const targets[] = { "sock_pfree_ref", "sock_gen_put" };
	struct sk_assign_lifetime *lifetime;
	int ret, i;

	if (!kernel_config_has("CONFIG_LTO_NONE=y")) {
		printf("SKIP: release tracing requires a confirmed non-LTO kernel\n");
		test__skip();
		return NULL;
	}
	if (!kernel_config_has("CONFIG_DYNAMIC_FTRACE=y")) {
		printf("SKIP: release tracing requires dynamic ftrace\n");
		test__skip();
		return NULL;
	}
	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		ret = libbpf_find_vmlinux_btf_id(targets[i], BPF_TRACE_FENTRY);
		if (ret <= 0) {
			printf("SKIP: %s tracing is unavailable\n", targets[i]);
			test__skip();
			return NULL;
		}
	}
	lifetime = sk_assign_lifetime__open();
	if (!ASSERT_OK_PTR(lifetime, "lifetime_open"))
		return NULL;
	lifetime->rodata->release_cookie = socket_cookie(server);
	bpf_program__set_autoload(lifetime->progs.queue_enter, false);
	bpf_program__set_autoload(lifetime->progs.queue_observe, false);
	if (!ASSERT_OK(sk_assign_lifetime__load(lifetime), "lifetime_load") ||
	    !ASSERT_OK(sk_assign_lifetime__attach(lifetime), "lifetime_attach")) {
		sk_assign_lifetime__destroy(lifetime);
		return NULL;
	}
	return lifetime;
}

static void wait_for_release(struct sk_assign_lifetime *lifetime, __u64 packets)
{
	int i;

	for (i = 0; i < POLL_RETRIES; i++) {
		if (__atomic_load_n(&lifetime->bss->released_packets,
				    __ATOMIC_ACQUIRE) >= packets)
			break;
		usleep(POLL_INTERVAL_US);
	}
	ASSERT_EQ(lifetime->bss->released_packets, packets, "released_packets");
	ASSERT_EQ(lifetime->bss->release_errors, 0, "release_errors");
}

static void run_netkit_release(int family, bool redirect)
{
	const char *dest = family == AF_INET ? "198.18.0.99" : "2001:db8:99::99";
	const char *bind_addr = family == AF_INET ? "0.0.0.0" : "::";
	struct netns_obj *host = NULL, *pod = NULL;
	struct sk_assign_lifetime *lifetime = NULL;
	struct network_helper_opts client_opts = {
		.timeout_ms = IO_TIMEOUT_MS,
	};
	struct sk_assign_netkit *skel = NULL;
	struct network_helper_opts opts = {
		.timeout_ms = IO_TIMEOUT_MS,
		.post_socket_cb = transparent_socket,
		.cb_opts = &family,
	};
	struct sockaddr_storage expected;
	struct bpf_link *link = NULL;
	int server = -1, client;
	__u64 assigned;
	socklen_t len;

	if (!setup_netkit(family, &host, &pod))
		goto cleanup;
	if (redirect) {
		SYS(cleanup, "ip link add %s type dummy", DUMMY_DEV);
		SYS(cleanup, "ip link set %s up", DUMMY_DEV);
	}
	server = start_server_str(family, SOCK_STREAM, bind_addr, PROXY_PORT, &opts);
	if (!ASSERT_GE(server, 0, "start_server"))
		goto cleanup;
	lifetime = open_release_trace(server);
	if (!lifetime)
		goto cleanup;
	skel = sk_assign_netkit__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;
	skel->rodata->dest_port = DEST_PORT;
	skel->rodata->proxy_port = PROXY_PORT;
	if (redirect) {
		skel->rodata->after_assign = AFTER_ASSIGN_REDIRECT;
		skel->rodata->redirect_ifindex = if_nametoindex(DUMMY_DEV);
	} else {
		skel->rodata->after_assign = AFTER_ASSIGN_DROP;
	}
	if (!ASSERT_OK(sk_assign_netkit__load(skel), "skel_load"))
		goto cleanup;
	link = bpf_program__attach_netkit(skel->progs.assign_socket,
					  if_nametoindex(HOST_DEV), NULL);
	if (!ASSERT_OK_PTR(link, "attach_netkit"))
		goto cleanup;
	if (!ASSERT_OK(make_sockaddr(family, dest, DEST_PORT, &expected, &len),
		       "make_sockaddr"))
		goto cleanup;

	client = connect_pod(&expected, len, &client_opts);
	if (!ASSERT_LT(client, 0, "connect_fails")) {
		close(client);
		goto cleanup;
	}
	if (!ASSERT_OK(bpf_link__detach(link), "detach_netkit") ||
	    !ASSERT_OK(kern_sync_rcu(), "sync_rcu"))
		goto cleanup;
	assigned = skel->bss->listener_assignments;
	ASSERT_GT(assigned, 0, "listener_assignments");
	ASSERT_EQ(skel->bss->assign_errors, 0, "assign_errors");
	wait_for_release(lifetime, assigned);
cleanup:
	bpf_link__destroy(link);
	sk_assign_netkit__destroy(skel);
	sk_assign_lifetime__destroy(lifetime);
	if (server >= 0)
		close(server);
	netns_free(pod);
	netns_free(host);
}

static int reuseport_socket(int fd, void *opts)
{
	int one = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)))
		return -1;
	return transparent_socket(fd, opts);
}

static void run_netkit_reuseport(int family)
{
	const char *dest = family == AF_INET ? "198.18.0.99" : "2001:db8:99::99";
	const char *bind_addr = family == AF_INET ? "0.0.0.0" : "::";
	struct netns_obj *host = NULL, *pod = NULL;
	struct network_helper_opts client_opts = {
		.timeout_ms = IO_TIMEOUT_MS,
	};
	int servers[2] = { -1, -1 }, client = -1;
	struct sk_assign_netkit *skel = NULL;
	struct network_helper_opts opts = {
		.timeout_ms = IO_TIMEOUT_MS,
		.post_socket_cb = reuseport_socket,
		.cb_opts = &family,
	};
	struct sockaddr_storage expected;
	char buf[sizeof(TEST_DATA) - 1];
	struct bpf_link *link = NULL;
	int accepted = -1, prog_fd;
	int ret, err, i;
	__u32 zero = 0;
	socklen_t len;
	__u64 fd_val;

	if (!setup_netkit(family, &host, &pod))
		goto cleanup;
	for (i = 0; i < ARRAY_SIZE(servers); i++) {
		servers[i] = start_server_str(family, SOCK_STREAM, bind_addr,
					      PROXY_PORT, &opts);
		if (!ASSERT_GE(servers[i], 0, "start_server"))
			goto cleanup;
	}
	skel = sk_assign_netkit__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		goto cleanup;
	skel->rodata->dest_port = DEST_PORT;
	skel->rodata->proxy_port = PROXY_PORT;
	skel->rodata->use_proxy_map = true;
	if (!ASSERT_OK(sk_assign_netkit__load(skel), "skel_load"))
		goto cleanup;
	fd_val = servers[0];
	if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.proxy_map),
					   &zero, &fd_val, BPF_NOEXIST),
		       "proxy_map_update"))
		goto cleanup;
	for (i = 0; i < ARRAY_SIZE(servers); i++) {
		fd_val = servers[i];
		if (!ASSERT_OK(bpf_map_update_elem(bpf_map__fd(skel->maps.reuse_map),
						   &i, &fd_val, BPF_NOEXIST),
			       "reuse_map_update"))
			goto cleanup;
	}
	prog_fd = bpf_program__fd(skel->progs.select_second);
	if (!ASSERT_OK(setsockopt(servers[0], SOL_SOCKET,
				  SO_ATTACH_REUSEPORT_EBPF, &prog_fd,
				  sizeof(prog_fd)), "attach_reuseport"))
		goto cleanup;
	link = bpf_program__attach_netkit(skel->progs.assign_socket,
					  if_nametoindex(HOST_DEV), NULL);
	if (!ASSERT_OK_PTR(link, "attach_netkit"))
		goto cleanup;
	if (!ASSERT_OK(make_sockaddr(family, dest, DEST_PORT, &expected, &len),
		       "make_sockaddr"))
		goto cleanup;

	client = connect_pod(&expected, len, &client_opts);
	if (!ASSERT_GE(client, 0, "connect_client"))
		goto cleanup;
	accepted = accept(servers[1], NULL, NULL);
	if (!ASSERT_GE(accepted, 0, "accept_selected"))
		goto cleanup;
	if (!ASSERT_OK(settimeo(accepted, IO_TIMEOUT_MS), "accepted_timeout") ||
	    !ASSERT_EQ(send(client, TEST_DATA, sizeof(buf), 0), sizeof(buf),
		       "send_client") ||
	    !ASSERT_EQ(recv(accepted, buf, sizeof(buf), MSG_WAITALL),
		       sizeof(buf), "recv_server") ||
	    !ASSERT_MEMEQ(buf, TEST_DATA, sizeof(buf), "server_data"))
		goto cleanup;
	if (!ASSERT_OK(fcntl(servers[0], F_SETFL, O_NONBLOCK), "nonblock"))
		goto cleanup;
	ret = accept(servers[0], NULL, NULL);
	err = errno;
	if (ret >= 0)
		close(ret);
	ASSERT_EQ(ret, -1, "assigned_listener_idle");
	ASSERT_EQ(err, EAGAIN, "assigned_listener_eagain");
	if (!ASSERT_OK(bpf_link__detach(link), "detach_netkit"))
		goto cleanup;
	ASSERT_GT(skel->bss->listener_assignments, 0, "listener_assignments");
	ASSERT_EQ(skel->bss->assign_errors, 0, "assign_errors");
	ASSERT_GT(skel->bss->reuse_calls, 0, "reuse_calls");
	ASSERT_EQ(skel->bss->reuse_errors, 0, "reuse_errors");
cleanup:
	bpf_link__destroy(link);
	if (accepted >= 0)
		close(accepted);
	if (client >= 0)
		close(client);
	for (i = 0; i < ARRAY_SIZE(servers); i++) {
		if (servers[i] >= 0)
			close(servers[i]);
	}
	sk_assign_netkit__destroy(skel);
	netns_free(pod);
	netns_free(host);
}

void test_sk_assign_netkit(void)
{
	if (test__start_subtest("tcpv4"))
		run_netkit(AF_INET, false, false);
	if (test__start_subtest("tcpv6"))
		run_netkit(AF_INET6, false, false);
	if (test__start_subtest("tcpv4_nfqueue"))
		run_netkit(AF_INET, true, false);
	if (test__start_subtest("tcpv6_nfqueue"))
		run_netkit(AF_INET6, true, false);
	if (test__start_subtest("tcpv4_nfqueue_retransmit"))
		run_netkit(AF_INET, true, true);
	if (test__start_subtest("tcpv6_nfqueue_retransmit"))
		run_netkit(AF_INET6, true, true);
	if (test__start_subtest("tcpv4_drop"))
		run_netkit_release(AF_INET, false);
	if (test__start_subtest("tcpv6_drop"))
		run_netkit_release(AF_INET6, false);
	if (test__start_subtest("tcpv4_redirect"))
		run_netkit_release(AF_INET, true);
	if (test__start_subtest("tcpv6_redirect"))
		run_netkit_release(AF_INET6, true);
	if (test__start_subtest("tcpv4_reuseport"))
		run_netkit_reuseport(AF_INET);
	if (test__start_subtest("tcpv6_reuseport"))
		run_netkit_reuseport(AF_INET6);
}
