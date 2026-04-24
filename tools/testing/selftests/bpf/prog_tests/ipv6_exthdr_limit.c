// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2026 Isovalent */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <test_progs.h>
#include <network_helpers.h>

#include "ipv6_exthdr_limit.skel.h"

#define VETH_A		"veth_ehl_a"
#define VETH_B		"veth_ehl_b"
#define ADDR_A		"fd0e:0:1::1"
#define ADDR_B		"fd0e:0:1::2"
#define ADDR_C		"fd0e:0:1::99"
#define PORT		7070
#define SYSCTL		"/proc/sys/net/ipv6/max_ext_hdrs_number"
#define LIMIT_STR	"7"
#define LIMIT_VAL	7

/* RFC 8200 Destination Options: minimum-sized (8 bytes) containing one PadN. */
struct dopt_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__u8 options[6];
} __packed;

static const __u8 payload[16] = "bpf-eh-limit-tst";

static int iface_mac(const char *name, __u8 mac[ETH_ALEN])
{
	struct ifreq ifr = {};
	int fd, err;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0)
		return -errno;
	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
	err = ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);
	if (err < 0)
		return -errno;
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	return 0;
}

static int build_eh_udp_pkt(__u8 *buf, size_t buf_sz, int n_eh,
			    const __u8 *src_mac, const __u8 *dst_mac,
			    const struct in6_addr *src_ip,
			    const struct in6_addr *dst_ip,
			    __u16 sport, __u16 dport)
{
	size_t payload_len = sizeof(payload);
	struct ipv6hdr *ip6;
	struct dopt_hdr *dopt;
	struct ethhdr *eth;
	struct udphdr *udp;
	size_t total;
	int i;

	total = sizeof(*eth) + sizeof(*ip6) + (size_t)n_eh * sizeof(*dopt) +
		sizeof(*udp) + payload_len;
	if (total > buf_sz)
		return -EINVAL;

	eth = (void *)buf;
	ip6 = (void *)(eth + 1);
	dopt = (void *)(ip6 + 1);

	memcpy(eth->h_dest, dst_mac, ETH_ALEN);
	memcpy(eth->h_source, src_mac, ETH_ALEN);
	eth->h_proto = htons(ETH_P_IPV6);

	memset(ip6, 0, sizeof(*ip6));
	ip6->version = 6;
	ip6->payload_len = htons(n_eh * sizeof(*dopt) +
				 sizeof(*udp) + payload_len);
	ip6->nexthdr = n_eh > 0 ? IPPROTO_DSTOPTS : IPPROTO_UDP;
	ip6->hop_limit = 64;
	ip6->saddr = *src_ip;
	ip6->daddr = *dst_ip;

	for (i = 0; i < n_eh; i++) {
		dopt[i].nexthdr = (i == n_eh - 1) ? IPPROTO_UDP : IPPROTO_DSTOPTS;
		dopt[i].hdrlen = 0;
		/* PadN: type=1, opt data len=4, 4 zero bytes */
		dopt[i].options[0] = 0x01;
		dopt[i].options[1] = 0x04;
		memset(&dopt[i].options[2], 0, 4);
	}

	udp = (void *)(dopt + n_eh);
	udp->source = htons(sport);
	udp->dest = htons(dport);
	udp->len = htons(sizeof(*udp) + payload_len);
	udp->check = 0;
	memcpy(udp + 1, payload, payload_len);
	udp->check = build_udp_v6_csum(ip6, udp);
	if (!udp->check)
		udp->check = 0xffff;

	return total;
}

static int send_crafted(int n_eh)
{
	__u8 buf[256], src_mac[ETH_ALEN], dst_mac[ETH_ALEN];
	struct in6_addr src_ip, dst_ip;
	struct sockaddr_ll sll = {};
	int sk, ifindex, len, rc;

	ifindex = if_nametoindex(VETH_B);
	if (!ifindex)
		return -errno;
	if (iface_mac(VETH_B, src_mac) || iface_mac(VETH_A, dst_mac))
		return -1;
	if (inet_pton(AF_INET6, ADDR_C, &src_ip) != 1 ||
	    inet_pton(AF_INET6, ADDR_A, &dst_ip) != 1)
		return -1;

	len = build_eh_udp_pkt(buf, sizeof(buf), n_eh, src_mac, dst_mac,
			       &src_ip, &dst_ip, 40000, PORT);
	if (len < 0)
		return len;

	sk = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
	if (sk < 0)
		return -errno;

	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IPV6);
	sll.sll_ifindex = ifindex;
	sll.sll_halen = ETH_ALEN;
	memcpy(sll.sll_addr, dst_mac, ETH_ALEN);

	rc = sendto(sk, buf, len, 0, (struct sockaddr *)&sll, sizeof(sll));
	close(sk);
	return rc == len ? 0 : -1;
}

static int save_sysctl(const char *path, char *buf, size_t buf_sz)
{
	ssize_t n;
	char *nl;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, buf_sz - 1);
	close(fd);
	if (n <= 0)
		return -EIO;
	buf[n] = '\0';
	nl = strchr(buf, '\n');
	if (nl)
		*nl = '\0';
	return 0;
}

void serial_test_ipv6_exthdr_limit(void)
{
	struct ipv6_exthdr_limit *skel = NULL;
	char saved_limit[32] = "";
	struct sockaddr_in6 srv = {}, cli = {};
	int srv_fd = -1, cli_fd = -1;
	char rbuf[128];
	__u64 pre_deliver;
	ssize_t n;

	if (!ASSERT_OK(save_sysctl(SYSCTL, saved_limit, sizeof(saved_limit)),
		       "save sysctl"))
		return;
	if (!ASSERT_OK(write_sysctl(SYSCTL, LIMIT_STR), "set sysctl"))
		return;

	SYS(cleanup, "ip link add %s type veth peer name %s", VETH_A, VETH_B);
	SYS(cleanup, "ip addr add %s/64 dev %s nodad", ADDR_A, VETH_A);
	SYS(cleanup, "ip addr add %s/64 dev %s nodad", ADDR_B, VETH_B);
	SYS(cleanup, "ip link set %s up", VETH_A);
	SYS(cleanup, "ip link set %s up", VETH_B);

	skel = ipv6_exthdr_limit__open_and_load();
	if (!ASSERT_OK_PTR(skel, "skel open/load"))
		goto cleanup;
	if (!ASSERT_OK(ipv6_exthdr_limit__attach(skel), "skel attach"))
		goto cleanup;

	/* Step 1: regular IPv6 UDP client/server. Verifies IPv6 connectivity
	 * works and exercises ip6_protocol_deliver_rcu on the receive path.
	 */
	srv_fd = start_server(AF_INET6, SOCK_DGRAM, ADDR_A, PORT, 500);
	if (!ASSERT_OK_FD(srv_fd, "udp server"))
		goto cleanup;

	cli_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (!ASSERT_OK_FD(cli_fd, "udp client"))
		goto cleanup;
	cli.sin6_family = AF_INET6;
	inet_pton(AF_INET6, ADDR_B, &cli.sin6_addr);
	if (!ASSERT_OK(bind(cli_fd, (struct sockaddr *)&cli, sizeof(cli)),
		       "bind client"))
		goto cleanup;

	srv.sin6_family = AF_INET6;
	srv.sin6_port = htons(PORT);
	inet_pton(AF_INET6, ADDR_A, &srv.sin6_addr);

	pre_deliver = skel->bss->deliver_rcu_count;
	n = sendto(cli_fd, payload, sizeof(payload), 0,
		   (struct sockaddr *)&srv, sizeof(srv));
	if (!ASSERT_EQ(n, sizeof(payload), "udp sendto"))
		goto cleanup;

	n = recv(srv_fd, rbuf, sizeof(rbuf), 0);
	ASSERT_EQ(n, sizeof(payload), "udp server recv");
	ASSERT_GT(skel->bss->deliver_rcu_count, pre_deliver,
		  "ip6_protocol_deliver_rcu reached");

	/* Step 2: LIMIT_VAL extension headers, at the limit - must be
	 * delivered, no drop.
	 */
	if (!ASSERT_EQ(skel->bss->drop_count, 0, "baseline drop_count"))
		goto cleanup;
	if (!ASSERT_OK(send_crafted(LIMIT_VAL), "send at-limit packet"))
		goto cleanup;
	n = recv(srv_fd, rbuf, sizeof(rbuf), 0);
	ASSERT_EQ(n, sizeof(payload), "server recv at-limit");
	ASSERT_EQ(skel->bss->drop_count, 0, "no drop at limit");

	/* Step 3: LIMIT_VAL+1 extension headers - exceeds limit, must be
	 * dropped with SKB_DROP_REASON_IPV6_TOO_MANY_EXTHDRS.
	 */
	if (!ASSERT_OK(send_crafted(LIMIT_VAL + 1), "send over-limit packet"))
		goto cleanup;
	usleep(100000);
	ASSERT_EQ(skel->bss->drop_count, 1, "drop over limit");
	n = recv(srv_fd, rbuf, sizeof(rbuf), MSG_DONTWAIT);
	ASSERT_LT(n, 0, "server did not receive over-limit packet");

cleanup:
	if (cli_fd >= 0)
		close(cli_fd);
	if (srv_fd >= 0)
		close(srv_fd);
	ipv6_exthdr_limit__destroy(skel);
	SYS_NOFAIL("ip link del %s", VETH_A);
	if (saved_limit[0])
		write_sysctl(SYSCTL, saved_limit);
}
