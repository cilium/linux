// SPDX-License-Identifier: GPL-2.0
/* AF_XDP zerocopy echo helper for netkit-leased RX queues.
 *
 * Server mode (-s): creates an AF_XDP socket inside the netns of the
 * (single-mode) netkit device and binds it in zerocopy mode to the
 * given leased netkit RX queue. The XSK buffer pool registration and
 * the XDP_SETUP_XSK_POOL driver setup are redirected by the kernel
 * onto the physical RX queue behind the lease, and TX wakeups are
 * forwarded through netkit's ndo_xsk_wakeup.
 *
 * Steering happens on the physical device: a minimal hand-assembled
 * XDP program performing bpf_redirect_map(xskmap, rx_queue_index,
 * XDP_PASS) is attached in native mode through a BPF link (auto-
 * detached when the helper exits), with the socket inserted at the
 * physical queue index. Received UDPv6 frames matching the test port
 * are echoed back out through the physical queue's zerocopy TX path
 * with Ethernet/IPv6 addresses and UDP ports swapped, which keeps the
 * UDP checksum valid.
 *
 * Exits with SKIP_CODE when the zerocopy bind is not supported, e.g.
 * when the physical driver behind the lease has no XSK support.
 *
 * Client mode (-c): plain UDPv6 ping/pong against the echo server.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))

#define SKIP_CODE	42

#define NUM_DESC	256
#define DESC_MASK	(NUM_DESC - 1)
#define FRAME_SIZE	2048
#define NUM_FRAMES	NUM_DESC
#define UMEM_SIZE	(NUM_FRAMES * FRAME_SIZE)
#define FRAME_MASK	(~((__u64)FRAME_SIZE - 1))
/* Drivers like virtio-net require umem headroom covering their virtio
 * net header for the zerocopy pool bind.
 */
#define UMEM_HEADROOM	64

#define CLIENT_PAYLOAD	512
#define CLIENT_RETRIES	10

static bool cfg_server;
static bool cfg_client;
static bool cfg_dry_run;
static const char *cfg_netns_path;
static const char *cfg_nk_ifname;
static unsigned int cfg_nk_queue;
static const char *cfg_phys_ifname;
static unsigned int cfg_phys_queue;
static const char *cfg_host;
static unsigned int cfg_port;

struct xsk_ring {
	__u32 *producer;
	__u32 *consumer;
	void *desc;
};

static struct xsk_ring fq, cq, rxr, txr;
static void *umem_area;
static int xsk_fd;

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static void ksft_ready(void)
{
	const char *env = getenv("KSFT_READY_FD");
	char byte = 'R';
	int fd;

	if (!env)
		return;
	fd = atoi(env);
	if (write(fd, &byte, 1) != 1)
		error(1, errno, "ksft ready write");
	close(fd);
}

static int ksft_wait_fd(void)
{
	const char *env = getenv("KSFT_WAIT_FD");

	return env ? atoi(env) : -1;
}

static void ring_mmap(struct xsk_ring *r, off_t pgoff,
		      const struct xdp_ring_offset *off, size_t desc_sz)
{
	void *map;

	map = mmap(NULL, off->desc + NUM_DESC * desc_sz,
		   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
		   xsk_fd, pgoff);
	if (map == MAP_FAILED)
		error(1, errno, "mmap xsk ring");

	r->producer = map + off->producer;
	r->consumer = map + off->consumer;
	r->desc = map + off->desc;
}

static void xsk_setopt(int opt, int val)
{
	if (setsockopt(xsk_fd, SOL_XDP, opt, &val, sizeof(val)))
		error(1, errno, "setsockopt(SOL_XDP, %d)", opt);
}

static void xsk_setup(unsigned int ifindex)
{
	struct xdp_mmap_offsets off;
	struct xdp_umem_reg ureg = {};
	struct sockaddr_xdp sxdp = {};
	socklen_t optlen = sizeof(off);
	__u32 i;

	xsk_fd = socket(AF_XDP, SOCK_RAW, 0);
	if (xsk_fd < 0)
		error(1, errno, "socket(AF_XDP)");

	umem_area = mmap(NULL, UMEM_SIZE, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (umem_area == MAP_FAILED)
		error(1, errno, "mmap umem");

	ureg.addr = (__u64)(unsigned long)umem_area;
	ureg.len = UMEM_SIZE;
	ureg.chunk_size = FRAME_SIZE;
	ureg.headroom = UMEM_HEADROOM;

	if (setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_REG, &ureg, sizeof(ureg)))
		error(1, errno, "setsockopt(XDP_UMEM_REG)");

	xsk_setopt(XDP_UMEM_FILL_RING, NUM_DESC);
	xsk_setopt(XDP_UMEM_COMPLETION_RING, NUM_DESC);
	xsk_setopt(XDP_RX_RING, NUM_DESC);
	xsk_setopt(XDP_TX_RING, NUM_DESC);

	if (getsockopt(xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen))
		error(1, errno, "getsockopt(XDP_MMAP_OFFSETS)");

	ring_mmap(&fq, XDP_UMEM_PGOFF_FILL_RING, &off.fr, sizeof(__u64));
	ring_mmap(&cq, XDP_UMEM_PGOFF_COMPLETION_RING, &off.cr, sizeof(__u64));
	ring_mmap(&rxr, XDP_PGOFF_RX_RING, &off.rx, sizeof(struct xdp_desc));
	ring_mmap(&txr, XDP_PGOFF_TX_RING, &off.tx, sizeof(struct xdp_desc));

	for (i = 0; i < NUM_DESC / 2; i++)
		((__u64 *)fq.desc)[i] = (__u64)i * FRAME_SIZE;
	__atomic_store_n(fq.producer, NUM_DESC / 2, __ATOMIC_RELEASE);

	sxdp.sxdp_family = AF_XDP;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = cfg_nk_queue;
	sxdp.sxdp_flags = XDP_ZEROCOPY;

	if (bind(xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp))) {
		if (errno == EOPNOTSUPP) {
			printf("AF_XDP zerocopy not supported %i\n", -errno);
			exit(SKIP_CODE);
		}
		error(1, errno, "bind(AF_XDP, queue %u)", cfg_nk_queue);
	}
}

static int xskmap_setup(void)
{
	union bpf_attr attr = {};
	__u32 key = cfg_phys_queue;
	__u32 val = xsk_fd;
	int map_fd;

	attr.map_type = BPF_MAP_TYPE_XSKMAP;
	attr.key_size = sizeof(__u32);
	attr.value_size = sizeof(__u32);
	attr.max_entries = cfg_phys_queue + 1;

	map_fd = sys_bpf(BPF_MAP_CREATE, &attr);
	if (map_fd < 0)
		error(1, errno, "bpf(BPF_MAP_CREATE)");

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (__u64)(unsigned long)&key;
	attr.value = (__u64)(unsigned long)&val;

	if (sys_bpf(BPF_MAP_UPDATE_ELEM, &attr))
		error(1, errno, "bpf(BPF_MAP_UPDATE_ELEM)");
	return map_fd;
}

static int xdp_redir_setup(int map_fd, unsigned int ifindex)
{
	/* return bpf_redirect_map(xskmap, ctx->rx_queue_index, XDP_PASS); */
	const struct bpf_insn insns[] = {
		{ .code = BPF_LDX | BPF_MEM | BPF_W,
		  .dst_reg = BPF_REG_2, .src_reg = BPF_REG_1,
		  .off = offsetof(struct xdp_md, rx_queue_index) },
		{ .code = BPF_LD | BPF_DW | BPF_IMM,
		  .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD,
		  .imm = map_fd },
		{ 0 },
		{ .code = BPF_ALU64 | BPF_MOV | BPF_K,
		  .dst_reg = BPF_REG_3, .imm = XDP_PASS },
		{ .code = BPF_JMP | BPF_CALL,
		  .imm = BPF_FUNC_redirect_map },
		{ .code = BPF_JMP | BPF_EXIT },
	};
	static char log_buf[16384];
	union bpf_attr attr = {};
	int prog_fd, link_fd;

	attr.prog_type = BPF_PROG_TYPE_XDP;
	attr.insns = (__u64)(unsigned long)insns;
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.license = (__u64)(unsigned long)"GPL";
	attr.log_buf = (__u64)(unsigned long)log_buf;
	attr.log_size = sizeof(log_buf);
	attr.log_level = 1;

	prog_fd = sys_bpf(BPF_PROG_LOAD, &attr);
	if (prog_fd < 0)
		error(1, errno, "bpf(BPF_PROG_LOAD): %s", log_buf);

	/* Native mode, as required for zerocopy delivery. The link is
	 * dropped on process exit which detaches the program.
	 */
	memset(&attr, 0, sizeof(attr));
	attr.link_create.prog_fd = prog_fd;
	attr.link_create.target_ifindex = ifindex;
	attr.link_create.attach_type = BPF_XDP;
	attr.link_create.flags = XDP_FLAGS_DRV_MODE;

	link_fd = sys_bpf(BPF_LINK_CREATE, &attr);
	if (link_fd < 0)
		error(1, errno, "bpf(BPF_LINK_CREATE)");
	return link_fd;
}

static bool frame_echo(void *pkt, __u32 len)
{
	struct ethhdr *eth = pkt;
	struct ipv6hdr *ip6 = (struct ipv6hdr *)(eth + 1);
	struct udphdr *udp = (struct udphdr *)(ip6 + 1);
	struct in6_addr addr;
	__u8 mac[ETH_ALEN];
	__u16 port;

	if (len < sizeof(*eth) + sizeof(*ip6) + sizeof(*udp))
		return false;
	if (eth->h_proto != htons(ETH_P_IPV6))
		return false;
	if (ip6->nexthdr != IPPROTO_UDP)
		return false;
	if (udp->dest != htons(cfg_port))
		return false;

	/* The echo leaves through the physical queue's zerocopy TX
	 * path, so plain swaps suffice; swapping addresses and ports
	 * also keeps the UDP checksum valid.
	 */
	memcpy(mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, mac, ETH_ALEN);

	addr = ip6->saddr;
	ip6->saddr = ip6->daddr;
	ip6->daddr = addr;
	ip6->hop_limit = 64;

	port = udp->source;
	udp->source = udp->dest;
	udp->dest = port;
	return true;
}

static void fq_recycle(__u64 addr)
{
	__u32 prod = __atomic_load_n(fq.producer, __ATOMIC_RELAXED);

	((__u64 *)fq.desc)[prod & DESC_MASK] = addr & FRAME_MASK;
	__atomic_store_n(fq.producer, prod + 1, __ATOMIC_RELEASE);
}

static void run_server(void)
{
	unsigned int stat_rx = 0, stat_echo = 0, stat_last = 0;
	struct pollfd pfd[2] = {};
	__u32 cons, prod;
	bool kick;

	pfd[0].fd = xsk_fd;
	pfd[0].events = POLLIN;
	pfd[1].fd = ksft_wait_fd();
	pfd[1].events = POLLIN;

	ksft_ready();

	for (;;) {
		if (poll(pfd, pfd[1].fd >= 0 ? 2 : 1, 1000) < 0)
			error(1, errno, "poll()");
		if (pfd[1].fd >= 0 && (pfd[1].revents & POLLIN))
			break;

		kick = false;
		cons = __atomic_load_n(rxr.consumer, __ATOMIC_RELAXED);
		prod = __atomic_load_n(rxr.producer, __ATOMIC_ACQUIRE);
		while (cons != prod) {
			struct xdp_desc *desc =
				&((struct xdp_desc *)rxr.desc)[cons & DESC_MASK];
			char *pkt = (char *)umem_area + desc->addr;

			stat_rx++;
			if (frame_echo(pkt, desc->len)) {
				__u32 tx_prod =
					__atomic_load_n(txr.producer,
							__ATOMIC_RELAXED);

				((struct xdp_desc *)txr.desc)[tx_prod & DESC_MASK] = *desc;
				__atomic_store_n(txr.producer, tx_prod + 1,
						 __ATOMIC_RELEASE);
				kick = true;
				stat_echo++;
			} else {
				fq_recycle(desc->addr);
			}
			cons++;
		}
		__atomic_store_n(rxr.consumer, cons, __ATOMIC_RELEASE);

		if (kick &&
		    sendto(xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0 &&
		    errno != EAGAIN && errno != EBUSY)
			error(1, errno, "sendto(AF_XDP)");

		cons = __atomic_load_n(cq.consumer, __ATOMIC_RELAXED);
		prod = __atomic_load_n(cq.producer, __ATOMIC_ACQUIRE);
		while (cons != prod) {
			fq_recycle(((__u64 *)cq.desc)[cons & DESC_MASK]);
			cons++;
		}
		__atomic_store_n(cq.consumer, cons, __ATOMIC_RELEASE);

		if (stat_rx + stat_echo != stat_last) {
			stat_last = stat_rx + stat_echo;
			fprintf(stderr, "stats: rx=%u echo=%u\n",
				stat_rx, stat_echo);
		}
	}
}

static void run_client(void)
{
	struct sockaddr_in6 dst = {};
	struct timeval tv = { .tv_sec = 1 };
	char out[CLIENT_PAYLOAD];
	char in[FRAME_SIZE];
	ssize_t n = -1;
	int fd, i;

	dst.sin6_family = AF_INET6;
	dst.sin6_port = htons(cfg_port);
	if (inet_pton(AF_INET6, cfg_host, &dst.sin6_addr) != 1)
		error(1, 0, "bad address: %s", cfg_host);

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0)
		error(1, errno, "socket(AF_INET6)");
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)))
		error(1, errno, "setsockopt(SO_RCVTIMEO)");

	memset(out, 'q', sizeof(out));
	for (i = 0; i < CLIENT_RETRIES; i++) {
		if (sendto(fd, out, sizeof(out), 0,
			   (struct sockaddr *)&dst, sizeof(dst)) < 0)
			error(1, errno, "sendto()");
		n = recv(fd, in, sizeof(in), 0);
		if (n >= 0)
			break;
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			error(1, errno, "recv()");
	}
	if (n < 0)
		error(1, 0, "no echo reply after %d attempts", CLIENT_RETRIES);
	if (n != sizeof(out) || memcmp(in, out, sizeof(out)))
		error(1, 0, "echo payload mismatch");
	close(fd);
}

static void usage(const char *filepath)
{
	error(1, 0,
	      "Usage: %s (-s|-c) -p<port>\n"
	      "\t-s: -N<netns_path> -i<nk_ifname> -q<nk_queue>\n"
	      "\t    -I<phys_ifname> -Q<phys_queue> [-d]\n"
	      "\t-c: -h<server_ip>\n",
	      filepath);
}

static void parse_opts(int argc, char **argv)
{
	int c;

	while ((c = getopt(argc, argv, "scdN:i:q:I:Q:h:p:")) != -1) {
		switch (c) {
		case 's':
			cfg_server = true;
			break;
		case 'c':
			cfg_client = true;
			break;
		case 'd':
			cfg_dry_run = true;
			break;
		case 'N':
			cfg_netns_path = optarg;
			break;
		case 'i':
			cfg_nk_ifname = optarg;
			break;
		case 'q':
			cfg_nk_queue = strtoul(optarg, NULL, 0);
			break;
		case 'I':
			cfg_phys_ifname = optarg;
			break;
		case 'Q':
			cfg_phys_queue = strtoul(optarg, NULL, 0);
			break;
		case 'h':
			cfg_host = optarg;
			break;
		case 'p':
			cfg_port = strtoul(optarg, NULL, 0);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (cfg_server == cfg_client || !cfg_port)
		usage(argv[0]);
	if (cfg_server &&
	    (!cfg_netns_path || !cfg_nk_ifname || !cfg_phys_ifname))
		usage(argv[0]);
	if (cfg_client && !cfg_host)
		usage(argv[0]);
}

int main(int argc, char **argv)
{
	unsigned int nk_ifindex, phys_ifindex;
	int init_ns, target_ns;

	parse_opts(argc, argv);

	if (cfg_client) {
		run_client();
		return 0;
	}

	init_ns = open("/proc/self/ns/net", O_RDONLY);
	if (init_ns < 0)
		error(1, errno, "open(/proc/self/ns/net)");
	target_ns = open(cfg_netns_path, O_RDONLY);
	if (target_ns < 0)
		error(1, errno, "open(%s)", cfg_netns_path);

	/* The XDP socket lives in the netns of the netkit device, the
	 * steering program on the physical device in the initial netns.
	 */
	if (setns(target_ns, CLONE_NEWNET))
		error(1, errno, "setns(%s)", cfg_netns_path);

	nk_ifindex = if_nametoindex(cfg_nk_ifname);
	if (!nk_ifindex)
		error(1, 0, "bad interface name: %s", cfg_nk_ifname);
	xsk_setup(nk_ifindex);

	if (setns(init_ns, CLONE_NEWNET))
		error(1, errno, "setns(init)");

	phys_ifindex = if_nametoindex(cfg_phys_ifname);
	if (!phys_ifindex)
		error(1, 0, "bad interface name: %s", cfg_phys_ifname);
	xdp_redir_setup(xskmap_setup(), phys_ifindex);

	if (cfg_dry_run)
		return 0;

	run_server();
	return 0;
}
