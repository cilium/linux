// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ynl.h>
#include <net/if.h>

#include "netdev-user.h"

int main(int argc, char **argv)
{
	struct netdev_bind_queue_req *req;
	struct netdev_bind_queue_rsp *rsp;
	char if_src[IF_NAMESIZE] = {};
	char if_dst[IF_NAMESIZE] = {};
	struct ynl_sock *ys;
	struct ynl_error yerr;
	int src_ifindex = 0, dst_ifindex = 0;
	int src_queue_id = 0;

	if (argc > 1)
		src_ifindex = if_nametoindex(argv[1]);
	if (argc > 2)
		src_queue_id = strtol(argv[2], NULL, 0);
	if (argc > 3)
		dst_ifindex = if_nametoindex(argv[3]);

	ys = ynl_sock_create(&ynl_netdev_family, &yerr);
	if (!ys) {
		fprintf(stderr, "YNL: %s\n", yerr.msg);
		return 1;
	}

	req = netdev_bind_queue_req_alloc();
	netdev_bind_queue_req_set_src_ifindex(req, src_ifindex);
	netdev_bind_queue_req_set_src_queue_id(req, src_queue_id);
	netdev_bind_queue_req_set_dst_ifindex(req, dst_ifindex);

	rsp = netdev_bind_queue(ys, req);
	netdev_bind_queue_req_free(req);
	if (!rsp)
		goto err;

	assert(rsp->_present.dst_queue_id);
	printf("bound %s, queue %d to %s, queue %d\n",
	       if_indextoname(src_ifindex, if_src), src_queue_id,
	       if_indextoname(dst_ifindex, if_dst), rsp->dst_queue_id);

	netdev_bind_queue_rsp_free(rsp);
	ynl_sock_destroy(ys);
	return 0;
err:
	fprintf(stderr, "YNL: %s\n", ys->err.msg);
	ynl_sock_destroy(ys);
	return 2;
}
