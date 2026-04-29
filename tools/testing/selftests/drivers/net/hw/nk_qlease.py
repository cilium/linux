#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0

import re
import time
import threading
from os import path
from lib.py import (
    ksft_run,
    ksft_exit,
    ksft_eq,
    ksft_in,
    ksft_not_in,
    ksft_raises,
)
from lib.py import (
    NetDrvContEnv,
    NetNSEnter,
    EthtoolFamily,
    NetdevFamily,
    RtnlFamily,
)
from lib.py import (
    Netlink,
    bkg,
    bpftrace,
    cmd,
    defer,
    ethtool,
    ip,
    rand_port,
    wait_port_listen,
)
from lib.py import KsftFailEx, KsftSkipEx, CmdExitFailure

# iou-zcrx exits with 42 from setup_zcrx() when the NIC does not advertise
# QCFG_RX_PAGE_SIZE (or otherwise rejects the requested rx_buf_len).
SKIP_CODE = 42

# 192 KiB; well above the 64 KiB jumbogram threshold, used as the gso/gro
# max-size cap when the BIG-TCP test overrides the leased phys netdev.
_BIG_TCP_SIZE = 196608


def _restore_hugepages(count):
    with open("/proc/sys/vm/nr_hugepages", "w", encoding="utf-8") as f:
        f.write(str(count))


def _bigtcp_set(ifname, size, host=None):
    try:
        info = ip(f"-d -j link show dev {ifname}", json=True, host=host)[0]
    except Exception as e:
        raise KsftSkipEx(
            f"cannot query link info for {ifname}: {e}"
        ) from e
    old = {
        "gro_max_size": info.get("gro_max_size", 65536),
        "gso_max_size": info.get("gso_max_size", 65536),
        "gro_ipv4_max_size": info.get("gro_ipv4_max_size", 65536),
        "gso_ipv4_max_size": info.get("gso_ipv4_max_size", 65536),
    }
    try:
        ip(
            f"link set dev {ifname} "
            f"gso_max_size {size} gro_max_size {size} "
            f"gso_ipv4_max_size {size} gro_ipv4_max_size {size}",
            host=host,
        )
    except CmdExitFailure as e:
        raise KsftSkipEx(
            f"BIG TCP knobs not supported on {ifname}: {e}"
        ) from e
    return old


def _bigtcp_restore(ifname, old, host=None):
    ip(
        f"link set dev {ifname} "
        f"gso_max_size {old['gso_max_size']} "
        f"gro_max_size {old['gro_max_size']} "
        f"gso_ipv4_max_size {old['gso_ipv4_max_size']} "
        f"gro_ipv4_max_size {old['gro_ipv4_max_size']}",
        host=host,
    )


def _create_netkit_pair(cfg, rxqueues=2):
    if cfg._nk_host_ifname:
        cmd(f"ip link del dev {cfg._nk_host_ifname}", fail=False)
        cfg._nk_host_ifname = None
        cfg._nk_guest_ifname = None
    if getattr(cfg, "_tc_attached", False):
        cmd(
            f"tc filter del dev {cfg.ifname} ingress pref {cfg._bpf_prog_pref}",
            fail=False,
        )
        cfg._tc_attached = False

    all_links = ip("-d link show", json=True)
    old_idxs = {
        link["ifindex"]
        for link in all_links
        if link.get("linkinfo", {}).get("info_kind") == "netkit"
    }

    rtnl = RtnlFamily()
    rtnl.newlink(
        {
            "linkinfo": {
                "kind": "netkit",
                "data": {
                    "mode": "l2",
                    "policy": "forward",
                    "peer-policy": "forward",
                },
            },
            "num-rx-queues": rxqueues,
        },
        flags=[Netlink.NLM_F_CREATE, Netlink.NLM_F_EXCL],
    )

    all_links = ip("-d link show", json=True)
    nk_links = [
        link
        for link in all_links
        if link.get("linkinfo", {}).get("info_kind") == "netkit"
        and link["ifindex"] not in old_idxs
    ]
    if len(nk_links) != 2:
        raise KsftSkipEx("Failed to create netkit pair")

    nk_links.sort(key=lambda x: x["ifindex"])
    cfg._nk_host_ifname = nk_links[1]["ifname"]
    cfg._nk_guest_ifname = nk_links[0]["ifname"]
    cfg.nk_host_ifindex = nk_links[1]["ifindex"]
    cfg.nk_guest_ifindex = nk_links[0]["ifindex"]

    ip(f"link set dev {cfg._nk_guest_ifname} netns {cfg.netns.name}")
    ip(f"link set dev {cfg._nk_host_ifname} up")
    ip(f"-6 addr add fe80::1/64 dev {cfg._nk_host_ifname} nodad")
    ip(
        f"-6 route add {cfg.nk_guest_ipv6}/128 via fe80::2 "
        f"dev {cfg._nk_host_ifname}"
    )
    ip(f"link set dev {cfg._nk_guest_ifname} up", ns=cfg.netns)
    ip(f"-6 addr add fe80::2/64 dev {cfg._nk_guest_ifname}", ns=cfg.netns)
    ip(
        f"-6 addr add {cfg.nk_guest_ipv6}/64 dev {cfg._nk_guest_ifname} nodad",
        ns=cfg.netns,
    )
    ip(
        f"-6 route add default via fe80::1 dev {cfg._nk_guest_ifname}",
        ns=cfg.netns,
    )

    cfg._attach_bpf()


def _setup_lease(cfg, rxqueues=2):
    _create_netkit_pair(cfg, rxqueues=rxqueues)

    ethnl = EthtoolFamily()
    channels = ethnl.channels_get({"header": {"dev-index": cfg.ifindex}})[
        "combined-count"
    ]
    if channels < 2:
        raise KsftSkipEx(
            "Test requires NETIF with at least 2 combined channels"
        )
    src_queue = channels - 1

    with NetNSEnter(str(cfg.netns)):
        netdevnl = NetdevFamily()
        bind_result = netdevnl.queue_create(
            {
                "ifindex": cfg.nk_guest_ifindex,
                "type": "rx",
                "lease": {
                    "ifindex": cfg.ifindex,
                    "queue": {"id": src_queue, "type": "rx"},
                    "netns-id": 0,
                },
            }
        )
    return src_queue, bind_result["id"]


def _teardown_netkit(cfg):
    if cfg._nk_host_ifname:
        cmd(f"ip link del dev {cfg._nk_host_ifname}", fail=False)
        cfg._nk_host_ifname = None
        cfg._nk_guest_ifname = None


def set_flow_rule(cfg, src_queue):
    output = ethtool(
        f"-N {cfg.ifname} flow-type tcp6 dst-port {cfg.port} action {src_queue}"
    ).stdout
    values = re.search(r"ID (\d+)", output).group(1)
    return int(values)


def test_iou_zcrx(cfg) -> None:
    cfg.require_ipver("6")
    src_queue, nk_queue = _setup_lease(cfg)
    defer(_teardown_netkit, cfg)
    ethnl = EthtoolFamily()

    rings = ethnl.rings_get({"header": {"dev-index": cfg.ifindex}})
    rx_rings = rings["rx"]
    hds_thresh = rings.get("hds-thresh", 0)

    ethnl.rings_set(
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "enabled",
            "hds-thresh": 0,
            "rx": 64,
        }
    )
    defer(
        ethnl.rings_set,
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "unknown",
            "hds-thresh": hds_thresh,
            "rx": rx_rings,
        },
    )

    ethtool(f"-X {cfg.ifname} equal {src_queue}")
    defer(ethtool, f"-X {cfg.ifname} default")

    flow_rule_id = set_flow_rule(cfg, src_queue)
    defer(ethtool, f"-N {cfg.ifname} delete {flow_rule_id}")

    rx_cmd = (
        f"ip netns exec {cfg.netns.name} {cfg.bin_local} "
        f"-s -p {cfg.port} -i {cfg._nk_guest_ifname} -q {nk_queue}"
    )
    tx_cmd = f"{cfg.bin_remote} -c -h {cfg.nk_guest_ipv6} -p {cfg.port} -l 12840"
    with bkg(rx_cmd, exit_wait=True):
        wait_port_listen(cfg.port, proto="tcp", ns=cfg.netns)
        cmd(tx_cmd, host=cfg.remote)


def test_iou_zcrx_large_buf(cfg) -> None:
    """iou-zcrx with rx_buf_len > page size, going through a netkit-leased
    queue. Exercises the queue rx-buf-len path via netif_mp_open_rxq()'s
    lease redirect: the netkit ifindex is opaque to io_uring, but
    rx_page_size is honoured by the *physical* qops because the lease
    pointer rewrites the request from netkit onto the leased physical
    rxq before supported_params/validate_qcfg are consulted.
    """
    cfg.require_ipver("6")
    src_queue, nk_queue = _setup_lease(cfg)
    defer(_teardown_netkit, cfg)
    ethnl = EthtoolFamily()

    with open("/proc/sys/vm/nr_hugepages", "r+", encoding="utf-8") as f:
        nr_hugepages = int(f.read().strip())
        if nr_hugepages < 64:
            f.seek(0)
            f.write("64")
            defer(_restore_hugepages, nr_hugepages)

    rings = ethnl.rings_get({"header": {"dev-index": cfg.ifindex}})
    rx_rings = rings["rx"]
    hds_thresh = rings.get("hds-thresh", 0)

    ethnl.rings_set(
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "enabled",
            "hds-thresh": 0,
            "rx": 64,
        }
    )
    defer(
        ethnl.rings_set,
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "unknown",
            "hds-thresh": hds_thresh,
            "rx": rx_rings,
        },
    )

    ethtool(f"-X {cfg.ifname} equal {src_queue}")
    defer(ethtool, f"-X {cfg.ifname} default")

    flow_rule_id = set_flow_rule(cfg, src_queue)
    defer(ethtool, f"-N {cfg.ifname} delete {flow_rule_id}")

    # -x 2 asks iou-zcrx for rx_buf_len = 2 * page_size (8 KiB on x86_64),
    # backed by a 2 MiB hugepage area so the chunks are physically
    # contiguous, which is what zcrx requires for non-default rx_buf_len.
    rx_cmd = (
        f"ip netns exec {cfg.netns.name} {cfg.bin_local} "
        f"-s -p {cfg.port} -i {cfg._nk_guest_ifname} -q {nk_queue} -x 2"
    )
    tx_cmd = f"{cfg.bin_remote} -c -h {cfg.nk_guest_ipv6} -p {cfg.port} -l 12840"

    # Probe via -d (dry run): exits with SKIP_CODE if the leased physical
    # qops doesn't advertise QCFG_RX_PAGE_SIZE (e.g. older bnxt FW/HW).
    probe = cmd(rx_cmd + " -d", fail=False)
    if probe.ret == SKIP_CODE:
        msg = probe.stdout.strip() or "rx_buf_len not supported by leased NIC"
        raise KsftSkipEx(msg)

    with bkg(rx_cmd, exit_wait=True):
        wait_port_listen(cfg.port, proto="tcp", ns=cfg.netns)
        cmd(tx_cmd, host=cfg.remote)


def test_iou_zcrx_big_tcp(cfg) -> None:
    """iou-zcrx through netkit with BIG TCP RX, validated via BPF tracing.

    Configures GRO/GSO max sizing > 64 KiB on both the leased physical
    netdev (cfg.ifname) and the remote sender, runs iou-zcrx with
    rx_buf_len = 2 * page_size inside the netns against the netkit
    leased queue, and attaches a kprobe on io_zcrx_recv_skb() to
    record skb->len for every skb the io_uring zerocopy path consumes.
    This proves end-to-end that netkit RX queue leasing works end to
    end with large rx_buf_len + BIG TCP in io_uring ZC.
    """
    cfg.require_ipver("6")
    src_queue, nk_queue = _setup_lease(cfg)
    defer(_teardown_netkit, cfg)
    ethnl = EthtoolFamily()

    with open("/proc/sys/vm/nr_hugepages", "r+", encoding="utf-8") as f:
        nr_hugepages = int(f.read().strip())
        if nr_hugepages < 64:
            f.seek(0)
            f.write("64")
            defer(_restore_hugepages, nr_hugepages)

    old_local = _bigtcp_set(cfg.ifname, _BIG_TCP_SIZE)
    defer(_bigtcp_restore, cfg.ifname, old_local)
    old_remote = _bigtcp_set(cfg.remote_ifname, _BIG_TCP_SIZE,
                             host=cfg.remote)
    defer(_bigtcp_restore, cfg.remote_ifname, old_remote, host=cfg.remote)

    rings = ethnl.rings_get({"header": {"dev-index": cfg.ifindex}})
    rx_rings = rings["rx"]
    hds_thresh = rings.get("hds-thresh", 0)
    ethnl.rings_set(
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "enabled",
            "hds-thresh": 0,
            "rx": 64,
        }
    )
    defer(
        ethnl.rings_set,
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "unknown",
            "hds-thresh": hds_thresh,
            "rx": rx_rings,
        },
    )

    ethtool(f"-X {cfg.ifname} equal {src_queue}")
    defer(ethtool, f"-X {cfg.ifname} default")

    flow_rule_id = set_flow_rule(cfg, src_queue)
    defer(ethtool, f"-N {cfg.ifname} delete {flow_rule_id}")

    rx_cmd = (
        f"ip netns exec {cfg.netns.name} {cfg.bin_local} "
        f"-s -p {cfg.port} -i {cfg._nk_guest_ifname} -q {nk_queue} -x 2"
    )
    # Larger -l than test_iou_zcrx so the sender keeps the pipe full enough
    # for HW GRO to actually coalesce into >64 KiB skbs.
    tx_cmd = (
        f"{cfg.bin_remote} -c -h {cfg.nk_guest_ipv6} -p {cfg.port} -l 65536"
    )

    probe = cmd(rx_cmd + " -d", fail=False)
    if probe.ret == SKIP_CODE:
        msg = probe.stdout.strip() or "rx_buf_len not supported by leased NIC"
        raise KsftSkipEx(msg)

    # io_zcrx_recv_skb(read_descriptor_t *desc, struct sk_buff *skb, ...):
    # arg1 is the skb. The function is static but its address is taken by
    # tcp_read_sock(), so the symbol exists and is kprobe-attachable.
    bt_expr = (
        "kprobe:io_zcrx_recv_skb { "
        "$skb = (struct sk_buff *)arg1; "
        "@max_skb_len = max($skb->len); "
        "@total = count(); "
        "if ($skb->len > 65535) { @big_skbs = count(); } "
        "}"
    )
    bt_maps = {}
    bt_err = []

    def _bt_run():
        try:
            bt_maps.update(bpftrace(bt_expr, timeout=20, json=True))
        except Exception as e:  # pylint: disable=broad-except
            bt_err.append(repr(e))

    bt_thread = threading.Thread(target=_bt_run)
    bt_thread.start()
    # let bpftrace JIT/attach before we drive any zcrx traffic
    time.sleep(2)
    if not bt_thread.is_alive():
        bt_thread.join()
        raise KsftSkipEx(
            f"bpftrace did not start (kprobe on io_zcrx_recv_skb missing?): "
            f"{bt_err[0] if bt_err else 'no error reported'}"
        )

    with bkg(rx_cmd, exit_wait=True):
        wait_port_listen(cfg.port, proto="tcp", ns=cfg.netns)
        cmd(tx_cmd, host=cfg.remote)

    bt_thread.join()
    if bt_err:
        raise KsftSkipEx(f"bpftrace failed: {bt_err[0]}")
    if "total" not in bt_maps:
        raise KsftFailEx(
            f"bpftrace produced no io_zcrx_recv_skb events: {bt_maps}"
        )

    big = int(bt_maps.get("big_skbs", 0))
    max_len = int(bt_maps.get("max_skb_len", 0))
    total = int(bt_maps.get("total", 0))

    if max_len <= 65535:
        raise KsftFailEx(
            f"BIG TCP RX did not trigger via netkit lease: "
            f"max skb->len at io_zcrx_recv_skb was {max_len} "
            f"(total skbs={total}, big={big}). "
            f"Expected at least one skb with len > 65535."
        )

    ksft_eq(
        big > 0,
        True,
        comment=(
            f"BIG-TCP skbs reached io_zcrx_recv_skb via netkit lease: "
            f"big={big} max_len={max_len} total={total}"
        ),
    )


def test_attrs(cfg) -> None:
    cfg.require_ipver("6")
    src_queue, nk_queue = _setup_lease(cfg)
    defer(_teardown_netkit, cfg)
    netdevnl = NetdevFamily()
    queue_info = netdevnl.queue_get(
        {"ifindex": cfg.ifindex, "id": src_queue, "type": "rx"}
    )

    ksft_eq(queue_info["id"], src_queue)
    ksft_eq(queue_info["type"], "rx")
    ksft_eq(queue_info["ifindex"], cfg.ifindex)

    ksft_in("lease", queue_info)
    lease = queue_info["lease"]
    ksft_eq(lease["ifindex"], cfg.nk_guest_ifindex)
    ksft_eq(lease["queue"]["id"], nk_queue)
    ksft_eq(lease["queue"]["type"], "rx")
    ksft_in("netns-id", lease)


def test_attach_xdp_with_mp(cfg) -> None:
    cfg.require_ipver("6")
    src_queue, nk_queue = _setup_lease(cfg)
    defer(_teardown_netkit, cfg)
    ethnl = EthtoolFamily()

    rings = ethnl.rings_get({"header": {"dev-index": cfg.ifindex}})
    rx_rings = rings["rx"]
    hds_thresh = rings.get("hds-thresh", 0)

    ethnl.rings_set(
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "enabled",
            "hds-thresh": 0,
            "rx": 64,
        }
    )
    defer(
        ethnl.rings_set,
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "unknown",
            "hds-thresh": hds_thresh,
            "rx": rx_rings,
        },
    )

    ethtool(f"-X {cfg.ifname} equal {src_queue}")
    defer(ethtool, f"-X {cfg.ifname} default")

    netdevnl = NetdevFamily()

    rx_cmd = (
        f"ip netns exec {cfg.netns.name} {cfg.bin_local} "
        f"-s -p {cfg.port} -i {cfg._nk_guest_ifname} -q {nk_queue}"
    )
    with bkg(rx_cmd):
        wait_port_listen(cfg.port, proto="tcp", ns=cfg.netns)

        time.sleep(0.1)
        queue_info = netdevnl.queue_get(
            {"ifindex": cfg.ifindex, "id": src_queue, "type": "rx"}
        )
        ksft_in("io-uring", queue_info)

        prog = cfg.net_lib_dir / "xdp_dummy.bpf.o"
        with ksft_raises(CmdExitFailure):
            ip(f"link set dev {cfg.ifname} xdp obj {prog} sec xdp.frags")

    time.sleep(0.1)
    queue_info = netdevnl.queue_get(
        {"ifindex": cfg.ifindex, "id": src_queue, "type": "rx"}
    )
    ksft_not_in("io-uring", queue_info)


def test_destroy(cfg) -> None:
    cfg.require_ipver("6")
    src_queue, nk_queue = _setup_lease(cfg)
    defer(_teardown_netkit, cfg)
    ethnl = EthtoolFamily()

    rings = ethnl.rings_get({"header": {"dev-index": cfg.ifindex}})
    rx_rings = rings["rx"]
    hds_thresh = rings.get("hds-thresh", 0)

    ethnl.rings_set(
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "enabled",
            "hds-thresh": 0,
            "rx": 64,
        }
    )
    defer(
        ethnl.rings_set,
        {
            "header": {"dev-index": cfg.ifindex},
            "tcp-data-split": "unknown",
            "hds-thresh": hds_thresh,
            "rx": rx_rings,
        },
    )

    ethtool(f"-X {cfg.ifname} equal {src_queue}")
    defer(ethtool, f"-X {cfg.ifname} default")

    rx_cmd = (
        f"ip netns exec {cfg.netns.name} {cfg.bin_local} "
        f"-s -p {cfg.port} -i {cfg._nk_guest_ifname} -q {nk_queue}"
    )
    rx_proc = cmd(rx_cmd, background=True)
    wait_port_listen(cfg.port, proto="tcp", ns=cfg.netns)

    netdevnl = NetdevFamily()
    queue_info = netdevnl.queue_get(
        {"ifindex": cfg.ifindex, "id": src_queue, "type": "rx"}
    )
    ksft_in("io-uring", queue_info)

    # ip link del will wait for all refs to drop first, but iou-zcrx is holding
    # onto a ref. Terminate iou-zcrx async via a thread after a delay.
    kill_timer = threading.Timer(1, rx_proc.proc.terminate)
    kill_timer.start()

    ip(f"link del dev {cfg._nk_host_ifname}")
    kill_timer.join()
    cfg._nk_host_ifname = None
    cfg._nk_guest_ifname = None

    queue_info = netdevnl.queue_get(
        {"ifindex": cfg.ifindex, "id": src_queue, "type": "rx"}
    )
    ksft_not_in("io-uring", queue_info)

    flow_rule_id = set_flow_rule(cfg, src_queue)
    defer(ethtool, f"-N {cfg.ifname} delete {flow_rule_id}")

    rx_cmd = f"{cfg.bin_local} -s -p {cfg.port} -i {cfg.ifname} -q {src_queue}"
    tx_cmd = f"{cfg.bin_remote} -c -h {cfg.addr_v['6']} -p {cfg.port} -l 12840"
    with bkg(rx_cmd, exit_wait=True):
        wait_port_listen(cfg.port, proto="tcp")
        cmd(tx_cmd, host=cfg.remote)
    # Short delay since iou cleanup is async and takes a bit of time.
    time.sleep(0.1)
    queue_info = netdevnl.queue_get(
        {"ifindex": cfg.ifindex, "id": src_queue, "type": "rx"}
    )
    ksft_not_in("io-uring", queue_info)


def main() -> None:
    with NetDrvContEnv(__file__, rxqueues=2) as cfg:
        cfg.bin_local = path.abspath(
            path.dirname(__file__) + "/../../../drivers/net/hw/iou-zcrx"
        )
        cfg.bin_remote = cfg.remote.deploy(cfg.bin_local)
        cfg.port = rand_port()

        ksft_run(
            [
                test_iou_zcrx,
                test_iou_zcrx_large_buf,
                test_iou_zcrx_big_tcp,
                test_attrs,
                test_attach_xdp_with_mp,
                test_destroy,
            ],
            args=(cfg,),
        )
    ksft_exit()


if __name__ == "__main__":
    main()
