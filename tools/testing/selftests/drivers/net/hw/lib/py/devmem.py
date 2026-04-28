# SPDX-License-Identifier: GPL-2.0
"""Shared helpers for devmem TCP selftests."""

import re

from net.lib.py import (bkg, cmd, defer, ethtool, rand_port, wait_port_listen,
                        ksft_eq, KsftSkipEx, NetNSEnter, EthtoolFamily,
                        NetdevFamily)


def require_devmem(cfg):
    if not hasattr(cfg, "_devmem_probed"):
        probe_command = f"{cfg.bin_local} -f {cfg.ifname}"
        cfg._devmem_supported = cmd(probe_command, fail=False, shell=True).ret == 0
        cfg._devmem_probed = True

    if not cfg._devmem_supported:
        raise KsftSkipEx("Test requires devmem support")


def configure_nic(cfg):
    """Channels, rings, RSS, queue lease for netkit devmem.

    Rings and RSS are re-applied each call because per-test defers restore
    them after every test case. The queue lease is created only once.
    """
    cfg.require_ipver('6')
    ethnl = EthtoolFamily()

    channels = ethnl.channels_get({'header': {'dev-index': cfg.ifindex}})
    channels = channels['combined-count']
    if channels < 2:
        raise KsftSkipEx(
            'Test requires NETIF with at least 2 combined channels'
        )

    rings = ethnl.rings_get({'header': {'dev-index': cfg.ifindex}})
    rx_rings = rings['rx']
    hds_thresh = rings.get('hds-thresh', 0)
    orig_data_split = rings.get('tcp-data-split', 'unknown')

    ethnl.rings_set({'header': {'dev-index': cfg.ifindex},
                     'tcp-data-split': 'enabled',
                     'hds-thresh': 0,
                     'rx': min(64, rx_rings)})
    defer(ethnl.rings_set, {'header': {'dev-index': cfg.ifindex},
                            'tcp-data-split': orig_data_split,
                            'hds-thresh': hds_thresh,
                            'rx': rx_rings})

    cfg.src_queue = channels - 1
    ethtool(f"-X {cfg.ifname} equal {cfg.src_queue}")
    defer(ethtool, f"-X {cfg.ifname} default")

    if not hasattr(cfg, 'nk_queue'):
        with NetNSEnter(str(cfg.netns)):
            netdevnl = NetdevFamily()
            lease_result = netdevnl.queue_create({
                "ifindex": cfg.nk_guest_ifindex,
                "type": "rx",
                "lease": {
                    "ifindex": cfg.ifindex,
                    "queue": {"id": cfg.src_queue, "type": "rx"},
                    "netns-id": 0,
                },
            })
            cfg.nk_queue = lease_result['id']


def set_flow_rule(cfg, port):
    output = ethtool(
        f"-N {cfg.ifname} flow-type tcp6 dst-port {port}"
        f" action {cfg.src_queue}"
    ).stdout
    return int(re.search(r'ID (\d+)', output).group(1))


def ncdevmem_rx(cfg, port, verify=True, fail_on_linear=False):
    if hasattr(cfg, 'netns'):
        flow_rule_id = set_flow_rule(cfg, port)
        defer(ethtool, f"-N {cfg.ifname} delete {flow_rule_id}")

        ifname = cfg._nk_guest_ifname
        addr = cfg.nk_guest_ipv6
        extras = f" -t {cfg.nk_queue} -q 1 -n"
        if verify:
            extras += " -v 7"
    else:
        ifname = cfg.ifname
        addr = cfg.addr
        extras = ""

    if fail_on_linear:
        extras += " -L"

    return f"{cfg.bin_local} -l -f {ifname} -s {addr} -p {port} {extras}"


def ncdevmem_tx(cfg, port, chunk_size=0):
    """ncdevmem TX send command (without stdin pipe)."""
    if hasattr(cfg, 'netns'):
        ifname = cfg._nk_guest_ifname
        addr = cfg.remote_addr_v['6']
        nk_args = "-t 0 -q 1 -n"
    else:
        ifname = cfg.ifname
        addr = cfg.remote_addr
        nk_args = ""

    chunk = f"-z {chunk_size}" if chunk_size else ""

    return (f"{cfg.bin_local} -f {ifname} -s {addr} -p {port}"
            f" {nk_args} {chunk}").rstrip()


def socat_send(cfg, port, buf_size=0, nodelay=False, bind=False):
    """Socat command for sending to the devmem listener."""
    proto = f"TCP{cfg.addr_ipver}"

    if hasattr(cfg, 'netns'):
        addr = f"[{cfg.nk_guest_ipv6}]"
    else:
        addr = cfg.baddr

    buf = f"-b {buf_size} " if buf_size else ""

    suffix = ""
    if nodelay:
        suffix += ",nodelay"
    # Match the 5-tuple flow rule ncdevmem installs when given -c.
    if bind:
        suffix += f",bind={cfg.remote_baddr}:{port}"

    return f"socat {buf}-u - {proto}:{addr}:{port}{suffix}"


def socat_listen(cfg, port):
    """Socat listen command for TX tests."""
    proto = f"TCP{cfg.addr_ipver}"

    if hasattr(cfg, 'netns'):
        opts = ",reuseaddr"
    else:
        opts = ""

    return f"socat -U - {proto}-LISTEN:{port}{opts}"


def setup_test(cfg, bin_local):
    cfg.bin_local = bin_local
    cfg.bin_remote = cfg.remote.deploy(cfg.bin_local)
    cfg.listen_ns = getattr(cfg, 'netns', None)
    require_devmem(cfg)


def run_rx(cfg):
    if hasattr(cfg, 'netns'):
        configure_nic(cfg)
    port = rand_port()
    socat = socat_send(cfg, port)
    data_pipe = (f"yes $(echo -e \x01\x02\x03\x04\x05\x06) | head -c 1K"
                 f" | {socat}")
    ns = getattr(cfg, "netns", None)

    listen_cmd = ncdevmem_rx(cfg, port)
    with bkg(listen_cmd, exit_wait=True, ns=ns) as ncdevmem:
        wait_port_listen(port, proto="tcp", ns=ns)
        cmd(data_pipe, host=cfg.remote, shell=True)
    ksft_eq(ncdevmem.ret, 0)


def run_tx(cfg):
    if hasattr(cfg, 'netns'):
        configure_nic(cfg)
    ns = getattr(cfg, "netns", None)
    port = rand_port()
    tx = ncdevmem_tx(cfg, port)
    listen_cmd = socat_listen(cfg, port)

    with bkg(listen_cmd, host=cfg.remote, exit_wait=True) as socat:
        wait_port_listen(port, host=cfg.remote)
        cmd(f"bash -c 'echo -e \"hello\\nworld\" | {tx}'", ns=ns, shell=True)
    ksft_eq(socat.stdout.strip(), "hello\nworld")


def run_tx_chunks(cfg):
    if hasattr(cfg, 'netns'):
        configure_nic(cfg)
    ns = getattr(cfg, "netns", None)
    port = rand_port()
    tx = ncdevmem_tx(cfg, port, chunk_size=3)
    listen_cmd = socat_listen(cfg, port)

    with bkg(listen_cmd, host=cfg.remote, exit_wait=True) as socat:
        wait_port_listen(port, host=cfg.remote)
        cmd(f"bash -c 'echo -e \"hello\\nworld\" | {tx}'", ns=ns, shell=True)
    ksft_eq(socat.stdout.strip(), "hello\nworld")


def run_rx_hds(cfg):
    if hasattr(cfg, 'netns'):
        configure_nic(cfg)
    ns = getattr(cfg, "netns", None)

    for size in [1, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]:
        port = rand_port()

        listen_cmd = ncdevmem_rx(cfg, port, verify=False, fail_on_linear=True)
        socat = socat_send(cfg, port, buf_size=size, nodelay=True)

        with bkg(listen_cmd, exit_wait=True, ns=ns) as ncdevmem:
            wait_port_listen(port, proto="tcp", ns=ns)
            cmd(f"dd if=/dev/zero bs={size} count=1 2>/dev/null | "
                f"{socat}", host=cfg.remote, shell=True)
        ksft_eq(ncdevmem.ret, 0, f"HDS failed for payload size {size}")
