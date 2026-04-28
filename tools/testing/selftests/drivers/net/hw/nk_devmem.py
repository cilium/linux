#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Test devmem TCP with netkit."""

from os import path
from lib.py import ksft_run, ksft_exit, ksft_disruptive
from lib.py import NetDrvContEnv
from lib.py.devmem import setup_test, run_rx, run_tx, run_tx_chunks, run_rx_hds


@ksft_disruptive
def check_nk_rx(cfg) -> None:
    run_rx(cfg)


@ksft_disruptive
def check_nk_tx(cfg) -> None:
    run_tx(cfg)


@ksft_disruptive
def check_nk_tx_chunks(cfg) -> None:
    run_tx_chunks(cfg)


@ksft_disruptive
def check_nk_rx_hds(cfg) -> None:
    run_rx_hds(cfg)


def main() -> None:
    with NetDrvContEnv(__file__, rxqueues=2, primary_rx_redirect=True) as cfg:
        setup_test(cfg, path.abspath(path.dirname(__file__) + "/ncdevmem"))
        ksft_run([check_nk_rx, check_nk_tx, check_nk_tx_chunks, check_nk_rx_hds],
                 args=(cfg,))
    ksft_exit()


if __name__ == "__main__":
    main()
