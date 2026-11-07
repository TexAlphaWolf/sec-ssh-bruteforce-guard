"""Against the real kernel firewall. Needs root and nftables: skipped everywhere else.

CI runs these on a GitHub runner with sudo; locally: `sudo pytest -m nft`.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import uuid

import pytest

from sshguard.backends import NftBackend, run_process


def _nft_works() -> bool:
    if shutil.which("nft") is None or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return False
    return (
        subprocess.run(["nft", "list", "tables"], capture_output=True, check=False).returncode == 0
    )


pytestmark = [
    pytest.mark.nft,
    pytest.mark.skipif(not _nft_works(), reason="needs root and a working nftables"),
]


@pytest.fixture
def backend():  # type: ignore[no-untyped-def]
    b = NftBackend(table="sg_" + uuid.uuid4().hex[:8], ports=(), runner=run_process)
    b.setup()
    yield b
    b.remove_all()


def test_setup_twice_does_not_stack_rules(backend):  # type: ignore[no-untyped-def]
    backend.setup()
    backend.setup()
    assert backend.listing().count("saddr @blocked4") == 1


def test_ban_shows_up_with_an_expiry_and_goes_away_on_unban(backend):  # type: ignore[no-untyped-def]
    backend.ban("203.0.113.5", 3600)
    backend.ban("2001:db8:1:2::/64", 600)
    backend.ban("198.51.100.0/24", None)
    listing = backend.listing()
    assert "203.0.113.5 timeout 1h" in listing and "expires" in listing
    assert "2001:db8:1:2::/64 timeout 10m" in listing
    assert "198.51.100.0/24" in listing
    backend.unban("203.0.113.5")
    backend.unban("203.0.113.5")  # again: idempotent
    assert "203.0.113.5" not in backend.listing()


def test_banning_again_extends_the_timeout(backend):  # type: ignore[no-untyped-def]
    backend.ban("203.0.113.5", 60)
    backend.ban("203.0.113.5", 7200)
    listing = backend.listing()
    assert "203.0.113.5 timeout 2h" in listing
    assert "timeout 1m" not in listing


def test_sync_replaces_the_contents_in_one_step(backend):  # type: ignore[no-untyped-def]
    backend.ban("203.0.113.5", 600)
    backend.sync([("203.0.113.9", 600), ("2001:db8::/64", None)])
    listing = backend.listing()
    assert "203.0.113.5" not in listing
    assert "203.0.113.9" in listing and "2001:db8::/64" in listing
    backend.sync([])
    assert "203.0.113.9" not in backend.listing()


def test_a_ban_really_blocks_traffic_and_unban_restores_it(backend):  # type: ignore[no-untyped-def]
    """Connect to a local server from 127.0.0.1: banned -> the connection times out."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]

    def can_connect() -> bool:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.5):
                return True
        except OSError:
            return False

    try:
        assert can_connect()
        backend.ban("127.0.0.1", 600)
        assert not can_connect()
        backend.unban("127.0.0.1")
        assert can_connect()
    finally:
        server.close()


def test_ports_limit_what_is_blocked():
    server_a, server_b = socket.socket(), socket.socket()
    for s in (server_a, server_b):
        s.bind(("127.0.0.1", 0))
        s.listen(5)
    blocked, open_ = server_a.getsockname()[1], server_b.getsockname()[1]
    b = NftBackend(table="sg_" + uuid.uuid4().hex[:8], ports=(blocked,), runner=run_process)
    b.setup()
    try:
        b.ban("127.0.0.1", 600)

        def ok(port: int) -> bool:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1.5):
                    return True
            except OSError:
                return False

        assert not ok(blocked)
        assert ok(open_)
    finally:
        b.remove_all()
        server_a.close()
        server_b.close()


def test_reject_answers_immediately_instead_of_timing_out():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(5)
    port = server.getsockname()[1]
    b = NftBackend(
        table="sg_" + uuid.uuid4().hex[:8], ports=(port,), action="reject", runner=run_process
    )
    b.setup()
    try:
        b.ban("127.0.0.1", 600)
        with pytest.raises(ConnectionRefusedError):
            socket.create_connection(("127.0.0.1", port), timeout=3)
    finally:
        b.remove_all()
        server.close()
