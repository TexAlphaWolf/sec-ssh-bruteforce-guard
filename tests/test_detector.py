from __future__ import annotations

from dataclasses import replace

from conftest import fail
from sshguard.detector import DetectConfig, Detector
from sshguard.events import ACCEPTED, INVALID_USER, PREAUTH_DROP, Attempt
from sshguard.net import parse_networks

IP = "203.0.113.5"


def test_bans_at_the_threshold_not_before():
    d = Detector(DetectConfig(max_failures=5))
    assert all(d.observe(fail(IP, t)) is None for t in range(4))
    v = d.observe(fail(IP, 4))
    assert v is not None
    assert (v.target, v.reason, v.score) == (IP, "failures", 5.0)


def test_failures_outside_the_window_are_forgotten():
    d = Detector(DetectConfig(max_failures=3, window=60, slow_max_failures=0))
    for t in (0, 30, 100, 130):  # never 3 inside 60 s
        assert d.observe(fail(IP, t)) is None


def test_a_user_who_mistypes_three_times_is_not_banned():
    d = Detector(DetectConfig())
    assert all(d.observe(fail(IP, t, "luca")) is None for t in (0, 3, 6))
    assert d.observe(Attempt(9, IP, ACCEPTED, "luca")) is None


def test_weights_count_preauth_drops_as_half():
    d = Detector(DetectConfig(max_failures=2))
    drop = Attempt(0, IP, PREAUTH_DROP)
    assert d.observe(drop) is None
    assert d.observe(replace(drop, ts=1)) is None
    assert d.observe(replace(drop, ts=2)) is None
    assert d.observe(replace(drop, ts=3)) is not None  # 4 x 0.5


def test_weight_zero_events_do_not_count():
    d = Detector(DetectConfig(max_failures=1, max_users=0))
    assert d.observe(Attempt(0, IP, INVALID_USER)) is None  # no name: nothing to remember
    assert len(d) == 0


def test_password_spraying_many_names_few_tries_each():
    d = Detector(DetectConfig(max_failures=100, max_users=4))
    verdict = None
    for i in range(4):
        verdict = d.observe(fail(IP, i, f"user{i}"))
    assert verdict is not None
    assert verdict.reason == "spray"
    assert verdict.users == 4


def test_same_name_repeated_is_not_spraying():
    d = Detector(DetectConfig(max_failures=100, max_users=3, slow_max_failures=0))
    assert all(d.observe(fail(IP, i, "root")) is None for i in range(20))


def test_low_and_slow_is_caught_by_the_long_window():
    d = Detector(DetectConfig(max_failures=5, window=600, slow_max_failures=10, slow_window=86400))
    verdict = None
    for i in range(10):  # one try every 20 minutes
        verdict = d.observe(fail(IP, i * 1200))
    assert verdict is not None
    assert verdict.reason == "slow"


def test_slow_check_can_be_turned_off():
    d = Detector(DetectConfig(max_failures=5, slow_max_failures=0))
    assert all(d.observe(fail(IP, i * 1200)) is None for i in range(50))


def test_allowlist_is_never_counted():
    d = Detector(DetectConfig(max_failures=1, allowlist=parse_networks(["203.0.113.0/24"])))
    assert d.observe(fail(IP, 0)) is None
    assert len(d) == 0


def test_allowlist_does_not_leak_between_families():
    d = Detector(DetectConfig(max_failures=1, allowlist=parse_networks(["::/0"])))
    assert d.observe(fail(IP, 0)) is not None  # an IPv4 source is not in ::/0


def test_ipv6_is_counted_per_prefix():
    d = Detector(DetectConfig(max_failures=3, ipv6_prefix=64))
    out = [
        d.observe(fail(f"2001:db8:0:1::{i:x}", i)) for i in range(1, 4)
    ]  # three addresses, one /64
    assert out[-1] is not None
    assert out[-1].target == "2001:db8:0:1::/64"


def test_different_ipv6_prefixes_are_separate():
    d = Detector(DetectConfig(max_failures=2))
    assert d.observe(fail("2001:db8:0:1::1", 0)) is None
    assert d.observe(fail("2001:db8:0:2::1", 1)) is None


def test_sources_are_independent():
    d = Detector(DetectConfig(max_failures=2))
    assert d.observe(fail("203.0.113.1", 0)) is None
    assert d.observe(fail("203.0.113.2", 1)) is None
    assert d.observe(fail("203.0.113.1", 2)) is not None


def test_a_login_forgives_that_users_failures_only():
    d = Detector(DetectConfig(max_failures=3, slow_max_failures=0))
    d.observe(fail(IP, 0, "luca"))
    d.observe(fail(IP, 1, "luca"))
    d.observe(fail(IP, 2, "root"))
    d.observe(Attempt(3, IP, ACCEPTED, "luca"))  # luca's two typos are forgiven...
    assert d.observe(fail(IP, 4, "root")) is None  # ...root's failure is not: 2 so far
    assert d.observe(fail(IP, 5, "root")) is not None  # 3 failures for root


def test_forgiveness_can_be_switched_off():
    d = Detector(DetectConfig(max_failures=3, forgive_on_success=False))
    d.observe(fail(IP, 0, "luca"))
    d.observe(fail(IP, 1, "luca"))
    d.observe(Attempt(2, IP, ACCEPTED, "luca"))
    assert d.observe(fail(IP, 3, "luca")) is not None


def test_a_shared_address_with_many_honest_typos_is_not_banned_by_the_slow_rule():
    d = Detector(DetectConfig(max_failures=5, slow_max_failures=15))
    verdicts = []
    for n in range(40):  # forty colleagues, each one typo and then the right password
        t = n * 1500.0
        verdicts.append(d.observe(fail(IP, t, f"colleague{n}")))
        verdicts.append(d.observe(Attempt(t + 5, IP, ACCEPTED, f"colleague{n}")))
    assert not any(verdicts)


def test_accepted_without_a_user_or_from_an_unknown_source_is_harmless():
    d = Detector(DetectConfig())
    assert d.observe(Attempt(0, IP, ACCEPTED, None)) is None
    assert d.observe(Attempt(0, "203.0.113.77", ACCEPTED, "x")) is None


def test_memory_is_bounded():
    d = Detector(DetectConfig(max_failures=10, max_tracked=100))
    for i in range(500):
        d.observe(fail(f"10.{i // 250}.{i % 250}.1", i))
    assert len(d) == 100
    assert d.evicted == 400


def test_one_source_cannot_grow_without_limit():
    d = Detector(
        DetectConfig(
            max_failures=1e9, max_users=0, slow_max_failures=0, window=1e9, slow_window=1e9
        )
    )
    for i in range(5000):
        d.observe(fail(IP, i))
    state = d._states[IP]
    assert len(state.events) == 2048


def test_sweep_drops_quiet_sources():
    d = Detector(DetectConfig(slow_window=100, window=10))
    d.observe(fail("203.0.113.1", 0))
    d.observe(fail("203.0.113.2", 1000))
    assert d.sweep(1050) == 1
    assert len(d) == 1


def test_forget():
    d = Detector(DetectConfig(max_failures=2))
    d.observe(fail(IP, 0))
    d.forget(IP)
    assert d.observe(fail(IP, 1)) is None


def test_events_from_the_future_are_ignored_in_the_sum():
    d = Detector(DetectConfig(max_failures=3))
    d.observe(fail(IP, 100))
    d.observe(fail(IP, 101))
    assert (
        d.observe(fail(IP, 50)) is None
    )  # older line from a file read late: still only 3 total...


def test_probes_count_a_fifth_each():
    d = Detector(DetectConfig(max_failures=1, slow_max_failures=0))
    probe = Attempt(0, IP, "probe")
    out = [d.observe(replace(probe, ts=i)) for i in range(5)]
    assert out[:4] == [None] * 4 and out[4] is not None  # 5 x 0.2 reaches 1.0
