"""Every red-team attack must be defended — this is the security regression suite.

If a future change lets any of these through, this suite fails loudly.
"""
from attacks.redteam import run_all


def test_every_attack_is_defended():
    results = run_all()
    leaked = [(a.id, a.name, o) for a, o in results if not o.defended]
    assert not leaked, f"attacks leaked: {leaked}"
    assert len(results) >= 12  # full coverage present


def test_each_attack_blocked_at_expected_gate():
    by_id = {a.id: (a, o) for a, o in run_all()}
    expected = {
        "A01": "auth", "A02": "auth", "A03": "auth",
        "A04": "scope", "A05": "scope", "A06": "registry",
        "A07": "intent", "A08": "intent",
        "A09": "policy", "A10": "policy",
        "A11": "evidence", "A12": "evidence",
    }
    for aid, gate in expected.items():
        atk, out = by_id[aid]
        assert out.defended, f"{aid} {atk.name} was not defended"
        assert out.gate == gate, f"{aid} stopped at {out.gate}, expected {gate}"
