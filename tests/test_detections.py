"""Detection-as-code is gated by CI: every rule must be well-formed and mapped.

If anyone adds a detection that is missing metadata, has an invalid MITRE
technique, an unknown data source, or a query that doesn't reference its table,
this suite fails and the pipeline blocks the merge.
"""
from detections.validate import ALLOWED_SEVERITY, TECHNIQUE_RE, load_rules


def test_rules_load_and_validate():
    rules = load_rules()
    assert len(rules) >= 3, "expected at least 3 detections"


def test_every_rule_is_mapped_and_well_formed():
    for d in load_rules():
        assert d.severity in ALLOWED_SEVERITY, f"{d.id}: bad severity"
        assert TECHNIQUE_RE.match(d.technique), f"{d.id}: invalid MITRE technique"
        assert d.data_source in d.query, f"{d.id}: query must reference its table"
        assert d.id and d.title, f"{d.id}: missing id/title"


def test_rule_ids_are_unique():
    ids = [d.id for d in load_rules()]
    assert len(ids) == len(set(ids)), "duplicate detection ids found"
