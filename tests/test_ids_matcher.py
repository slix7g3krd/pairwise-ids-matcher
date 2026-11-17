import pytest

from security.ids_matcher import (
    normalize,
    match_rules,
    reassemble,
    direction_ok,
    allowlisted
)


def test_normalize_case():
    assert normalize('SELECT') == 'select'

def test_normalize_url():
    assert normalize('a%2fb') == 'a/b'

def test_multi_rules():
    assert match_rules('select union', [{'id': 'r1', 'pattern': 'select'}, {'id': 'r2', 'pattern': 'union'}]) == ['r1', 'r2']

def test_overlap():
    assert match_rules('union select', [{'id': 'r1', 'pattern': 'select'}, {'id': 'r2', 'pattern': 'union select'}]) == ['r1', 'r2']

def test_reassemble():
    assert reassemble([(1, 'ab'), (2, 'cd')]) == 'abcd'

def test_out_of_order():
    assert reassemble([(2, 'cd'), (1, 'ab')]) == 'abcd'

def test_retransmit():
    assert reassemble([(1, 'ab'), (1, 'ab'), (2, 'cd')]) == 'abcd'

def test_direction_in():
    assert direction_ok('ingress', 'ingress') is True

def test_direction_out():
    assert direction_ok('ingress', 'egress') is False

def test_allow_exact():
    assert allowlisted('10.0.0.1', {'10.0.0.1'}, {}) is True

def test_nat():
    assert allowlisted('10.0.0.1', set(), {'10.0.0.1': '203.0.113.5'}) is True

def test_empty():
    assert match_rules('', []) == []

def test_rule_order():
    assert match_rules('a b', [{'id': 'r1', 'pattern': 'b'}, {'id': 'r2', 'pattern': 'a'}]) == ['r1', 'r2']

def test_boundary():
    assert reassemble([(1, 'se'), (2, 'lect')]) == 'select'

def test_dedupe_rules():
    assert match_rules('a', [{'id': 'r1', 'pattern': 'a'}, {'id': 'r1', 'pattern': 'a'}]) == ['r1']
