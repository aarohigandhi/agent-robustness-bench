import pytest

from arb.eval.stats import intervals_overlap, wilson


def test_zero_successes_does_not_claim_certainty():
    """The reason Wilson is used at all. The normal approximation returns
    0.0 +/- 0.0 here, asserting certainty from 30 samples."""
    p, lo, hi = wilson(0, 30)
    assert p == 0.0
    assert lo == 0.0
    assert 0.05 < hi < 0.15  # roughly [0, 11%]


def test_all_successes_does_not_claim_certainty():
    p, lo, hi = wilson(30, 30)
    assert p == 1.0
    assert hi == 1.0
    assert 0.85 < lo < 0.95


def test_point_estimate_and_containment():
    p, lo, hi = wilson(12, 30)
    assert p == pytest.approx(0.4)
    assert lo < p < hi


def test_interval_narrows_with_more_samples():
    _, lo_small, hi_small = wilson(12, 30)
    _, lo_big, hi_big = wilson(120, 300)
    assert (hi_big - lo_big) < (hi_small - lo_small)


def test_overlap_guard_blocks_a_false_claim():
    """20% vs 15% at n=30 must not be reported as a difference."""
    a, b = wilson(6, 30), wilson(4, 30)
    assert intervals_overlap(a, b)


def test_clearly_separated_intervals_do_not_overlap():
    assert not intervals_overlap(wilson(29, 30), wilson(1, 30))


def test_empty_sample_is_maximally_uncertain():
    assert wilson(0, 0) == (0.0, 0.0, 1.0)


def test_rejects_impossible_counts():
    with pytest.raises(ValueError):
        wilson(31, 30)
