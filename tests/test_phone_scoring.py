"""Offline regression checks for the fallback phone summary."""

from phone_osint import manual_confidence


def test_empty_phone_data_is_not_high_risk():
    result = manual_confidence({'info': {'valid': False}})
    assert result['risk'] == 'Unassessed'
    assert result['confidence'] == 0


def test_completeness_score_is_bounded():
    result = manual_confidence({
        'info': {'valid': True, 'carrier': 'Test Carrier', 'region': 'Test Region'},
        'names': ['Fixture Name'], 'emails': ['sample@example.invalid'],
        'web_hits': [{'url': 'https://example.invalid'}],
        'hibp_results': [{'breached': True}],
    })
    assert 0 <= result['confidence'] <= 95
    assert result['risk'] == 'Unassessed'
