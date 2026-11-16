"""PDF report generation against local, synthetic input."""

from pdf_gen import generate_pdf


def test_pdf_generation():
    report = {
        'id': 1,
        'type': 'domain',
        'target': 'example.com',
        'timestamp': '2026-11-16 00:00:00',
        'results': {
            'domain': 'example.com', 'ip': '93.184.216.34',
            'http_status': 200, 'https_status': 200,
            'ssl': True, 'reachable': True,
        },
        'summary': {},
    }
    document = generate_pdf(report)
    assert document.startswith(b'%PDF')
    assert len(document) > 500
