from analyzer.brute_force_detector import (
    BruteForceDetector
)


def test_bruteforce_detection():

    records = []

    for _ in range(6):

        records.append({
            "event_type": "failed_login",
            "ip": "192.168.1.100"
        })

    detector = BruteForceDetector(
        records
    )

    alerts = detector.detect()

    assert len(alerts) >= 1
    assert alerts[0]["ip"] == (
        "192.168.1.100"
    )