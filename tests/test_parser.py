import pytest

from analyzer.parser import LogParser


def test_failed_login_parsing():

    parser = LogParser()

    record = parser._parse_line(
        "Jul 20 08:00:01 kali sshd[120]: Failed password for root from 192.168.1.100 port 22 ssh2"
    )

    assert record is not None
    assert record["username"] == "root"
    assert record["ip"] == "192.168.1.100"


def test_success_login_parsing():

    parser = LogParser()

    record = parser._parse_line(
        "Jul 20 08:01:05 kali sshd[121]: Accepted password for satnam from 192.168.1.10 port 22 ssh2"
    )

    assert record is not None
    assert record["username"] == "satnam"