from parsers.network_parser import parse_network_activity


def test_parse_network_activity(tmp_path):

    network_file = tmp_path / "network.csv"

    network_file.write_text(
        "timestamp,source_ip,destination_ip,port,protocol,process\n"
        "2026-09-07T10:10:00,192.168.1.50,8.8.8.8,443,TCP,chrome.exe\n"
        "2026-09-07T10:11:00,192.168.1.50,10.0.0.5,22,TCP,powershell.exe\n"
    )

    events = parse_network_activity(network_file)

    assert len(events) == 2

    assert events[0]["event_type"] == "network"

    assert events[0]["source_ip"] == "192.168.1.50"

    assert events[0]["destination_ip"] == "8.8.8.8"

    assert events[0]["port"] == "443"

    assert events[0]["protocol"] == "TCP"

    assert events[0]["process"] == "chrome.exe"