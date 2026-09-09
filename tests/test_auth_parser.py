from parsers.auth_parser import parse_auth_log


def test_parse_auth_log(tmp_path):

    auth_file = tmp_path / "auth.log"

    auth_file.write_text(
        "2026-09-07T09:58:00,admin,192.168.1.50,FAILURE\n"
        "2026-09-07T09:59:00,admin,192.168.1.50,FAILURE\n"
        "2026-09-07T10:00:00,admin,192.168.1.50,SUCCESS\n"
    )

    events = parse_auth_log(auth_file)

    assert len(events) == 3

    assert events[0]["event_type"] == "authentication"

    assert events[0]["username"] == "admin"

    assert events[0]["source_ip"] == "192.168.1.50"

    assert events[0]["authentication_result"] == "FAILURE"

    assert events[0]["severity"] == "LOW"

    assert events[2]["authentication_result"] == "SUCCESS"

    assert events[2]["severity"] == "INFO"