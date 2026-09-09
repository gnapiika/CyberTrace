from parsers.file_parser import parse_file_activity


def test_parse_file_activity(tmp_path):

    file_activity = tmp_path / "file_activity.csv"

    file_activity.write_text(
        "timestamp,action,path,username\n"
        "2026-09-07T10:05:00,CREATE,C:\\Users\\admin\\Downloads\\report.pdf,admin\n"
        "2026-09-07T10:07:00,EXECUTE,C:\\Users\\admin\\Downloads\\report.pdf,admin\n"
        "2026-09-07T10:10:00,DELETE,C:\\Users\\admin\\Downloads\\report.pdf,admin\n"
    )

    events = parse_file_activity(file_activity)

    assert len(events) == 3

    assert events[0]["event_type"] == "file"

    assert events[0]["file_action"] == "CREATE"

    assert events[1]["file_action"] == "EXECUTE"

    assert events[2]["file_action"] == "DELETE"

    assert events[0]["username"] == "admin"

    assert "report.pdf" in events[0]["file_path"]