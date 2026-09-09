from parsers.process_parser import parse_process_activity


def test_parse_process_activity(tmp_path):

    process_file = tmp_path / "processes.csv"

    process_file.write_text(
        "timestamp,process_name,pid,parent_pid,username,executable_path\n"
        "2026-09-07T10:07:00,powershell.exe,4500,3200,admin,C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
        "2026-09-07T10:08:00,suspicious.exe,4600,4500,admin,C:\\Users\\admin\\Downloads\\suspicious.exe\n"
    )

    events = parse_process_activity(process_file)

    assert len(events) == 2

    assert events[0]["event_type"] == "process"

    assert events[0]["process_name"] == "powershell.exe"

    assert events[0]["pid"] == "4500"

    assert events[1]["parent_pid"] == "4500"

    assert events[1]["process_name"] == "suspicious.exe"

    assert events[1]["username"] == "admin"