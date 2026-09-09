from parsers.usb_parser import parse_usb_activity


def test_parse_usb_activity(tmp_path):

    usb_file = tmp_path / "usb_events.csv"

    usb_file.write_text(
        "timestamp,action,device_id,device_name,file_path,username\n"
        "2026-09-07T10:15:00,CONNECT,USB001,SanDisk USB,,admin\n"
        "2026-09-07T10:16:00,COPY,USB001,SanDisk USB,C:\\Users\\admin\\Documents\\secret.pdf,admin\n"
        "2026-09-07T10:20:00,DISCONNECT,USB001,SanDisk USB,,admin\n"
    )

    events = parse_usb_activity(usb_file)

    assert len(events) == 3

    assert events[0]["event_type"] == "usb"

    assert events[0]["usb_action"] == "CONNECT"

    assert events[1]["usb_action"] == "COPY"

    assert events[1]["device_id"] == "USB001"

    assert "secret.pdf" in events[1]["file_path"]

    assert events[2]["usb_action"] == "DISCONNECT"