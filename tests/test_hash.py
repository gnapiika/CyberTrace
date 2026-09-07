import hashlib

from utils.hash_utils import calculate_sha256


def test_calculate_sha256(tmp_path):
    # Create a temporary evidence file
    test_file = tmp_path / "evidence.txt"
    content = "CyberTrace test evidence"
    test_file.write_text(content)

    # Calculate the hash using our CyberTrace utility
    result = calculate_sha256(test_file)

    # Calculate the expected hash independently
    expected = hashlib.sha256(content.encode()).hexdigest()

    # Verify both hashes match
    assert result == expected