import pytest
import src.client.client

def test_invalid_creds():
    """Tests that authentication fails with invalid credentials and that an appropirate error message is displayed."""

    result = authenticate("non-existent", "notapass")

    # Attempt to authenticate with invalid credentials
    with pytest.raises(Exception):  # Expect an exception on failed authentication
        result = authenticate("non-existent", "notapass")

    assert "Invalid authentication credentials." in captured
