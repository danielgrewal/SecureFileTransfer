import pytest
from src.client import client

def test_invalid_creds():
   """Tests that authentication fails with invalid credentials and that an appropriate error message is displayed."""

   username = input("Enter username: ")
   password = input("Enter password: ")

   # Attempt to authenticate with provided credentials
   with pytest.raises(Exception) as e:  # Expect an exception on failed authentication
       result = client.authenticate(username, password)

   # Assert that the error message indicates invalid credentials
   assert "Invalid authentication credentials." in client.errorMsg

