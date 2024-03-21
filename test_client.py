import pytest
from uuid import uuid4
from src.client import client

@pytest.mark.asyncio
async def async_authenticate(username, password): # async wrapper
    print("Async is being called")
    return client.authenticate(username, password)

@pytest.mark.asyncio
async def test_invalid_auth():
    
    print("TESTING AUTH WITH INVALID CREDS")

    username = "angad"
    password = "newpass"

    try:
        # Attempt to authenticate with provided credentials
        access_token, errorMsg = await async_authenticate(username, password)

        if access_token is not None:
            print("\nAuthentication successful!")
            print("Access Token: ", access_token)

    except Exception as e:
        # Assert the error message indicates invalid credentials
        assert "Invalid authentication credentials." in str(e)
        print("\nAuthentication failed:", e)

@pytest.mark.asyncio
async def test_valid_auth():

    """Tests that authentication fails with invalid credentials and that an appropriate error message is displayed."""
    
    print("TESTING AUTH WITH VALID CREDS")

    username = "admin"
    password = "root"

    try:
        # Attempt to authenticate with provided credentials
        access_token, errorMsg = await async_authenticate(username, password)

        if access_token is not None:
            print("\nAuthentication successful!")
            print("Access Token: ", access_token)

    except Exception as e:
        # Assert the error message indicates invalid credentials
        assert "Invalid authentication credentials." in str(e)
        print("\nAuthentication failed:", e)

@pytest.mark.asyncio
async def test_valid_verification():

  username = "usman"
  password = "pass"  

  access_token = await async_authenticate(username, password)

  headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

  assert client.is_valid_responder(username, headers) is True

@pytest.mark.asyncio

async def test_invalid_verification():

  username = "usman"  

  access_token = uuid4() # generating unique token
  
  headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

  assert client.is_valid_responder(username, headers) is False