import pytest
from uuid import uuid4
from src.client import client

@pytest.mark.asyncio
async def async_authenticate(username, password): # async wrapper
    return client.authenticate(username, password)

@pytest.mark.asyncio
async def test_invalid_auth():

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

@pytest.mark.asyncio
async def test_valid_auth():

    """Tests that authentication fails with invalid credentials and that an appropriate error message is displayed."""
    
    print("TESTING AUTH WITH VALID CREDS")

    username = "admin"
    password = "root"

    try:
        # Attempt to authenticate with provided credentials
        access_token, errorMsg = await async_authenticate(username, password)

    except Exception as e:
        # Assert the error message indicates invalid credentials
        assert "Invalid authentication credentials." in str(e)

@pytest.mark.asyncio
async def test_valid_verification():

  username = "usman"
  password = "mypass"  

  access_token = await async_authenticate(username, password)

  headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

  assert client.is_valid_responder(username, headers) is True

@pytest.mark.asyncio
async def test_invalid_verification():

  username = "usman"  

  access_token = uuid4() # generating fake token
  
  headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

  assert client.is_valid_responder(username, headers) is False

@pytest.mark.asyncio
async def test_invalid_startSession():

    username = "admin"  
    password = "root"

    access_token = await async_authenticate(username, password) # get token

    headers = {"Accept": "application/json",
                "Authorization": f"Bearer {access_token}"}

    result = client.start_session("angad", 2, 8888, headers)

    return access_token, result

    assert result is not None

@pytest.mark.asyncio
async def test_invalid_endSesson():

    access_token = uuid4() # generating fake token
    
    headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

    flag = False
    
    for i in range(1, 100):
        if client.close_session(i, headers) is True:
            flag = True
            break
    
    assert flag is False # unauthorized user cannot end a session