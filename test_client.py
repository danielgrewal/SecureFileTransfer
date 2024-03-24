import pytest
from uuid import uuid4

from test_server import encryption
from src.client import client

@pytest.mark.asyncio
async def async_authenticate(username, password): # async wrapper
    return client.authenticate(username, password)

@pytest.mark.asyncio
async def test_valid_auth():

    username = "angad"
    password = "newpass"

    try:
        # Attempt to authenticate with provided credentials
        result = await async_authenticate(username, password)
        assert result is not None

    except Exception as e:
        # Assert the error message indicates invalid credentials
        assert "Invalid authentication credentials." in str(e)

@pytest.mark.asyncio
async def test_invalid_auth():

    """Tests that authentication fails with invalid credentials and that an appropriate error message is displayed."""
    
    print("TESTING AUTH WITH VALID CREDS")

    username = "admin"
    password = "root"

    try:
        # Attempt to authenticate with provided credentials
        result = await async_authenticate(username, password)
        assert result is None

    except Exception as e:
        # Assert the error message indicates invalid credentials
        assert "Invalid authentication credentials." in str(e)

@pytest.mark.asyncio
async def test_valid_verification():

  username_initiator = "usman"
  password_initiator = "mypass"

  username_responder = "daniel" 

  access_token = await async_authenticate(username_initiator, password_initiator)

  headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

  assert client.is_valid_responder(username_responder, headers) is True

@pytest.mark.asyncio
async def test_invalid_verification1():

  username_responder = "angad" 
  
  access_token = uuid4() # generating fake token

  headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

  assert client.is_valid_responder(username_responder, headers) is False

@pytest.mark.asyncio
async def test_invalid_verification2():

  username_initiator = "usman"
  password_initiator = "mypass"

  username_responder = "admin" 

  access_token = await async_authenticate(username_initiator, password_initiator)

  headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

  assert client.is_valid_responder(username_responder, headers) is False

@pytest.mark.asyncio
async def test_invalid_verification3():

  username_initiator = "usman"
  password_initiator = "mypass"

  username_responder = "usman" 

  access_token = await async_authenticate(username_initiator, password_initiator)

  headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}

  assert client.is_valid_responder(username_responder, headers) is False

@pytest.mark.asyncio
async def test_invalid_startSession():

    access_token = uuid4() # generating fake token
    username = "angad"
    port = 8888

    headers = {"Accept": "application/json",
                "Authorization": f"Bearer {access_token}"}

    for j in [1,2]:
        result = client.start_session(username, j, port, headers)
        if result is not None:
            break

    assert result is None

@pytest.mark.asyncio
async def test_invalid_endSesson():

    access_token = uuid4() # generating fake token
    
    headers = {"Accept": "application/json",
               "Authorization": f"Bearer {access_token}"}
    
    result = client.close_session(3, headers) # session_id is known

    assert result is False # unauthorized user cannot end a session

@pytest.mark.asyncio
async def test_auth_sqlInjection():

    username = "angad' # "
    password = ""

    access_token = await async_authenticate(username, password)
    assert access_token is None

def test_all_encryption():
    encryption()