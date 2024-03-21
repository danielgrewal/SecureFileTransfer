import pytest
from uuid import uuid4
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

    headers = {"Accept": "application/json",
                "Authorization": f"Bearer {access_token}"}

    result = client.start_session("angad", 2, 8888, headers)

    assert result is None

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

@pytest.mark.asyncio
async def test_auth_sqlInjection():

    username = "angad' # "
    password = ""

    access_token = await async_authenticate(username, password)
    assert access_token is None
