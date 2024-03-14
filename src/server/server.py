from datetime import datetime, timezone, timedelta
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from Crypto.Random import get_random_bytes
from pydantic import BaseModel
from database import Database
from session import *
import base64


TOKEN_URL = "/authenticate"
TOKEN_EXPIRE_MIN = 60
SIGNATURE_KEY = "1c3d529fdf6fe91832ca1537607acace6b4810f780f1a7891f075db1a479e881"
SIGNATURE_ALGORITHM = "HS256"

password_context = CryptContext(schemes = ["bcrypt"], deprecated = "auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl = TOKEN_URL)

app = FastAPI()

class Token(BaseModel):
    access_token: str
    token_type: str

class User(BaseModel):
    username: str
    password_hash: str

def get_user(username: str):
    db = Database()
    db.connect()
    params = (username,)
    result = db.query("select username, password_hash from users where users.username = %s;", params)
    
    if not result:
        return False
    
    return User(username = result[0][0], password_hash = result[0][1])

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user.password_hash):
        return False

    return user

def hash_password(password):
    return password_context.hash(password)

def verify_password(password, hashed_password):
    return password_context.verify(password, hashed_password)

def create_token(data: dict):
    token_data = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes = TOKEN_EXPIRE_MIN)
    token_data.update({"exp": expire})
    encoded_jwt = jwt.encode(token_data, SIGNATURE_KEY, algorithm=SIGNATURE_ALGORITHM)
    return encoded_jwt

def extract_username(token: str) -> str:
    try:
        token_content = jwt.decode(token, SIGNATURE_KEY, algorithms=[SIGNATURE_ALGORITHM])
        subject = token_content.get("sub")
        return subject
    except JWTError as e:
        print(f"Unable to validate token: {e}")
        return None

@app.post(TOKEN_URL)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
   
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    else:
        access_token = create_token(data = { "sub": user.username })
        return Token(access_token=access_token, token_type="bearer")

@app.get("/sessions/")
async def check_sessions(request: Request, token:str = Depends(oauth2_scheme)):
    username = extract_username(token)
    if not username:
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail="Invalid access token."
        )
    sessions = get_outstanding_sessions(username)
    return { "sessions": sessions } 

@app.post("/validateuser/")
async def validate_user(request:Request, token:str = Depends(oauth2_scheme)):
    request_body = await request.json()
    sending_user = extract_username(token)
    if sending_user == request_body.get('username'):
        raise HTTPException(
            status_code = status.HTTP_400_BAD_REQUEST,
            detail="Error: Initiator and Responder cannot be the same user."
        )
    user = get_user(request_body.get('username'))
    if not user:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail="Username was not found."
        )
    return { "username": user.username } 

@app.post("/startsession/")
async def start_session(request:Request, token:str = Depends(oauth2_scheme)):
    request_body = await request.json()

    username_initiator = extract_username(token)
    username_responder = request_body.get('responder')
    role_initiator = request_body.get('role')
    address_initiator = request.client.host
    port_initiator = request_body.get('port')
    aes_key = get_random_bytes(32)  # Generate AES-256 key
    params = (username_initiator, username_responder, role_initiator, address_initiator, port_initiator, aes_key)
    session = create_session(params)
    return {"session_id": session[0], "aes_key": base64.b64encode(session[6]).decode('utf-8')}

@app.get("/joinsession/")
async def join_session(token:str = Depends(oauth2_scheme)):
    username_responder = extract_username(token)
    result = get_first_invite(username_responder)
    session_id = result[0]
    username_initiator = result[1]
    role_initiator = result[3]
    address = result[4]
    port = result[5] 
    aes_key = base64.b64encode(result[6]).decode('utf-8')

    return {
        "session_id": session_id,
        "username_initiator": username_initiator,
        "role_initiator": role_initiator,
        "address": address,
        "port": port,
        "aes_key": aes_key
    }





