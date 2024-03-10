from datetime import datetime, timezone, timedelta
from typing import Annotated
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

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

def get_user(username: str, password: str):
    
    user = User(username = username, password_hash = password)
    # if not user:
    #     return False
    # if not verify_password(password, user.hashed_password):
    #     return False
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

@app.post(TOKEN_URL)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]) -> Token:
   
    user = get_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_token(data = { "sub": user.username })
    return Token(access_token=access_token, token_type="bearer")

@app.get("/items/")
async def read_items(token:str = Depends(oauth2_scheme)):
    return {"protected_data": token}
