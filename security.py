from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext
import jwt
from pydantic import BaseModel
from typing import Union

SECRET_KEY = "1d4e1791104e9b4418a26c7a5cd330f19ab1d953f33637f35d0f8d1373b64f26"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    id: Union[int, None] = None


def create_access_token(data: dict, expires_delta: Union[int, None] = ACCESS_TOKEN_EXPIRE_MINUTES):
    expires_delta = timedelta(minutes=expires_delta)
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])