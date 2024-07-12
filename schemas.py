from pydantic import BaseModel,EmailStr
from datetime import datetime




class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

    class config:
        from_attribute = True

class UserBase(BaseModel):
    email: EmailStr
    password: str

class User(BaseModel):
    username: str
    email: EmailStr
    id: int
    created_at: datetime

    class config:
        from_attribute = True