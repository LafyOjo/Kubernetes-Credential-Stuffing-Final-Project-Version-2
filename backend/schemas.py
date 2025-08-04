from typing import Optional
from pydantic import BaseModel, EmailStr


class UserBase(BaseModel):
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserInDB(UserBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True


class User(UserInDB):
    pass


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: Optional[str] = None
