from typing import Union
from uuid import UUID
from pydantic import BaseModel, EmailStr, Field


class TokenSchema(BaseModel):
    access_token: str
    refresh_token: str


class UserLoginForm(BaseModel):
    username: str
    password: str


class TokenPayload(BaseModel):
    id: str = None
    email: str = None
    exp: int = None


class UserAuth(BaseModel):
    email: str = Field(..., description="user email")
    password: str = Field(..., min_length=8, max_length=24,
                          description="user password")


class UserOut(BaseModel):
    id: UUID
    email: str


class SystemUser(UserOut):
    password: str
    token: str


class LoggedOutMessage(BaseModel):
    message: str


MeResponse = Union[UserOut, LoggedOutMessage]


class UserSchema(BaseModel):
    email: EmailStr
    password: str

    class Config:
        orm_mode = True
