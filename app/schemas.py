from pydantic import BaseModel,ConfigDict,EmailStr,Field
from typing import List, Optional
from datetime import datetime

class userBase(BaseModel):
    name:str
    email:EmailStr
    avatar_url : Optional[str] = None
    bio:Optional[str] = None

class userCreate(userBase):
    password:str
    roles:Optional[List[str]]= Field(default_factory=lambda: ["user"]) 

class RoleRead(BaseModel):
    id:int
    name:str
    model_config = ConfigDict(from_attributes=True)

class userRead(userBase):
    id:int
    roles:List[RoleRead] = []
    model_config = ConfigDict(from_attributes=True)

class userUpdate(BaseModel):
    name:Optional[str] = None
    email:Optional[str] = None
    avatar_url : Optional[str] = None
    bio:Optional[str] = None

class Token(BaseModel):
    access_token: str
    refresh_token:str
    token_type:str

class Logout(BaseModel):
    refresh_token:str

class refreshRequest(BaseModel):
    refresh_token: str


class fileUpload(BaseModel):
    filename: str
    size:Optional[int]
    tags:Optional[list[str]] = Field(default_factory=list)

class TagRead(BaseModel):
    name:str
    model_config = ConfigDict(from_attributes=True)

class fileRead(BaseModel):
    filename:str
    uploaded_at:datetime
    user_id:int
    file_url:str
    tags:List[TagRead] = []
    model_config = ConfigDict(from_attributes=True)
 

class TagCreate(BaseModel):
    id:int
    name:str

class passwordReset(BaseModel):
    token:str
    new_password:str



class resetRequest(BaseModel):
    email:EmailStr