from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from app.model import User
import os
from fastapi import Depends, HTTPException, status
from typing import Optional
from uuid import uuid4
import hashlib
from sqlalchemy.orm import Session
from app.db import get_db

algorithm = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
SECRET_KEY = os.getenv("SECRET_KEY","default_secret_key")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY","default_refresh_secret_key")
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 1

def get_password_hash(password:str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password:str, hashed_password:str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expires_at = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes= ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp":int(expires_at.timestamp())})
    jwt_token= jwt.encode(to_encode, SECRET_KEY, algorithm=algorithm)
    return jwt_token

def decode_access_token(token:str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[algorithm])
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token",
        )
    
def hash_refresh_token(token:str):
    return hashlib.sha256(token.encode()).hexdigest()

def create_refresh_token(user_id:int, sub:str, orig_iat:Optional[datetime] = None, expires_days:int = REFRESH_TOKEN_EXPIRE_DAYS):
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days= expires_days)
    jti = str(uuid4())
    if orig_iat is None:
        orig_iat = now

    payload = {
        "jti":jti,
        "orig_iat":int(orig_iat.timestamp()),
        "expires_at":int(expires_at.timestamp()),
        "iat":int(now.timestamp()),
        "sub": str(sub),
        "user_id":user_id
    }
    token = jwt.encode(payload,REFRESH_SECRET_KEY, algorithm=algorithm)
    return token,jti,expires_at,orig_iat

def decode_refresh_token(token:str):
    try:
        return jwt.decode(token,REFRESH_SECRET_KEY,algorithms=[algorithm])
    except JWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,detail="Invalid refresh token")
    
def authenticate_user(db:Session, email:str, password:str):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password,user.password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,detail="Invalid email or password")
    return user

def get_current_user(token:str = Depends(oauth2_scheme),db:Session = Depends(get_db)):
    payload = decode_access_token(token)
    user_id:int = payload.get("sub")
    if user_id is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,detail="Invalid token")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,detail="User not Found")
    return user
    
def user_has_roles(user:User, role_names:str)-> bool:
    return any (role.name == role_names for role in user.roles)

def user_has_permission(user:User, permission_names)->bool:
    return any(
        permission.name == permission_names
        for role in user.roles
        for permission in role.permissions
    )
def create_reset_token(email:str, expires_delta:Optional[timedelta] = None):
    expires_at = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode ={"sub":email, "exp": int(expires_at.timestamp())}
    token  = jwt.encode(to_encode, SECRET_KEY, algorithm= algorithm)
    return token

def verify_reset_token(token:str, db) -> str:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[algorithm])
        email:str = payload.get("sub")
        if email is None:
            return None
        user = db.query(User).filter(User.email == email).first()
        return user

    except JWTError:
        return None
    