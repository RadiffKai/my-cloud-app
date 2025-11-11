from fastapi import APIRouter, Depends, status, HTTPException
from datetime import datetime, timezone, timedelta
from app import model, schemas
from app.db import get_db
from app.schemas import refreshRequest
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm
from auth.auth import (
    get_password_hash,
    authenticate_user,
    create_access_token,
    create_refresh_token,
    hash_refresh_token,
    decode_refresh_token,
    create_reset_token,
    verify_reset_token,
)
from fastapi_mail import MessageSchema, FastMail
from auth.email import conf
from fastapi.background import BackgroundTasks

router = APIRouter()


@router.post("/signup", response_model=schemas.userRead)
def signup(user: schemas.userCreate, db: Session = Depends(get_db)):
    # Optional: check for existing email
    existing = db.query(model.User).filter(model.User.email == user.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    hash_password = get_password_hash(user.password)
    db_user = model.User(
        name=user.name,
        email=user.email,
        password=hash_password,
        avatar_url=user.avatar_url,
        bio=user.bio,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    if user.roles:
        for role_name in user.roles:
            role = db.query(model.Role).filter(model.Role.name == role_name).first()
            if role:
                db_user.roles.append(role)
        db.commit()

    return db_user


@router.post("/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Expects application/x-www-form-urlencoded with fields:
      - username (we treat this as email)
      - password
    This matches the frontend sending:
      new URLSearchParams({ username: formData.email, password: formData.password })
    """
    # authenticate_user should accept (db, email, password) and return user or None
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    access_token = create_access_token(data={"sub": str(user.id)})
    refresh_token, jti, expires_at, orig_iat = create_refresh_token(user_id=user.id, sub=str(user.id))

    db_rt = model.RefreshToken(
        jti=jti,
        expires_at=expires_at,
        orig_iat=orig_iat,
        user_id=user.id,
        token_hash=hash_refresh_token(refresh_token),
    )
    db.add(db_rt)
    db.commit()

    # Return token + refresh token; frontend expects access_token & token_type
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post("/refresh", response_model=schemas.Token)
def refresh(token: refreshRequest, db: Session = Depends(get_db)):
    refresh_token = token.refresh_token
    payload = decode_refresh_token(refresh_token)
    if not payload:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    jti = payload.get("jti")
    user_id = payload.get("user_id")
    orig_iat = payload.get("orig_iat", payload.get("iat", datetime.now(timezone.utc).timestamp()))

    sessionstart = datetime.fromtimestamp(orig_iat, tz=timezone.utc)
    if sessionstart + timedelta(days=3) < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Session expired")

    db_token = db.query(model.RefreshToken).filter(model.RefreshToken.jti == jti).first()
    if not db_token or db_token.revoked or db_token.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Please login again")

    if db_token.token_hash != hash_refresh_token(refresh_token):
        db_token.revoked = True
        db.add(db_token)
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token reuse detected. Please login again")

    new_refresh_token, new_jti, new_expires_at, new_orig_iat = create_refresh_token(
        user_id=user_id, sub=str(user_id), orig_iat=orig_iat
    )

    db_token.revoked = True
    db_token.replaced_by = new_jti
    db.add(db_token)
    db.commit()

    new_db_token = model.RefreshToken(
        jti=new_jti,
        user_id=user_id,
        expires_at=new_expires_at,
        orig_iat=new_orig_iat,
        token_hash=hash_refresh_token(new_refresh_token),
    )
    db.add(new_db_token)
    db.commit()

    access_token = create_access_token(data={"sub": str(user_id)})
    return {"access_token": access_token, "token_type": "bearer", "refresh_token": new_refresh_token}


@router.post("/logout", response_model=dict)
def logout(token: schemas.Logout, db: Session = Depends(get_db)):
    token_str = token.refresh_token
    if not token_str:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Token required to logout")
    payload = decode_refresh_token(token_str)
    if not payload:
        return {"msg": "Logged Out Successfully"}

    # FIX: use string key "jti"
    jti = payload.get("jti")
    if not jti:
        return {"msg": "Logged Out Successfully"}

    db_token = db.query(model.RefreshToken).filter(model.RefreshToken.jti == jti).first()
    if db_token:
        db_token.revoked = True
        db.add(db_token)
        db.commit()

    return {"msg": "Logged out Successfully"}


@router.post("/requestpasswordreset")
async def sendresetemail(request: schemas.resetRequest, background_task: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(model.User).filter(model.User.email == request.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    token = create_reset_token(user.email)

    # Consider using a front-end URL rather than localhost if deployed
    reset_link = f"https://your-frontend-domain.com/reset-password?token={token}"
    message = MessageSchema(
        subject="Password Reset Request",
        recipients=[user.email],
        body=f"Click the link to reset your password: {reset_link}",
        subtype="plain",
    )
    fm = FastMail(conf)
    background_task.add_task(fm.send_message, message)
    return {"msg": "Password reset email sent"}


@router.post("/passwordreset")
def passwordreset(data: schemas.passwordReset, db: Session = Depends(get_db)):
    user = verify_reset_token(data.token, db)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    hashed_password = get_password_hash(data.new_password)
    user.password = hashed_password
    db.add(user)
    db.commit()
    return {"msg": "Password reset successful"}
