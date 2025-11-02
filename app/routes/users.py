from app import schemas, model
from fastapi import APIRouter,Depends, UploadFile, File
from auth.auth import get_current_user
from app.db import get_db
from sqlalchemy.orm import Session
from app.cloud import upload_avatar



router = APIRouter()



@router.get("/User", response_model=schemas.userRead)
def get_user_info(current_user:model.User= Depends(get_current_user),db:Session= Depends(get_db)):
    return current_user


@router.put("/update", response_model= schemas.userRead)
def update_profile(data:schemas.userUpdate,current_user:model.User= Depends(get_current_user),db:Session= Depends(get_db)):
    updated_data= data.model_dump(exclude_unset= True)

    for field, value  in updated_data.items():
        setattr(current_user,field, value)
    db.commit()
    db.refresh(current_user)
    return current_user    
    
@router.post("/upload_pic")
def upload_picture(file: UploadFile = File (...),db:Session = Depends(get_db),current_user: model.User = Depends(get_current_user)):

    avatar_url = upload_avatar(file.file)
    current_user.avatar_url = avatar_url
    db.commit()
    db.refresh(current_user)
    return current_user
