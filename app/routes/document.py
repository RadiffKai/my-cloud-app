from fastapi import APIRouter, Depends, UploadFile, File, HTTPException,Query
from auth.auth import get_current_user
from app import schemas, model
from sqlalchemy.orm import Session
from app.db import get_db
from app.cloud import upload_file
from datetime import datetime, timezone
from typing import List, Optional

router = APIRouter()

@router.post("/uploadfile",response_model=schemas.fileRead)
def uploadFile(file:UploadFile = File(...), current_user:model.User = Depends(get_current_user), tags:Optional[List[str]] = Query(default= []), db:Session = Depends(get_db)):
    try:
        file_url = upload_file(file.file)
        new_file = model.fileModel(
            filename = file.filename,
            file_url = file_url,
            size = 0,
            user_id = current_user.id,
            uploaded_at = datetime.now(timezone.utc)
        )
        for tag_name in tags:
            tag = db.query(model.Tag).filter(model.Tag.name == tag_name).first()
            if not tag:
                tag = model.Tag(name=tag_name)
                db.add(tag)
                db.commit()
                db.refresh(tag)
            new_file.tags.append(tag)
        db.add(new_file)
        db.commit()
        db.refresh(new_file)

        return new_file
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File upload failed: {str(e)}")
    

@router.post("/tags", response_model= schemas.TagRead)
def createTag(tag:schemas.TagCreate, current_user:model.User = Depends(get_current_user), db:Session = Depends(get_db)):
    existing_tag = db.query(model.Tag).filter(model.Tag.name == tag.name).first()
    if existing_tag:
        raise HTTPException(status_code=400, detail="Tag already exists")
    new_tag = model.Tag(name=tag.name)
    db.add(new_tag)
    db.commit()
    db.refresh(new_tag)
    return new_tag


@router.get("/usersdocument")
def getUsersDocuments(current_user:model.User = Depends(get_current_user),db:Session = Depends(get_db)):
    files = db.query(model.fileModel).filter(model.fileModel.user_id == current_user.id).all()
    return files


@router.get("/searchfiles", response_model= List[schemas.fileRead])
def searchFiles(
    current_user:model.User = Depends(get_current_user),
    q:Optional[str] = Query(default= None, description ="Search filename"),
    tag: Optional[str] = Query(default= None, description= "Search by Tag"),
    db: Session = Depends(get_db)
):
    query = db.query(model.fileModel).filter(model.fileModel.user_id == current_user.id)
    if q:
        query = query.filter(model.fileModel.filename.ilike(f"%{q}%"))
    if tag:
        query = query.join(model.fileModel.tags).filter(model.Tag.name.ilike(f"%{tag}%"))
    
    files = query.all()
    return files