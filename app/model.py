from sqlalchemy import Column, Integer, String, ForeignKey, Table,Boolean,DateTime
from app.db import Base
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import relationship


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    avatar_url = Column(String)
    bio = Column(String)
    roles = relationship("Role", secondary="user_roles", back_populates="users")
    created_at = Column(DateTime, default= datetime.now(timezone.utc) )

    files = relationship("fileModel", back_populates="user")

file_tags = Table(
    "file_tags",
    Base.metadata,
    Column("file_id", Integer, ForeignKey("files.id", ondelete="CASCADE")),
    Column("tag_id", Integer, ForeignKey("tags.id", ondelete="CASCADE"))
)

class Tag(Base):
    __tablename__ = "tags"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)

    files = relationship("fileModel", secondary="file_tags", back_populates="tags")




class fileModel(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True,index=True)
    filename = Column(String,nullable=False)
    file_url= Column(String,nullable=True)
    size = Column(Integer)
    uploaded_at = Column(DateTime,default=lambda:datetime.now(timezone.utc))
    user_id = Column(Integer,ForeignKey("users.id",ondelete= "CASCADE"))

    user = relationship("User", back_populates="files")
    tags = relationship("Tag", secondary="file_tags", back_populates="files")




user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE")),
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"))
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE")),
    Column("permission_id", Integer, ForeignKey("permissions.id", ondelete="CASCADE"))
)

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    users = relationship("User", secondary="user_roles", back_populates="roles")
    permissions = relationship("Permission", secondary= "role_permissions", back_populates="roles")


class Permission(Base):
    __tablename__ = "permissions"
    id  = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)    
    roles = relationship("Role", secondary="role_permissions", back_populates="permissions")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer,ForeignKey("users.id", ondelete="CASCADE"))
    token_hash = Column(String,nullable=False)
    jti = Column(String,index=True,nullable=False)
    expires_at = Column(DateTime, default=lambda: datetime.now(timezone.utc) + timedelta(days=1), nullable=False)
    orig_iat = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    revoked = Column(Boolean,default=False)
    replaced_by = Column(String,nullable=True)

    user = relationship("User", backref="refresh_tokens")