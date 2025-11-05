from fastapi import FastAPI
from auth.routes import router as auth_router
from auth.auth import get_password_hash
from contextlib import asynccontextmanager
from app.db import engine,Base,Sessionlocal
from app.model import Role,User
from app.routes.users import router as users_router
from app.routes.document import router as document_router
from datetime import datetime, timezone
from fastapi.middleware.cors import CORSMiddleware


@asynccontextmanager
async def lifespan(app:FastAPI):
    Base.metadata.create_all(bind=engine)
    db = Sessionlocal()
    try:
        plainpassword = "kaliian"
        superadminemail ="kamauian3522@gmail.com"

        hashedpassword = get_password_hash(plainpassword)
        superadmin_role = db.query(Role).filter(Role.name == "superadmin").first()
        if not superadmin_role:
            superadmin_role = Role(name = "superadmin")
            db.add(superadmin_role)
            db.commit()
            db.refresh(superadmin_role)

        superadmin= db.query(User).filter(User.email == superadminemail).first()
        if not superadmin:
            superadmin  = User(
                name = "System Owner",
                password = hashedpassword,
                email = superadminemail,
                avatar_url = None,
                bio = None,
                created_at = datetime.now(timezone.utc)
            )
            superadmin.roles.append(superadmin_role)
            db.add(superadmin)
            db.commit()
            db.refresh(superadmin)
        else:
            if superadmin_role not in superadmin.roles:
                superadmin.roles.append(superadmin_role)
                db.commit()
    except Exception as e:
        print(f"Error creating superadmin {e}")
    finally:
        db.close()
    yield

app = FastAPI(lifespan=lifespan)
app.include_router(auth_router, prefix="/auth", tags =["users"])
app.include_router(users_router, prefix="/profile", tags = ["profile"])
app.include_router(document_router, prefix="/files", tags=["files"])


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://lovafiles-dash.vercel.app/"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
