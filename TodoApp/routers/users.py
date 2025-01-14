from typing import Annotated

from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy.orm import Session

from fastapi import APIRouter, Depends, HTTPException, status

from .auth import bcrypt_context, get_current_user

router = APIRouter(prefix="/users", tags=["users"])

bcrypt_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class PasswordChangeRequest(BaseModel):
    old_password: str
    new_password: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]


@router.get("/", status_code=status.HTTP_200_OK)
async def get_user(user: user_dependency, db: db_dependency):
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication Failed.")
    return db.query(Users).filter(Users.id == user.get("id")).all()


@router.put("/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    user: user_dependency,
    db: db_dependency,
    password_change_request: PasswordChangeRequest,
):
    if user is None:
        raise HTTPException(status_code=404, detail="Authentication Failed.")
    user_model = db.query(Users).filter(Users.id == user.get("id")).first()
    if user_model is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if not bcrypt_context.verify(
        password_change_request.old_password, user_model.hashed_password
    ):
        raise HTTPException(status_code=400, detail="Incorrect Old Password.")
    user_model.hashed_password = bcrypt_context.hash(
        password_change_request.new_password
    )
    db.commit()
