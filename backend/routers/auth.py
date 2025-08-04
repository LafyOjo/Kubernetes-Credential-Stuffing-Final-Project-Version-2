from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from .. import crud
from ..schemas import UserCreate, User, Token
from ..database import get_db
from ..security import create_access_token, log_failed_attempt, is_ip_blocked

auth_router = APIRouter()


@auth_router.post("/register", response_model=User)
def register_user_endpoint(user_in: UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=user_in.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return crud.create_user(db=db, user=user_in)


@auth_router.post("/login", response_model=Token)
def login_for_access_token_endpoint(
    request: Request,
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    client_ip = request.client.host
    if is_ip_blocked(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed login attempts.")

    user = crud.authenticate_user(db, email=form_data.username, password=form_data.password)
    if not user:
        log_failed_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}
