from typing import List

from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session

from ..schemas import User
from ..database import get_db
from ..security import get_current_user
from .. import crud

shop_router = APIRouter()

PRODUCTS = [
    {"id": 1, "name": "Classic Wool Socks", "price": 12.99},
    {"id": 2, "name": "Sport Ankle Socks", "price": 8.50},
]
CARTS: dict[int, list] = {}


@shop_router.get("/products", response_model=List[dict])
def get_products_endpoint():
    return PRODUCTS


@shop_router.post("/cart", status_code=201)
def add_to_cart_endpoint(
    item: dict,
    current_user: User = Depends(get_current_user),
    x_reauth_password: str = Header(None),
    db: Session = Depends(get_db),
):
    if not crud.authenticate_user(db, email=current_user.email, password=x_reauth_password):
        raise HTTPException(status_code=401, detail="Re-authentication failed")

    if current_user.id not in CARTS:
        CARTS[current_user.id] = []
    CARTS[current_user.id].append(item)
    return {"message": "Item added", "cart": CARTS[current_user.id]}


@shop_router.get("/cart", response_model=List[dict])
def get_cart_endpoint(current_user: User = Depends(get_current_user)):
    return CARTS.get(current_user.id, [])
