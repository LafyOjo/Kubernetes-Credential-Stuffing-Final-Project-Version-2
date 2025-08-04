import time
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from .config import settings
from .database import Base, engine, SessionLocal, get_db
from .security import anomaly_detector, log_failed_attempt
from .routers.auth import auth_router
from .routers.shop import shop_router
from .routers.metrics import metrics_router
from . import crud
from .schemas import UserCreate

app = FastAPI(title="APIShield+ Backend")


@app.on_event("startup")
def on_startup():
    # Create database tables
    Base.metadata.create_all(bind=engine)

    # Seed initial user accounts
    db = SessionLocal()
    try:
        alice = crud.get_user_by_email(db, email="alice@example.com")
        if not alice:
            alice_in = UserCreate(email="alice@example.com", password="password123")
            crud.create_user(db, user=alice_in)
            print("INFO:     Created demo user: alice@example.com")

        ben = crud.get_user_by_email(db, email="ben@example.com")
        if not ben:
            ben_in = UserCreate(email="ben@example.com", password="strongPassword!@#")
            crud.create_user(db, user=ben_in)
            print("INFO:     Created demo user: ben@example.com")
    finally:
        db.close()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    start_time = time.time()

    if settings.ANOMALY_DETECTION_ENABLED:
        request_feature = len(request.url.path)
        score = anomaly_detector.score(request_feature)
        if score == -1:
            log_failed_attempt(request.client.host, "anomaly_detected")

    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)

    return response


app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(shop_router, prefix="/shop", tags=["shop"])
app.include_router(metrics_router, prefix="/metrics", tags=["metrics"])


@app.get("/")
def read_root():
    return {"message": "Welcome to the APIShield+ Backend for the University of Essex MSc Project"}
