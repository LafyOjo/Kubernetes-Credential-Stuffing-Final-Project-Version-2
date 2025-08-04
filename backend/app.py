import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List

import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException, status, Header, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, BaseSettings, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor


class Settings(BaseSettings):
    """Loads environment variables from a .env file."""
    DATABASE_URL: str = "sqlite:///./sql_app.db"
    SECRET_KEY: str = "a_very_secret_key_that_should_be_changed"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    API_KEY: str = "mysecretapikey"
    ANOMALY_DETECTION_ENABLED: bool = True
    ANOMALY_MODEL: str = "isolation_forest"

    class Config:
        env_file = ".env"

settings = Settings()


engine = create_engine(
    settings.DATABASE_URL, 
    connect_args={"check_same_thread": False} # Needed for SQLite
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean(), default=True)


# Shared properties
class UserBase(BaseModel):
    email: EmailStr

# Properties to receive via API on creation
class UserCreate(UserBase):
    password: str

# Properties to return to client
class UserInDB(UserBase):
    id: int
    is_active: bool

    class Config:
        orm_mode = True

# Additional properties to return to client
class User(UserInDB):
    pass

# Token Schema
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# --- Password Hashing ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

# --- JWT Token Handling ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

# --- Credential Stuffing Detection ---
FAILED_ATTEMPTS: Dict[str, Dict[str, Any]] = {}

def log_failed_attempt(ip: str, reason: str = "invalid_credentials"):
    now = datetime.utcnow()
    if ip not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[ip] = {"count": 0, "timestamps": []}
    
    FAILED_ATTEMPTS[ip]["count"] += 1
    FAILED_ATTEMPTS[ip]["timestamps"].append(now)
    FAILED_ATTEMPTS[ip]["last_reason"] = reason

def is_ip_blocked(ip: str) -> bool:
    if ip not in FAILED_ATTEMPTS:
        return False
    
    now = datetime.utcnow()
    one_minute_ago = now - timedelta(minutes=1)
    FAILED_ATTEMPTS[ip]["timestamps"] = [ts for ts in FAILED_ATTEMPTS[ip]["timestamps"] if ts > one_minute_ago]
    FAILED_ATTEMPTS[ip]["count"] = len(FAILED_ATTEMPTS[ip]["timestamps"])

    if FAILED_ATTEMPTS[ip]["count"] > 10:
        return True
    return False

def get_security_metrics():
    blocked_ips = [ip for ip, data in FAILED_ATTEMPTS.items() if data.get("count", 0) > 10]
    return {
        "total_failed_attempts": sum(data["count"] for data in FAILED_ATTEMPTS.values()),
        "currently_blocked_ips": len(blocked_ips),
        "failed_attempts_by_ip": FAILED_ATTEMPTS
    }

# --- Anomaly Detection Model ---
class AnomalyDetector:
    def __init__(self, algo: str = "isolation_forest"):
        rng = np.random.default_rng(42)
        X = rng.uniform(low=[5], high=[50], size=(100, 1))
        
        if algo == "lof":
            self.model = LocalOutlierFactor(novelty=True, contamination=0.1)
        else:
            self.model = IsolationForest(contamination=0.1, random_state=42)
            
        self.model.fit(X)

    def score(self, value: float) -> int:
        return int(self.model.predict([[value]])[0])

anomaly_detector = AnomalyDetector(settings.ANOMALY_MODEL)


def get_user(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def create_user(db: Session, user: UserCreate):
    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    user = get_user_by_email(db, email=email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user



def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

def validate_api_key(api_key: str = Header(None, alias="X-API-Key")):
    if api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    return api_key



# --- Auth Router ---
auth_router = APIRouter()

@auth_router.post("/register", response_model=User)
def register_user_endpoint(user_in: UserCreate, db: Session = Depends(get_db)):
    db_user = get_user_by_email(db, email=user_in.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    return create_user(db=db, user=user_in)

@auth_router.post("/login", response_model=Token)
def login_for_access_token_endpoint(
    request: Request,
    db: Session = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends()
):
    client_ip = request.client.host
    if is_ip_blocked(client_ip):
        raise HTTPException(status_code=429, detail="Too many failed login attempts.")

    user = authenticate_user(db, email=form_data.username, password=form_data.password)
    if not user:
        log_failed_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Shop Router ---
shop_router = APIRouter()
PRODUCTS = [{"id": 1, "name": "Classic Wool Socks", "price": 12.99}, {"id": 2, "name": "Sport Ankle Socks", "price": 8.50}]
CARTS: dict[int, list] = {}

@shop_router.get("/products", response_model=List[dict])
def get_products_endpoint():
    return PRODUCTS

@shop_router.post("/cart", status_code=201)
def add_to_cart_endpoint(
    item: dict,
    current_user: User = Depends(get_current_user),
    x_reauth_password: str = Header(None),
    db: Session = Depends(get_db)
):
    if not authenticate_user(db, email=current_user.email, password=x_reauth_password):
        raise HTTPException(status_code=401, detail="Re-authentication failed")

    if current_user.id not in CARTS:
        CARTS[current_user.id] = []
    CARTS[current_user.id].append(item)
    return {"message": "Item added", "cart": CARTS[current_user.id]}

@shop_router.get("/cart", response_model=List[dict])
def get_cart_endpoint(current_user: User = Depends(get_current_user)):
    return CARTS.get(current_user.id, [])

# --- Metrics Router ---
metrics_router = APIRouter()

@metrics_router.get("/")
def get_metrics_endpoint(api_key: str = Depends(validate_api_key)):
    return get_security_metrics()



app = FastAPI(title="APIShield+ Backend")

# --- NEW: Startup event to create initial users ---
@app.on_event("startup")
def on_startup():
    # Create database tables
    Base.metadata.create_all(bind=engine)
    
    # Seed initial user accounts
    db = SessionLocal()
    try:
        # Check for Alice
        alice = get_user_by_email(db, email="alice@example.com")
        if not alice:
            alice_in = UserCreate(email="alice@example.com", password="password123")
            create_user(db, user=alice_in)
            print("INFO:     Created demo user: alice@example.com")

        # Check for Ben
        ben = get_user_by_email(db, email="ben@example.com")
        if not ben:
            ben_in = UserCreate(email="ben@example.com", password="strongPassword!@#")
            create_user(db, user=ben_in)
            print("INFO:     Created demo user: ben@example.com")
    finally:
        db.close()


# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security Middleware
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

# Include API Routers
app.include_router(auth_router, prefix="/auth", tags=["auth"])
app.include_router(shop_router, prefix="/shop", tags=["shop"])
app.include_router(metrics_router, prefix="/metrics", tags=["metrics"])

@app.get("/")
def read_root():
    return {"message": "Welcome to the APIShield+ Backend for the University of Essex MSc Project"}
