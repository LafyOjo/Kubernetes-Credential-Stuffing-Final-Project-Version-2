import time
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

from .config import settings
from .database import get_db
from .models import User
from .schemas import TokenData

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
        "failed_attempts_by_ip": FAILED_ATTEMPTS,
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


# --- Dependencies ---
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
    user = db.query(User).filter(User.email == token_data.email).first()
    if user is None:
        raise credentials_exception
    return user


def validate_api_key(api_key: str = Header(None, alias="X-API-Key")):
    if api_key != settings.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API Key")
    return api_key
