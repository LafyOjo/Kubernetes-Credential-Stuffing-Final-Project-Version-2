from fastapi import APIRouter, Depends

from ..security import validate_api_key, get_security_metrics

metrics_router = APIRouter()


@metrics_router.get("/")
def get_metrics_endpoint(api_key: str = Depends(validate_api_key)):
    return get_security_metrics()
