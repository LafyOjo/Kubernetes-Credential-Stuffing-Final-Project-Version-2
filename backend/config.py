from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""
    DATABASE_URL: str = "sqlite:///./sql_app.db"
    SECRET_KEY: str = "a_very_secret_key_that_should_be_changed"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    API_KEY: str = "mysecretapikey"
    ANOMALY_DETECTION_ENABLED: bool = True
    ANOMALY_MODEL: str = "isolation_forest"

    model_config = SettingsConfigDict(env_file=".env")

settings = Settings()
