import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Methodist Church Kenya AI Assistant"
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./methodist_church.db")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # JWT authentication details
    SECRET_KEY: str = os.getenv("SECRET_KEY", "supersecretkeyforchurchaiassistant")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day

    class Config:
        env_file = ".env"

settings = Settings()
