from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"
    RP_ID: str = "localhost"
    RP_NAME: str = "FIDO2 Demo RP"
    ALLOWED_ORIGINS: str = "http://localhost:8080"
    JWT_SECRET: str
    ENV: str = "dev"

    @property
    def allowed_origins_list(self) -> List[str]:
        return [o.strip() for o in self.ALLOWED_ORIGINS.split(",") if o.strip()]

settings = Settings()
