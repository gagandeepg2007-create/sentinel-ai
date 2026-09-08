from pydantic_settings import BaseSettings
from pymongo import MongoClient
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VigilX_ML_Config")

class Settings(BaseSettings):
    MONGO_URI: str = "mongodb://localhost:27017/"
    MONGO_DB_NAME: str = "sentinel_raw_telemetry"

    class Config:
        env_file = ".env"

settings = Settings()

try:
    mongo_client = MongoClient(settings.MONGO_URI)
    db = mongo_client[settings.MONGO_DB_NAME]
    logger.info(f"[*] FastAPI ML Compute Layer attached to cluster: [{settings.MONGO_DB_NAME}]")
except Exception as e:
    logger.error(f"[!] Critical Connection Error on MongoDB Cluster Socket: {str(e)}")
    raise e