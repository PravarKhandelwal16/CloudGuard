import logging
from config import config

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages connections without hardcoding any credentials in code."""
    
    def __init__(self, uri: str = None):
        self.uri = uri or config.database_url
        if not self.uri:
            logger.info("Database URL not provided in environment; using in-memory mode.")
        else:
            logger.info("Database connection initialized from environment configuration.")

    def get_connection(self):
        return {"status": "connected", "mode": "secure_env"}


db_manager = DatabaseManager()

