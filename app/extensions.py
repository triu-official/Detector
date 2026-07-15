import os

from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
csrf = CSRFProtect()

# Limiter storage: memory:// for local dev
storage_uri = os.getenv("REDIS_URL", "memory://")
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],
    storage_uri=storage_uri,
)
