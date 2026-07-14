from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
csrf = CSRFProtect()
# Note: In-memory storage is okay for local/dev use only.
# For production, you may configure REDIS_URL in environment variables and uncomment the storage param below.
# storage_uri = os.getenv("REDIS_URL", "memory://")
limiter = Limiter(key_func=get_remote_address, default_limits=[])
