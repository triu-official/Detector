from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect


db = SQLAlchemy()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=["60/minute"])
