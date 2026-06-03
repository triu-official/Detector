from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from threading import Lock

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect
from redis import Redis
from redis.exceptions import RedisError

db = SQLAlchemy()
csrf = CSRFProtect()
login_manager = LoginManager()
migrate = Migrate()
limiter = Limiter(key_func=get_remote_address, default_limits=[])


class NullRedis:
    def get(self, *_args, **_kwargs):
        return None

    def setex(self, *_args, **_kwargs):
        return False

    def delete(self, *_args, **_kwargs):
        return 0

    def ping(self):
        return False


class RedisProxy:
    def __init__(self) -> None:
        self._client: Redis | NullRedis = NullRedis()

    def configure(self, url: str) -> None:
        if not url:
            self._client = NullRedis()
            return
        try:
            client = Redis.from_url(url, decode_responses=True)
            client.ping()
            self._client = client
        except RedisError:
            self._client = NullRedis()

    def get(self, *args, **kwargs):
        return self._client.get(*args, **kwargs)

    def setex(self, *args, **kwargs):
        return self._client.setex(*args, **kwargs)

    def delete(self, *args, **kwargs):
        return self._client.delete(*args, **kwargs)

    def ping(self):
        return self._client.ping()


redis_client = RedisProxy()
error_buffer: deque[dict[str, str]] = deque(maxlen=50)
_error_lock = Lock()


@dataclass
class RuntimeState:
    last_error: dict[str, str] | None = None
    model_loaded: bool = False
    last_cleanup_at: float = 0.0


runtime_state = RuntimeState()


def configure_redis(url: str) -> None:
    redis_client.configure(url)


def record_error(message: str, *, path: str = "", error_type: str = "server_error") -> None:
    payload = {"message": message, "path": path, "type": error_type}
    runtime_state.last_error = payload
    with _error_lock:
        error_buffer.appendleft(payload)
