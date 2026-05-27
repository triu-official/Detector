from __future__ import annotations

from celery import Celery

from app import create_app
from app.config import CONFIG_MAP
from app.phishing.services import run_analysis


celery = Celery(__name__)



def init_celery(config_name: str | None = None) -> Celery:
    app = create_app(CONFIG_MAP.get(config_name or 'development'))
    celery.conf.update(
        broker_url=app.config['REDIS_URL'] or 'redis://redis:6379/0',
        result_backend=app.config['REDIS_URL'] or 'redis://redis:6379/0',
        task_ignore_result=False,
    )

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


@celery.task(name='detector.analyze_url_task')
def analyze_url_task(url: str) -> dict:
    app = create_app(CONFIG_MAP.get('development'))
    with app.app_context():
        return run_analysis(url, app.config).__dict__
