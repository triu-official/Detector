from __future__ import annotations

import os
from typing import Any

from celery import Celery
from celery.result import AsyncResult
from flask import Flask

from app import create_app
from app.config import CONFIG_MAP
from app.phishing.services import run_analysis

celery = Celery("detector")


def init_celery(app: Flask) -> Celery:
    celery.conf.update(
        broker_url=app.config["CELERY_BROKER_URL"],
        result_backend=app.config["CELERY_RESULT_BACKEND"],
        task_ignore_result=False,
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_always_eager=app.config["CELERY_TASK_ALWAYS_EAGER"],
        task_eager_propagates=app.config["CELERY_TASK_EAGER_PROPAGATES"],
    )

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery


@celery.task(bind=True, name="detector.analyze_url_task")
def analyze_url_task(self, url: str) -> dict[str, Any]:
    app = create_app(CONFIG_MAP.get(os.getenv("FLASK_ENV", "development")))
    with app.app_context():
        result = run_analysis(url, app.config, persist=True)
    return {"analysis_id": result.analysis_id}


def get_job_state(job_id: str) -> AsyncResult:
    return AsyncResult(job_id, app=celery)


flask_env = os.getenv("FLASK_ENV", "development")
flask_app = create_app(CONFIG_MAP.get(flask_env, CONFIG_MAP["development"]))
init_celery(flask_app)
