import multiprocessing
import os

bind = "0.0.0.0:5000"
workers = int(os.getenv("GUNICORN_WORKERS", (2 * multiprocessing.cpu_count()) + 1))
threads = int(os.getenv("GUNICORN_THREADS", "2"))
timeout = int(os.getenv("GUNICORN_TIMEOUT", "30"))
accesslog = "-"
errorlog = "-"
