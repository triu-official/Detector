import multiprocessing
import os
import signal

bind = '0.0.0.0:5000'
workers = int(os.getenv('GUNICORN_WORKERS', max((2 * multiprocessing.cpu_count()) + 1, 3)))
threads = int(os.getenv('GUNICORN_THREADS', '2'))
timeout = int(os.getenv('GUNICORN_TIMEOUT', '45'))
graceful_timeout = int(os.getenv('GUNICORN_GRACEFUL_TIMEOUT', '30'))
accesslog = '-'
errorlog = '-'


def worker_int(_worker):
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
