# CloudGuard Gunicorn Configuration
import multiprocessing

bind = "127.0.0.1:5000"
workers = multiprocessing.cpu_count() * 2 + 1
threads = 2
worker_class = "gthread"
timeout = 120
keepalive = 5

accesslog = "/var/log/cloudguard/gunicorn_access.log"
errorlog = "/var/log/cloudguard/gunicorn_error.log"
loglevel = "info"

# Security: Never log request body or sensitive parameters
capture_output = True

