from flask import Flask, send_from_directory, abort, request, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import json
from typing import Callable, Any
from dotenv import load_dotenv
import os
import redis
from flask_cors import CORS
from urllib.parse import urlparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import time
import sys
import subprocess

# 加载环境变量
load_dotenv()

app = Flask(__name__)

# 加载配置
from config import Config
app.config.from_object(Config)

# 确保目录存在
for directory in [Config.RULES_DIR, Config.LOGS_DIR, Config.FONTS_DIR, Config.IMAGES_DIR]:
    directory.mkdir(exist_ok=True)

# 配置 CORS
CORS(app, origins=Config.ALLOWED_ORIGINS, methods=["GET"], allow_headers=["Origin", "Referer"])

# 配置结构化日志
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": record.created,
            "level": record.levelname,
            "message": record.msg,
            "module": record.module,
            "client_ip": getattr(record, "client_ip", "unknown"),
            "user_agent": getattr(record, "user_agent", "unknown"),
            "method": getattr(record, "method", "unknown"),
            "path": getattr(record, "path", "unknown"),
            "referer": getattr(record, "referer", "unknown"),
            "origin": getattr(record, "origin", "unknown")
        }
        return json.dumps(log_record)

def setup_logging():
    for log_type, filename in [("access", "access.log"), ("error", "error.log")]:
        handler = RotatingFileHandler(
            Config.LOGS_DIR / filename,
            maxBytes=Config.LOG_FILE_MAX_BYTES,
            backupCount=Config.LOG_FILE_BACKUP_COUNT,
        )
        handler.setFormatter(JSONFormatter())
        logger = logging.getLogger(log_type)
        logger.setLevel(logging.INFO if log_type == "access" else logging.ERROR)
        logger.addHandler(handler)

setup_logging()

# 配置 Redis 存储
redis_url = f"redis://:{os.getenv('REDIS_PASSWORD')}@{os.getenv('REDIS_HOST')}:{os.getenv('REDIS_PORT')}/0"

# 速率限制
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[f"{Config.RATE_LIMIT_REQUESTS} per {Config.RATE_LIMIT_WINDOW} seconds"],
    storage_uri=redis_url,
)

# 规范化 URL，移除尾随斜杠
def normalize_url(url: str) -> str:
    if not url:
        return ""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

# 验证装饰器（用户代理、请求方法、Referer 和 Origin）
def require_valid_request(resource_type: str = "rule") -> Callable:
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs) -> Any:
            client_ip = request.remote_addr
            user_agent = request.headers.get("User-Agent", "")
            method = request.method
            path = request.path
            referer = request.headers.get("Referer", "")
            origin = request.headers.get("Origin", "")

            # 规范化 Referer 和 Origin
            normalized_referer = normalize_url(referer)
            normalized_origin = normalize_url(origin)

            # 记录请求信息
            logging.getLogger("access").info(
                f"Request received for {resource_type}",
                extra={
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                    "method": method,
                    "path": path,
                    "referer": referer,
                    "origin": origin
                }
            )

            # 检查请求方法
            if method != "GET":
                logging.getLogger("error").error(
                    f"Method not allowed: {method}",
                    extra={
                        "client_ip": client_ip,
                        "user_agent": user_agent,
                        "method": method,
                        "path": path,
                        "referer": referer,
                        "origin": origin
                    }
                )
                abort(405)

            # 对于 rules 资源，检查 User-Agent
            if resource_type == "rule":
                if Config.ALLOWED_USER_AGENT_SUBSTRING not in user_agent:
                    logging.getLogger("error").error(
                        f"Forbidden: Invalid User-Agent '{user_agent}'",
                        extra={
                            "client_ip": client_ip,
                            "user_agent": user_agent,
                            "method": method,
                            "path": path,
                            "referer": referer,
                            "origin": origin
                        }
                    )
                    abort(403)
            # 对于字体和图片资源，检查 Referer 和 Origin
            else:
                valid_referer = normalized_referer in Config.ALLOWED_REFERERS
                valid_origin = normalized_origin in Config.ALLOWED_ORIGINS if normalized_origin else False

                if not (valid_referer or valid_origin):
                    logging.getLogger("error").error(
                        f"Forbidden: Invalid or missing Referer '{referer}' and Origin '{origin}'",
                        extra={
                            "client_ip": client_ip,
                            "user_agent": user_agent,
                            "method": method,
                            "path": path,
                            "referer": referer,
                            "origin": origin
                        }
                    )
                    abort(403)

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# 规则文件服务
@app.route("/rules/<filename>", methods=["GET"])
@require_valid_request(resource_type="rule")
@limiter.limit(f"{Config.RATE_LIMIT_REQUESTS}/{Config.RATE_LIMIT_WINDOW}seconds")
def serve_rule_file(filename: str) -> Response:
    client_ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    method = request.method
    path = request.path
    referer = request.headers.get("Referer", "")
    origin = request.headers.get("Origin", "")

    if not filename.endswith(".list"):
        logging.getLogger("error").error(
            f"Invalid file extension for '{filename}'",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        abort(404)

    filename = secure_filename(filename)
    file_path = Config.RULES_DIR / filename

    if not (file_path.is_file() and str(file_path).startswith(str(Config.RULES_DIR.resolve()))):
        logging.getLogger("error").error(
            f"File not found: '{filename}'",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        abort(404)

    try:
        logging.getLogger("access").info(
            f"Serving file '{filename}'",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        response = send_from_directory(Config.RULES_DIR, filename)
        response.headers["Cache-Control"] = "public, max-age=3600"
        response.headers["ETag"] = f"{file_path.stat().st_mtime}"
        return response
    except Exception as e:
        logging.getLogger("error").error(
            f"Error serving file '{filename}': {str(e)}",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        abort(500)

# 字体文件服务
@app.route("/fonts/<filename>", methods=["GET"])
@require_valid_request(resource_type="font")
@limiter.limit(f"{Config.RATE_LIMIT_REQUESTS}/{Config.RATE_LIMIT_WINDOW}seconds")
def serve_font_file(filename: str) -> Response:
    client_ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    method = request.method
    path = request.path
    referer = request.headers.get("Referer", "")
    origin = request.headers.get("Origin", "")

    if not any(filename.lower().endswith(ext) for ext in Config.ALLOWED_FONT_EXTENSIONS):
        logging.getLogger("error").error(
            f"Invalid font file extension for '{filename}'",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        abort(404)

    filename = secure_filename(filename)
    file_path = Config.FONTS_DIR / filename

    if not (file_path.is_file() and str(file_path).startswith(str(Config.FONTS_DIR.resolve()))):
        logging.getLogger("error").error(
            f"Font file not found: '{filename}'",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        abort(404)

    try:
        logging.getLogger("access").info(
            f"Serving font file '{filename}'",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        response = send_from_directory(Config.FONTS_DIR, filename)
        response.headers["Cache-Control"] = "public, max-age=31536000"
        response.headers["ETag"] = f"{file_path.stat().st_mtime}"
        response.headers["Content-Type"] = "font/ttf"
        return response
    except Exception as e:
        logging.getLogger("error").error(
            f"Error serving font file '{filename}': {str(e)}",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        abort(500)

# 图片文件服务
@app.route("/images/<filename>", methods=["GET"])
@require_valid_request(resource_type="image")
@limiter.limit(f"{Config.RATE_LIMIT_REQUESTS}/{Config.RATE_LIMIT_WINDOW}seconds")
def serve_image_file(filename: str) -> Response:
    client_ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    method = request.method
    path = request.path
    referer = request.headers.get("Referer", "")
    origin = request.headers.get("Origin", "")

    if not any(filename.lower().endswith(ext) for ext in Config.ALLOWED_IMAGE_EXTENSIONS):
        logging.getLogger("error").error(
            f"Invalid image file extension for '{filename}'",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        abort(404)

    filename = secure_filename(filename)
    file_path = Config.IMAGES_DIR / filename

    if not (file_path.is_file() and str(file_path).startswith(str(Config.IMAGES_DIR.resolve()))):
        logging.getLogger("error").error(
            f"Image file not found: '{filename}'",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        abort(404)

    try:
        logging.getLogger("access").info(
            f"Serving image file '{filename}'",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        response = send_from_directory(Config.IMAGES_DIR, filename)
        response.headers["Cache-Control"] = "public, max-age=31536000"
        response.headers["ETag"] = f"{file_path.stat().st_mtime}"
        return response
    except Exception as e:
        logging.getLogger("error").error(
            f"Error serving image file '{filename}': {str(e)}",
            extra={
                "client_ip": client_ip,
                "user_agent": user_agent,
                "method": method,
                "path": path,
                "referer": referer,
                "origin": origin
            }
        )
        abort(500)

# 健康检查端点
@app.route("/health", methods=["GET"])
@require_valid_request(resource_type="health")
def health_check() -> dict:
    client_ip = request.remote_addr
    user_agent = request.headers.get("User-Agent", "")
    method = request.method
    path = request.path
    referer = request.headers.get("Referer", "")
    origin = request.headers.get("Origin", "")

    logging.getLogger("access").info(
        f"Health check requested",
        extra={
            "client_ip": client_ip,
            "user_agent": user_agent,
            "method": method,
            "path": path,
            "referer": referer,
            "origin": origin
        }
    )
    return {"status": "healthy", "timestamp": str(Path(__file__).stat().st_mtime)}

# 错误处理
@app.errorhandler(403)
def forbidden(e) -> tuple[dict, int]:
    logging.getLogger("error").error(
        f"Forbidden error",
        extra={
            "client_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "method": request.method,
            "path": request.path,
            "referer": request.headers.get("Referer", ""),
            "origin": request.headers.get("Origin", "")
        }
    )
    return {"error": "Forbidden: Invalid access"}, 403

@app.errorhandler(404)
def not_found(e) -> tuple[dict, int]:
    logging.getLogger("error").error(
        f"Not found error",
        extra={
            "client_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "method": request.method,
            "path": request.path,
            "referer": request.headers.get("Referer", ""),
            "origin": request.headers.get("Origin", "")
        }
    )
    return {"error": "Resource not found"}, 404

@app.errorhandler(405)
def method_not_allowed(e) -> tuple[dict, int]:
    logging.getLogger("error").error(
        f"Method not allowed error",
        extra={
            "client_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "method": request.method,
            "path": request.path,
            "referer": request.headers.get("Referer", ""),
            "origin": request.headers.get("Origin", "")
        }
    )
    return {"error": "Method not allowed"}, 405

@app.errorhandler(429)
def ratelimit_error(e) -> tuple[dict, int]:
    logging.getLogger("error").error(
        f"Rate limit exceeded",
        extra={
            "client_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "method": request.method,
            "path": request.path,
            "referer": request.headers.get("Referer", ""),
            "origin": request.headers.get("Origin", "")
        }
    )
    return {"error": "Too many requests"}, 429

@app.errorhandler(500)
def server_error(e) -> tuple[dict, int]:
    logging.getLogger("error").error(
        f"Server error",
        extra={
            "client_ip": request.remote_addr,
            "user_agent": request.headers.get("User-Agent", ""),
            "method": request.method,
            "path": request.path,
            "referer": request.headers.get("Referer", ""),
            "origin": request.headers.get("Origin", "")
        }
    )
    return {"error": "Internal server error"}, 500

# 热重载逻辑
class ReloadHandler(FileSystemEventHandler):
    def __init__(self, directories):
        self.directories = directories
        self.process = None
        self.start_server()

    def start_server(self):
        """启动服务器进程"""
        if self.process:
            self.process.terminate()
            self.process.wait()
        self.process = subprocess.Popen(
            [sys.executable, __file__],
            env={**os.environ, "FLASK_ENV": "development"}
        )

    def on_any_event(self, event):
        """监控文件变化并重启"""
        if event.is_directory:
            return
        if event.src_path.endswith(('.log', '.pyc', '.pyo', '.swp')):
            return
        logging.getLogger("access").info(
            f"Detected file change: {event.src_path}, restarting server",
            extra={
                "client_ip": "localhost",
                "user_agent": "system",
                "method": "N/A",
                "path": event.src_path,
                "referer": "N/A",
                "origin": "N/A"
            }
        )
        print(f"Detected change in {event.src_path}, restarting...")
        self.start_server()

def run_with_reloader():
    """运行应用并启用热重载"""
    directories_to_watch = [
        str(Config.RULES_DIR),
        str(Config.FONTS_DIR),
        str(Config.IMAGES_DIR),
        str(Config.BASE_DIR)  # 监控代码文件变化
    ]
    
    event_handler = ReloadHandler(directories_to_watch)
    observer = Observer()
    
    for directory in directories_to_watch:
        observer.schedule(event_handler, directory, recursive=True)
    
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # 检查是否在生产环境（gunicorn）运行
    if os.getenv("GUNICORN_RUNNING") != "true":
        run_with_reloader()
    else:
        app.run(host="0.0.0.0", port=Config.SERVER_PORT, debug=False)