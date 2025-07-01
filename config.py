from pathlib import Path
from typing import Optional

class Config:
    BASE_DIR: Path = Path(__file__).parent
    RULES_DIR: Path = BASE_DIR / "rules"
    LOGS_DIR: Path = BASE_DIR / "logs"
    FONTS_DIR: Path = BASE_DIR / "fonts"
    IMAGES_DIR: Path = BASE_DIR / "images"
    ALLOWED_USER_AGENT_SUBSTRING: str = "Surge iOS"
    SERVER_PORT: int = 8099
    LOG_FILE_MAX_BYTES: int = 10 * 1024 * 1024  # 10MB
    LOG_FILE_BACKUP_COUNT: int = 2
    SECRET_KEY: str = "your SECRET_KEY"
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60
    ALLOWED_ORIGINS: list = ["https://domain1.com", "https://domain2.com"]
    ALLOWED_REFERERS: list = ["https://domain1.com", "https://domain2.com"]
    ALLOWED_FONT_EXTENSIONS: list = [".ttf"]
    ALLOWED_IMAGE_EXTENSIONS: list = [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg"]