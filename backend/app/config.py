"""Runtime configuration (environment variables / .env)."""
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=True, extra="ignore", protected_namespaces=()
    )

    PROJECT_NAME: str = "DNS Defender AI"
    VERSION: str = "3.0.0"

    # --- storage -----------------------------------------------------------
    # SQLite for local runs / tests, PostgreSQL in docker-compose.
    DATABASE_URL: str = f"sqlite:///{BACKEND_DIR / 'data' / 'defender.db'}"
    RETENTION_DAYS: int = 7  # DNS events/features/predictions older than this are pruned

    # --- machine learning --------------------------------------------------
    ML_MODEL_PATH: str = str(BACKEND_DIR / "models" / "dga_rf.joblib")
    # None -> use the thresholds stored in the trained model bundle
    SUSPICIOUS_THRESHOLD: Optional[float] = None
    MALICIOUS_THRESHOLD: Optional[float] = None

    # --- response policy ---------------------------------------------------
    ALERT_ONLY_MODE: bool = True          # never block automatically while True
    AUTO_BLOCK_CONFIRMED: bool = False    # only effective when ALERT_ONLY_MODE is False
    AUTO_BLOCK_MIN_RISK: float = 0.95

    # --- DNS capture & blocking -------------------------------------------
    CAPTURE_MODE: str = "off"             # off | dnsmasq | scapy
    DNSMASQ_LOG_PATH: str = "/var/log/dnsmasq/queries.log"
    DNS_BLOCKLIST_PATH: str = "/rules/blocked.conf"   # dnsmasq servers-file
    SCAPY_INTERFACE: Optional[str] = None
    MONITOR_IGNORE_LOCALHOST: bool = False

    # --- optional LLM explanations (NVIDIA NIM, OpenAI-compatible) ---------
    NVIDIA_API_KEY: Optional[str] = None
    NVIDIA_MODEL: str = "meta/llama-3.1-70b-instruct"
    NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"

    # --- API security -------------------------------------------------------
    API_KEY: Optional[str] = None         # when set, every /api/v1 route (except health) requires it
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"


settings = Settings()
