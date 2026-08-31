"""Environment-driven configuration for the example service."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    mongo_uri: str
    mongo_db: str
    log_id: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            mongo_uri=os.getenv("MONGO_URI", "mongodb://localhost:27017"),
            mongo_db=os.getenv("MONGO_DB", "approvo_vehicle_releases"),
            log_id=os.getenv("APPROVO_LOG_ID", "vehicle-releases"),
        )


settings = Settings.from_env()
