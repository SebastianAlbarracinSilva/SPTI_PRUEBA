import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.identity import AuthContext  # noqa: E402
from app.policy import PolicyEngine  # noqa: E402

SUPPORT = AuthContext(1, "soporte1", "support")
ADMIN = AuthContext(3, "admin1", "admin")


@pytest.fixture()
def engine() -> PolicyEngine:
    return PolicyEngine.from_file(settings.policy_path)
