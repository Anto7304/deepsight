"""Always use a disposable database, independent of the caller's app settings."""
import os
import tempfile

_data = tempfile.TemporaryDirectory(prefix="deepsight-tests-")
os.environ.update(
    ASIVM_DATA_DIR=_data.name,
    # This opt-in URL must point to a dedicated, disposable test database.
    ASIVM_DATABASE_URL=os.getenv("ASIVM_TEST_DATABASE_URL", f"sqlite:///{_data.name}/test.db"),
    ASIVM_ADMIN_USER="admin",
    ASIVM_ADMIN_PASSWORD="Test-Password-1234",
    ASIVM_SECRET_KEY="deepsight-tests-only-secret-key-32-bytes",
    ASIVM_SCHEDULER="false",
    ASIVM_WORKER="false",
    ASIVM_SEED_DEMO="false",
    ASIVM_KEV_AUTO_SYNC="false",
    ASIVM_RATE_LIMIT_PER_MIN="10000",
    ASIVM_LOGIN_RATE_LIMIT_PER_MIN="1000",
)
os.environ.pop("ANTHROPIC_API_KEY", None)
