import pytest

from keyward.crypto import KdfParams

# Fast KDF settings so the test suite runs quickly. Real vaults use the defaults.
FAST = KdfParams(time_cost=1, memory_cost=8 * 1024, parallelism=1)
PASSWORD = "correct horse battery"


@pytest.fixture
def fast_kdf():
    return FAST
