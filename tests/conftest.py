import sys
from pathlib import Path

# Permite `from pcaputil import ...` nos testes.
sys.path.insert(0, str(Path(__file__).parent))

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).resolve().parent.parent
