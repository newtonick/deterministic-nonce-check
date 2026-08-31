import sys
from pathlib import Path

# Let the test import sign_with_embit as a sibling module.
sys.path.insert(0, str(Path(__file__).parent))
