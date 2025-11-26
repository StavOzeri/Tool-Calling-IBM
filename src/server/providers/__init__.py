from __future__ import annotations
from typing import Dict, List

from .tool_base import BaseProvider

# כאן מייבאים את המחלקות הספציפיות
from .API_tools.virusTotal import VirusTotalProvider
from .API_tools.AlienVaultOTX import AlienVaultOTXProvider
from .API_tools.URLscan import URLScanIOProvider
from .API_tools.Xforce import XForceProvider

from .DB_tools.AbuselPDB import AbuseIPDBProvider
from .DB_tools.BRON import BRONProvider
from .DB_tools.NIST import NISTProvider


# ----- REGISTRY אמיתי -----

_PROVIDERS: Dict[str, BaseProvider] = {
    "virustotal": VirusTotalProvider(),
    "alien_vault_otx": AlienVaultOTXProvider(),
    "urlscan": URLScanIOProvider(),
    "xforce": XForceProvider(),
    "abuseipdb": AbuseIPDBProvider(),
    "bron": BRONProvider(),
    "nist": NISTProvider(),
}


def get_provider(name: str) -> BaseProvider:
    """החזרת provider לפי שם (אם לא קיים - נזרוק שגיאה)."""
    try:
        return _PROVIDERS[name]
    except KeyError:
        raise ValueError(f"Unknown provider: {name}. Available: {list(_PROVIDERS.keys())}")


def get_all_providers() -> List[BaseProvider]:
    """החזרת כל ה-providers כרשימה."""
    return list(_PROVIDERS.values())
