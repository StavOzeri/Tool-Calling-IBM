# src/server/providers/api_tools/alien_vault_otx.py
from __future__ import annotations

import os
from typing import Literal, Any

import httpx

from ..tool_base import BaseProvider, ProviderResult, IndicatorType


class AlienVaultOTXProvider(BaseProvider):
    """
    Provider ל-AlienVault OTX.

    כרגע יש:
    - query(...) גנרי (placeholder - נממש כשיהיה לך עוד דאטה)
    - submit_file(...) שמממש את endpoint:
      POST /api/v1/indicators/submit_file  (multipart/form-data)
    """

    name = "alien_vault_otx"
    provider_kind: Literal["api"] = "api"

    # ה-base URL כולל כבר /api/v1
    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(
        self,
        api_key: str | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        # מפתח API – מה-ENV או מהפרמטר
        self.api_key = api_key or os.environ.get("ALIENVAULT_OTX_API_KEY", "")
        self._client = client or httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=10.0,
        )

    # ---------- helpers פנימיים ----------

    async def _request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict:
        """
        פונקציה פנימית לקריאות JSON "רגילות" (GET/POST עם query params).
        """
        headers = {
            # לפי הטבלה – header בשם api-key
            "api-key": self.api_key,
            "Accept": "application/json",
        }

        resp = await self._client.request(
            method=method.upper(),
            url=path,
            params=params or {},
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()

    def _build_result(
        self,
        *,
        indicator: str,
        indicator_type: IndicatorType,
        raw: dict,
        verdict: str | None = None,
        score: int | None = None,
    ) -> ProviderResult:
        """
        מחזיר ProviderResult בפורמט האחיד.
        """
        result: ProviderResult = {
            "provider": self.name,
            "indicator": indicator,
            "indicator_type": indicator_type,
            "raw": raw,
        }
        if verdict is not None:
            result["verdict"] = verdict
        if score is not None:
            result["score"] = score
        return result

    # ---------- מימוש ה-endpoint: submit_file ----------

    async def submit_file(self, file_path: str) -> dict:
        """
        מעלה קובץ ל-OTX דרך endpoint:
        POST /api/v1/indicators/submit_file

        • Headers:
            api-key: <API_KEY>
        • Body:
            multipart/form-data עם שדה file

        Args:
            file_path: נתיב לקובץ המקומי להעלאה.

        Returns:
            JSON של התגובה מה-API (dict).
        """
        headers = {
            "api-key": self.api_key,
            "Accept": "application/json",
        }

        # קורא את הקובץ כ-binary לזיכרון ושולח כ-multipart/form-data
        filename = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            file_bytes = f.read()

        files = {
            # השם "file" – השדה ב-multipart (בהיעדר מידע אחר מהטבלה)
            "file": (filename, file_bytes, "application/octet-stream"),
        }

        resp = await self._client.post(
            "/indicators/submit_file",
            headers=headers,
            files=files,
        )
        resp.raise_for_status()
        return resp.json()

    # ---------- נקודת הכניסה הגנרית (query) שנקראת מה-MCP ----------

    async def query(
        self,
        indicator: str,
        indicator_type: IndicatorType,
    ) -> ProviderResult:
        """
        פונקציה גנרית שה-MCP קורא אליה.

        כרגע היא עדיין placeholder – כשנוסיף טבלה של endpoints נוספים
        (IP / domain / URL / hash וכו') נממש כאן לוגיקה אמיתית.
        """

        if indicator_type == "ip":
            raw = {"placeholder": True, "note": "replace with real IP endpoint"}
        elif indicator_type == "domain":
            raw = {"placeholder": True, "note": "replace with real domain endpoint"}
        elif indicator_type == "url":
            raw = {"placeholder": True, "note": "replace with real URL endpoint"}
        elif indicator_type == "hash":
            raw = {"placeholder": True, "note": "replace with real hash endpoint"}
        else:
            raise ValueError(f"Unsupported indicator_type: {indicator_type}")

        return self._build_result(
            indicator=indicator,
            indicator_type=indicator_type,
            raw=raw,
        )
