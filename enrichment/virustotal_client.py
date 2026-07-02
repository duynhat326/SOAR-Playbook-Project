from __future__ import annotations

import json
import os
from urllib import error, request

from env_utils import load_local_env_files


class VirusTotalNotFoundError(LookupError):
    pass


class VirusTotalClient:
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str | None = None, *, timeout: float = 15.0) -> None:
        load_local_env_files()
        self._api_key = api_key or os.getenv("VIRUSTOTAL_API_KEY")
        if not self._api_key:
            raise RuntimeError(
                "VirusTotal API key is missing. Set VIRUSTOTAL_API_KEY to enable live threat intel."
            )
        self._timeout = timeout

    def get_attributes(self, object_path: str) -> dict:
        raw_url = f"{self.BASE_URL}{object_path}"
        vt_request = request.Request(
            raw_url,
            headers={
                "accept": "application/json",
                "x-apikey": self._api_key,
            },
            method="GET",
        )
        try:
            with request.urlopen(vt_request, timeout=self._timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            if exc.code == 404:
                raise VirusTotalNotFoundError(object_path) from exc
            raise RuntimeError(
                f"VirusTotal request failed for {object_path} with HTTP {exc.code}: {details}"
            ) from exc
        except error.URLError as exc:
            raise RuntimeError(f"VirusTotal request failed for {object_path}: {exc.reason}") from exc

        data = payload.get("data", {})
        attributes = data.get("attributes")
        if not isinstance(attributes, dict):
            raise RuntimeError(f"VirusTotal returned no attributes for {object_path}.")
        return attributes
