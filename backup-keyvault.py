"""
Azure Key Vault Secrets Backup Script
--------------------------------------
Reads configuration from environment variables and backs up all secrets
from an Azure Key Vault to a local JSON file.

Required Environment Variables:
    AZURE_KEYVAULT_URI      - e.g. https://my-vault.vault.azure.net/
    AZURE_CLIENT_ID         - Service principal / app client ID
    AZURE_CLIENT_SECRET     - Service principal / app client secret
    AZURE_GRANT_TYPE        - Typically: client_credentials
    AZURE_SCOPE             - e.g. https://vault.azure.net/.default
    AZURE_TENANT_ID         - Your Azure AD tenant ID

Optional:
    AZURE_BACKUP_OUTPUT_DIR - Directory to write backup file (default: ./backups)
"""

import os
import sys
import json
import time
import logging
import hashlib
import requests
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv
load_dotenv()

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ── Config ────────────────────────────────────────────────────────────────────
class Config:
    def __init__(self):
        self.keyvault_uri   = self._require("AZURE_KEYVAULT_URI").rstrip("/")
        self.client_id      = self._require("AZURE_CLIENT_ID")
        self.client_secret  = self._require("AZURE_CLIENT_SECRET")
        self.grant_type     = self._require("AZURE_GRANT_TYPE")
        self.scope          = self._require("AZURE_SCOPE")
        self.output_dir     = Path(os.getenv("AZURE_BACKUP_OUTPUT_DIR", "./backups"))

    @staticmethod
    def _require(name: str) -> str:
        value = os.getenv(name)
        if not value:
            log.error("Missing required environment variable: %s", name)
            sys.exit(1)
        return value


# ── Auth ──────────────────────────────────────────────────────────────────────
def get_access_token(cfg: Config) -> str:
    """Obtain a Bearer token from Azure AD using client credentials."""
    # Extract tenant from the vault URI host or fall back to a dedicated env var
    # Standard vault URI: https://<vault-name>.vault.azure.net/
    # We need the tenant ID for the token endpoint.
    tenant_id = os.getenv("AZURE_TENANT_ID")
    if not tenant_id:
        log.error(
            "AZURE_TENANT_ID environment variable is required to fetch an access token."
        )
        sys.exit(1)

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    payload = {
        "grant_type":    cfg.grant_type,
        "client_id":     cfg.client_id,
        "client_secret": cfg.client_secret,
        "scope":         cfg.scope,
    }

    log.info("Requesting access token from Azure AD …")
    resp = requests.post(token_url, data=payload, timeout=30)

    if resp.status_code != 200:
        log.error("Token request failed [%s]: %s", resp.status_code, resp.text)
        sys.exit(1)

    token = resp.json().get("access_token")
    if not token:
        log.error("No access_token in response: %s", resp.json())
        sys.exit(1)

    log.info("Access token obtained successfully.")
    return token


# ── Key Vault API helpers ─────────────────────────────────────────────────────
API_VERSION = "7.4"


def list_secret_names(vault_uri: str, token: str) -> list[str]:
    """Return all secret *names* (non-deleted) in the vault."""
    url = f"{vault_uri}/secrets?api-version={API_VERSION}&maxresults=25"
    headers = {"Authorization": f"Bearer {token}"}
    names = []

    while url:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            log.error("Failed to list secrets [%s]: %s", resp.status_code, resp.text)
            sys.exit(1)
        body = resp.json()
        for item in body.get("value", []):
            # item["id"] looks like https://vault.azure.net/secrets/<name>/<version>
            # We only want the name part (no version)
            name = item["id"].split("/secrets/")[1].split("/")[0]
            if item.get("attributes", {}).get("enabled", True):
                names.append(name)
        url = body.get("nextLink")  # pagination

    return names


def get_secret_value(vault_uri: str, token: str, name: str) -> dict:
    """Fetch the latest enabled version of a single secret."""
    url = f"{vault_uri}/secrets/{name}?api-version={API_VERSION}"
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(url, headers=headers, timeout=30)

    if resp.status_code != 200:
        log.warning("Could not retrieve secret '%s' [%s]: %s", name, resp.status_code, resp.text)
        return {"name": name, "value": None, "error": resp.text}

    body = resp.json()
    return {
        "name":         name,
        "value":        body.get("value"),
        "content_type": body.get("contentType"),
        "tags":         body.get("tags", {}),
        "enabled":      body.get("attributes", {}).get("enabled"),
        "created":      body.get("attributes", {}).get("created"),
        "updated":      body.get("attributes", {}).get("updated"),
        "expires":      body.get("attributes", {}).get("exp"),
    }


# ── Backup writer ─────────────────────────────────────────────────────────────
def write_backup(cfg: Config, backup: dict) -> Path:
    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_path = cfg.output_dir / f"keyvault_backup_{timestamp}.json"
    out_path.write_text(json.dumps(backup, indent=2, default=str), encoding="utf-8")
    log.info("Backup saved → %s", out_path)
    return out_path


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    cfg = Config()

    token = get_access_token(cfg)

    log.info("Listing secrets in vault: %s", cfg.keyvault_uri)
    names = list_secret_names(cfg.keyvault_uri, token)
    log.info("Found %d enabled secret(s).", len(names))

    backup_secrets = []
    for i, name in enumerate(names, 1):
        log.info("[%d/%d] Fetching secret: %s", i, len(names), name)
        backup_secrets.append(get_secret_value(cfg.keyvault_uri, token, name))
        time.sleep(0.1)  # gentle rate-limiting

    backup = {
        "metadata": {
            "vault_uri":    cfg.keyvault_uri,
            "backup_time":  datetime.now(timezone.utc).isoformat(),
            "secret_count": len(backup_secrets),
            "tool_version": "1.0.0",
        },
        "secrets": backup_secrets,
    }

    out_path = write_backup(cfg, backup)
    log.info("✓ Backup complete — %d secret(s) saved to %s", len(backup_secrets), out_path)

    checksum = hashlib.sha256(out_path.read_bytes()).hexdigest()
    log.info("SHA-256: %s", checksum)


if __name__ == "__main__":
    main()
