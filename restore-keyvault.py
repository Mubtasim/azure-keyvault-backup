"""
Azure Key Vault Secrets Batch Insert Script
-------------------------------------------
Reads secrets from a CSV file and writes them to an Azure Key Vault, one
PUT /secrets/{name} per row (the same call as setting a secret from Postman).

CSV columns:
    name          (required)  Secret name — letters, digits and hyphens only
    value         (required)  Secret value (quote it if it contains commas)
    content_type  (optional)  e.g. text/plain
    tags          (optional)  key=value pairs separated by ';'
    expires       (optional)  2027-12-31 or 2027-12-31T23:59:59Z (UTC)
    enabled       (optional)  true / false (default: true)

Empty optional columns are simply not sent, so the new version has no
content type / tags / expiry — exactly like a plain Postman PUT.

Uses the same environment variables as backup-keyvault.py.

Usage:
    python restore-keyvault.py secrets.csv --dry-run
    python restore-keyvault.py secrets.csv
"""

import os
import re
import csv
import sys
import time
import fnmatch
import logging
import argparse
import importlib.util
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import requests

# Reuse Config + auth from the backup script (hyphenated filename → load by path)
_spec = importlib.util.spec_from_file_location(
    "backup_keyvault", Path(__file__).with_name("backup-keyvault.py")
)
backup_keyvault = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(backup_keyvault)

log = logging.getLogger(__name__)

API_VERSION  = "7.4"
MAX_RETRIES  = 5
KNOWN_COLUMNS = {"name", "value", "content_type", "tags", "expires", "enabled"}
NAME_RE       = re.compile(r"^[0-9a-zA-Z-]{1,127}$")
TRUE_WORDS    = {"true", "yes", "1"}
FALSE_WORDS   = {"false", "no", "0"}


# ── CSV loading & validation ──────────────────────────────────────────────────
def parse_tags(raw: str) -> dict:
    tags = {}
    for pair in raw.split(";"):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            raise ValueError(f"tag '{pair}' is not in key=value form")
        key, val = pair.split("=", 1)
        if not key.strip():
            raise ValueError(f"tag '{pair}' has an empty key")
        tags[key.strip()] = val.strip()
    if len(tags) > 15:
        raise ValueError("Key Vault allows at most 15 tags per secret")
    return tags


def parse_expires(raw: str) -> int:
    text = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError(f"expires '{raw}' is not a valid date (use 2027-12-31 or 2027-12-31T23:59:59Z)")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def parse_enabled(raw: str) -> bool:
    word = raw.lower()
    if word in TRUE_WORDS:
        return True
    if word in FALSE_WORDS:
        return False
    raise ValueError(f"enabled '{raw}' must be true or false")


def load_csv(path: Path) -> list[dict]:
    """Parse and validate every row. Exits with a list of problems if any row is bad."""
    if not path.is_file():
        log.error("CSV file not found: %s", path)
        sys.exit(1)

    # utf-8-sig strips the BOM Excel adds when saving as CSV
    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        columns = {c.strip().lower() for c in (reader.fieldnames or [])}
        missing = {"name", "value"} - columns
        unknown = columns - KNOWN_COLUMNS
        if missing:
            log.error("CSV is missing required column(s): %s", ", ".join(sorted(missing)))
            sys.exit(1)
        if unknown:
            log.error("CSV has unknown column(s): %s (allowed: %s)",
                      ", ".join(sorted(unknown)), ", ".join(sorted(KNOWN_COLUMNS)))
            sys.exit(1)

        secrets, errors, seen = [], [], {}
        for line_no, raw_row in enumerate(reader, start=2):  # line 1 is the header
            row = {(k or "").strip().lower(): (v or "") for k, v in raw_row.items()}
            name  = row.get("name", "").strip()
            value = row.get("value", "")  # never strip: whitespace may be part of the secret

            if not name and not value and not any(v.strip() for v in row.values()):
                continue  # blank line

            problems = []
            if not NAME_RE.match(name):
                problems.append(f"invalid name '{name}' (letters, digits and hyphens only, max 127)")
            if value == "":
                problems.append("value is empty")
            # Key Vault names are case-insensitive
            if name.lower() in seen:
                problems.append(f"duplicate of line {seen[name.lower()]}")
            else:
                seen[name.lower()] = line_no

            secret = {"line": line_no, "name": name, "value": value}
            for column, parser, key in (
                ("content_type", str,           "content_type"),
                ("tags",         parse_tags,    "tags"),
                ("expires",      parse_expires, "expires"),
                ("enabled",      parse_enabled, "enabled"),
            ):
                cell = row.get(column, "").strip()
                if cell:
                    try:
                        secret[key] = parser(cell)
                    except ValueError as e:
                        problems.append(str(e))

            if problems:
                errors.append(f"line {line_no}: " + "; ".join(problems))
            else:
                secrets.append(secret)

    if errors:
        log.error("CSV has %d invalid row(s) — nothing was written:", len(errors))
        for err in errors:
            log.error("  %s", err)
        sys.exit(1)

    return secrets


def filter_secrets(secrets: list[dict], only: str | None, exclude: str | None) -> list[dict]:
    def matches(name: str, patterns: str) -> bool:
        return any(fnmatch.fnmatch(name.lower(), p.strip().lower())
                   for p in patterns.split(",") if p.strip())

    if only:
        secrets = [s for s in secrets if matches(s["name"], only)]
    if exclude:
        secrets = [s for s in secrets if not matches(s["name"], exclude)]
    return secrets


# ── Key Vault API helpers ─────────────────────────────────────────────────────
def kv_request(method: str, url: str, token: str, **kwargs) -> requests.Response:
    """HTTP call with retries on throttling (429) and transient server errors (5xx)."""
    headers = {"Authorization": f"Bearer {token}"}
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, headers=headers, timeout=30, **kwargs)
        except requests.RequestException as e:
            if attempt == MAX_RETRIES:
                raise
            wait = 2 ** attempt
            log.warning("Network error (%s) — retrying in %ds …", e, wait)
            time.sleep(wait)
            continue

        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt == MAX_RETRIES:
                return resp
            wait = int(resp.headers.get("Retry-After", 2 ** attempt))
            log.warning("[%s] from Key Vault — retrying in %ds …", resp.status_code, wait)
            time.sleep(wait)
            continue
        return resp
    return resp


def error_text(resp: requests.Response) -> str:
    try:
        return resp.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        return resp.text


def get_current(vault: str, token: str, name: str) -> tuple[str, str | None]:
    """
    Returns (state, current_value):
      ("exists", value) | ("disabled", None) | ("deleted", None) | ("missing", None)
    """
    resp = kv_request("GET", f"{vault}/secrets/{name}?api-version={API_VERSION}", token)
    if resp.status_code == 200:
        return "exists", resp.json().get("value")
    if resp.status_code == 403 and "disabled" in resp.text.lower():
        return "disabled", None  # Key Vault refuses GET on a disabled secret's value
    if resp.status_code != 404:
        raise RuntimeError(f"GET failed [{resp.status_code}]: {error_text(resp)}")

    resp = kv_request("GET", f"{vault}/deletedsecrets/{name}?api-version={API_VERSION}", token)
    if resp.status_code == 200:
        return "deleted", None
    return "missing", None


def recover_deleted(vault: str, token: str, name: str):
    resp = kv_request("POST", f"{vault}/deletedsecrets/{name}/recover?api-version={API_VERSION}", token)
    if resp.status_code != 200:
        raise RuntimeError(f"recover failed [{resp.status_code}]: {error_text(resp)}")
    # Recovery is asynchronous — wait until the secret is readable again
    for _ in range(30):
        time.sleep(2)
        check = kv_request("GET", f"{vault}/secrets/{name}?api-version={API_VERSION}", token)
        if check.status_code in (200, 403):
            return
    raise RuntimeError("recover did not finish within 60s")


def set_secret(vault: str, token: str, secret: dict):
    """PUT the secret — same body shape as the Postman call."""
    body = {
        "value": secret["value"],
        "attributes": {"enabled": secret.get("enabled", True)},
    }
    if "content_type" in secret:
        body["contentType"] = secret["content_type"]
    if "tags" in secret:
        body["tags"] = secret["tags"]
    if "expires" in secret:
        body["attributes"]["exp"] = secret["expires"]

    resp = kv_request("PUT", f"{vault}/secrets/{secret['name']}?api-version={API_VERSION}",
                      token, json=body)
    if resp.status_code != 200:
        raise RuntimeError(f"PUT failed [{resp.status_code}]: {error_text(resp)}")


# ── Per-secret processing ─────────────────────────────────────────────────────
def process(secret: dict, vault: str, token: str, mode: str,
            dry_run: bool, recover: bool) -> tuple[str, str]:
    """Decide what to do with one secret and (unless dry-run) do it. Returns (action, detail)."""
    name = secret["name"]
    try:
        state, current = get_current(vault, token, name)

        if state == "deleted":
            if not recover:
                return "CONFLICT", "soft-deleted; use --recover-deleted or purge it"
            action, detail = "RECOVER", "recover soft-deleted secret, then set value"
        elif state == "missing":
            action, detail = "CREATE", ""
        elif mode == "skip-existing":
            return "SKIP", "already exists"
        elif mode == "skip-unchanged" and state == "exists" and current == secret["value"]:
            return "SKIP", "unchanged"
        else:
            action = "UPDATE"
            detail = "secret is disabled; value unknown" if state == "disabled" else (
                "value differs" if current != secret["value"] else "forced overwrite")

        if not dry_run:
            if action == "RECOVER":
                recover_deleted(vault, token, name)
            set_secret(vault, token, secret)
        return action, detail

    except Exception as e:  # one bad secret must not stop the rest
        return "FAILED", str(e)


# ── Main ──────────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser(description="Batch insert secrets from a CSV into Azure Key Vault.")
    p.add_argument("csv_file", type=Path, help="CSV with columns name,value[,content_type,tags,expires,enabled]")
    p.add_argument("--dry-run", action="store_true", help="show what would happen without writing anything")
    p.add_argument("--vault", help="target vault URI (default: AZURE_KEYVAULT_URI from .env)")
    p.add_argument("--mode", choices=["skip-unchanged", "skip-existing", "overwrite"],
                   default="skip-unchanged",
                   help="what to do with secrets that already exist (default: skip-unchanged)")
    p.add_argument("--only", help="comma-separated names or patterns to include, e.g. 'prod-*,api-key'")
    p.add_argument("--exclude", help="comma-separated names or patterns to skip")
    p.add_argument("--workers", type=int, default=5, help="parallel requests (default: 5)")
    p.add_argument("--recover-deleted", action="store_true",
                   help="recover soft-deleted secrets before setting them")
    return p.parse_args()


def main():
    args = parse_args()
    if args.vault:
        os.environ["AZURE_KEYVAULT_URI"] = args.vault
    if args.workers < 1:
        log.error("--workers must be at least 1")
        sys.exit(1)

    secrets = load_csv(args.csv_file)
    log.info("Loaded %d secret(s) from %s", len(secrets), args.csv_file)
    secrets = filter_secrets(secrets, args.only, args.exclude)
    if args.only or args.exclude:
        log.info("%d secret(s) left after --only/--exclude filters", len(secrets))
    if not secrets:
        log.info("Nothing to do.")
        return

    cfg = backup_keyvault.Config()
    token = backup_keyvault.get_access_token(cfg)
    log.info("Target vault: %s%s", cfg.keyvault_uri, "  (DRY RUN)" if args.dry_run else "")

    width = max(len(s["name"]) for s in secrets)
    counts = {}
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = pool.map(
            lambda s: process(s, cfg.keyvault_uri, token, args.mode, args.dry_run, args.recover_deleted),
            secrets,
        )
        # pool.map yields in CSV order, so the log reads top-to-bottom like the file
        for secret, (action, detail) in zip(secrets, results):
            counts[action] = counts.get(action, 0) + 1
            line = f"{'[' + action + ']':<11} {secret['name']:<{width}}  {f'({detail})' if detail else ''}"
            if action in ("FAILED", "CONFLICT"):
                log.warning(line.rstrip())
            else:
                log.info(line.rstrip())

    # RECOVER and CONFLICT only appear in the summary when they happened
    order = ["CREATE", "UPDATE", "RECOVER", "SKIP", "CONFLICT", "FAILED"]
    always = {"CREATE", "UPDATE", "SKIP", "FAILED"}
    summary = ", ".join(f"{counts.get(a, 0)} {a.lower()}" for a in order if a in always or counts.get(a))
    log.info("%s: %s", "Dry run summary" if args.dry_run else "Summary", summary)

    if counts.get("FAILED") or counts.get("CONFLICT"):
        sys.exit(1)


if __name__ == "__main__":
    main()
