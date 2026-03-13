# Azure Key Vault — Secrets Backup Guide

Back up all secrets from your Azure Key Vault to a local JSON file with a single command.

---

## Prerequisites

- Python 3.8 or higher
- An Azure service principal with **read access** to the Key Vault

---

## 1. Install Dependencies

```bash
pip install requests python-dotenv
```

---

## 2. Set Up Your `.env` File

Create a file named `.env` in the same folder as `backup_keyvault.py` and fill in your values:

```env
AZURE_KEYVAULT_URI=https://your-vault-name.vault.azure.net/
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_GRANT_TYPE=client_credentials
AZURE_SCOPE=https://vault.azure.net/.default
```

> ⚠️ **Never commit `.env` to Git.** Add it to your `.gitignore` immediately.

### Where to find these values

| Variable | Where to find it |
|---|---|
| `AZURE_KEYVAULT_URI` | Azure Portal → Key Vault → Overview → Vault URI |
| `AZURE_TENANT_ID` | Azure Portal → Azure Active Directory → Overview → Tenant ID |
| `AZURE_CLIENT_ID` | Azure Portal → App Registrations → your app → Application (client) ID |
| `AZURE_CLIENT_SECRET` | Azure Portal → App Registrations → your app → Certificates & secrets |
| `AZURE_GRANT_TYPE` | Always use `client_credentials` |
| `AZURE_SCOPE` | Always use `https://vault.azure.net/.default` |

### Optional variables

| Variable | Default | Description |
|---|---|---|
| `AZURE_BACKUP_OUTPUT_DIR` | `./backups` | Folder where backup files are saved |

---

## 3. Run the Backup

```bash
python backup_keyvault.py
```

That's it. The script will:

1. Authenticate with Azure AD using your service principal
2. List all enabled secrets in the vault
3. Fetch the latest value of each secret
4. Save everything to a timestamped JSON file

---

## 4. Output File

Backups are saved to the `./backups/` folder (or your custom `AZURE_BACKUP_OUTPUT_DIR`) with a name like:

```
backups/keyvault_backup_20260314T120000Z.json
```

The JSON structure looks like this:

```json
{
  "metadata": {
    "vault_uri": "https://your-vault.vault.azure.net/",
    "backup_time": "2026-03-14T12:00:00+00:00",
    "secret_count": 12,
    "tool_version": "1.0.0"
  },
  "secrets": [
    {
      "name": "my-api-key",
      "value": "abc123...",
      "content_type": null,
      "tags": {},
      "enabled": true,
      "created": 1700000000,
      "updated": 1700000000,
      "expires": null
    }
  ]
}
```

A **SHA-256 checksum** of the file is printed at the end of the run — save it if you need to verify the file hasn't been tampered with later.

---

## 5. Required Azure Permissions

Your service principal needs the following **Key Vault access policy** (or RBAC role):

| Permission type | Required permissions |
|---|---|
| Secret permissions | `List`, `Get` |
| RBAC equivalent | `Key Vault Secrets User` |

To set this in the Azure Portal: **Key Vault → Access policies → Add Access Policy → Secret permissions: List + Get**.

---

## Troubleshooting

**`Missing required environment variable`**
→ Check your `.env` file is in the same directory as the script and all variables are filled in.

**`Token request failed [401]`**
→ Double-check `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, and `AZURE_TENANT_ID`.

**`Failed to list secrets [403]`**
→ Your service principal lacks permissions on the Key Vault. See Section 5 above.

**`ModuleNotFoundError: No module named 'dotenv'`**
→ Run `pip install python-dotenv`.
