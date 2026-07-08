"""Admin dashboard routes for Kiro Gateway."""
import os
import re
import json
import time
import glob
import asyncio
import secrets
import string
from pathlib import Path
from fastapi import APIRouter, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
import httpx
from kiro.stats_collector import StatsCollector

# Admin key: env var default, overridable via settings file at runtime
_ADMIN_API_KEY_DEFAULT = os.getenv("ADMIN_API_KEY", "kiro-admin-2026")
ACCOUNTS_DIR = "/root/kiro-accounts"
ADMIN_SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "admin_settings.json")


def _load_admin_settings() -> dict:
    """Load admin settings from JSON file."""
    try:
        with open(ADMIN_SETTINGS_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_admin_settings(settings: dict):
    """Save admin settings to JSON file."""
    dirname = os.path.dirname(ADMIN_SETTINGS_FILE)
    os.makedirs(dirname, exist_ok=True)
    with open(ADMIN_SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)


def _get_admin_key() -> str:
    """Get effective admin API key: settings file > env var > default."""
    settings = _load_admin_settings()
    return settings.get("api_key") or _ADMIN_API_KEY_DEFAULT


def _mask_key(key: str) -> str:
    """Mask middle portion of a key for display."""
    if len(key) <= 8:
        return key[:3] + "***"
    half = len(key) // 2
    return key[:4] + "*" * (half - 2) + key[-4:]

# Pydantic model for account creation via admin panel
class AccountCredential(BaseModel):
    clientId: str = Field(..., description="AWS Q Developer client ID")
    clientSecret: str = Field(..., description="AWS Q Developer client secret (JWT)")
    refreshToken: str = Field(..., description="Refresh token")
    email: str = Field(default="", description="Account email")
    provider: str = Field(default="BuilderId", description="Auth provider")
    region: str = Field(default="us-east-1", description="AWS region")
    subscription: str = Field(default="Amazon Q Developer", description="Subscription type")
    creditLimit: int = Field(default=0, description="Monthly credit limit")
    creditUsed: int = Field(default=0, description="Credits used")

router = APIRouter(tags=["Admin"])

async def verify_admin_key(request: Request):
    auth = request.headers.get("Authorization", "")
    current_key = _get_admin_key()
    if auth != f"Bearer {current_key}":
        raise HTTPException(status_code=403, detail="Invalid admin key")

def _next_account_number() -> int:
    """Find the next available account number from existing files."""
    max_num = 0
    for f in glob.glob(os.path.join(ACCOUNTS_DIR, "acct-*.json")):
        m = re.search(r'acct-0*(\d+)\.json', os.path.basename(f))
        if m:
            num = int(m.group(1))
            if num > max_num:
                max_num = num
    return max_num + 1


@router.get("/admin/api/dashboard", dependencies=[Depends(verify_admin_key)])
async def get_dashboard(request: Request):
    am = request.app.state.account_manager
    accounts = am._accounts
    total = len(accounts)
    healthy = 0
    degraded = 0
    failed = 0
    healthy_real = 0  # accounts with actual working runtime state
    total_req = 0
    success_req = 0
    failed_req = 0
    account_list = []

    # Preload all account file data for real info
    file_data_map = {}
    for f in glob.glob(os.path.join(ACCOUNTS_DIR, "*.json")):
        try:
            with open(f) as fh:
                file_data_map[f] = json.load(fh)
        except Exception:
            pass

    for aid, acct in accounts.items():
        failures = acct.failures
        last_fail = acct.last_failure_time
        if acct.failures > 0 and acct.last_failure_time > 0:
            backoff = min(2 ** (acct.failures - 1), 1440.0)
            cooldown_until = acct.last_failure_time + 60.0 * backoff
        else:
            cooldown_until = 0

        # Read real data from JSON file
        file_data = file_data_map.get(aid, {})

        models = []
        if acct.model_cache:
            models = acct.model_cache.get_all_model_ids()
        elif acct.model_resolver:
            models = acct.model_resolver.get_available_models() if hasattr(acct.model_resolver, 'get_available_models') else []

        t = acct.stats.total_requests
        s = acct.stats.successful_requests
        f = acct.stats.failed_requests
        total_req += t
        success_req += s
        failed_req += f

        now = time.time()
        is_cooldown = cooldown_until > now

        # Status: reflect real initialization state
        has_runtime = acct.auth_manager is not None
        has_models = len(models) > 0
        if has_runtime and has_models and failures == 0:
            status = "healthy"
            healthy += 1
        elif is_cooldown:
            status = "cooldown"
            degraded += 1
        elif failures > 0:
            status = "degraded"
            degraded += 1
        else:
            # File exists but runtime not ready - show as pending
            status = "pending"
            degraded += 1

        # Region: runtime first, then file, then ?
        region = getattr(acct, 'region', '')
        if acct.auth_manager:
            region = getattr(acct.auth_manager, '_region', region)
        if not region or region == '?':
            region = file_data.get('region', '?')
        if not region:
            region = '?'

        account_list.append({
            "id": aid.split("/")[-1].replace(".json", ""),
            "status": status,
            "email": file_data.get('email', ''),
            "region": region,
            "subscription": file_data.get('subscription', ''),
            "provider": file_data.get('provider', ''),
            "creditLimit": file_data.get('creditLimit', 0),
            "creditUsed": file_data.get('creditUsed', 0),
            "time": file_data.get('time', ''),
            "failures": failures,
            "cooldown_until": cooldown_until,
            "last_failure_time": last_fail,
            "stats": {"total": t, "success": s, "failed": f},
            "models": models,
        })

        # Track real healthy count from runtime
        if has_runtime and has_models:
            healthy_real += 1

    free_limit = 0
    free_used = 0
    for cred_file in sorted(glob.glob("/root/kiro-accounts/*.json")):
        try:
            with open(cred_file) as f:
                cd = json.load(f)
            if cd.get("creditLimit"):
                free_limit += cd["creditLimit"]
                free_used += cd.get("creditUsed", 0)
        except Exception:
            pass

    version = getattr(request.app.state, '_version', '?')
    try:
        from kiro.config import APP_VERSION
        version = APP_VERSION
    except Exception:
        pass

    uptime = time.time() - getattr(request.app.state, '_start_time', time.time())

    # Current proxy from settings
    settings = _load_admin_settings()
    proxy_url = settings.get("proxy_url", "")

    return {
        "gateway": {
            "version": version,
            "uptime": uptime,
            "accounts_total": total,
            "accounts_healthy": healthy,
            "accounts_degraded": degraded,
            "accounts_failed": failed,
            "accounts_healthy_real": healthy_real,
            "proxy_url": proxy_url,
            "current_account_index": am._current_account_index,
        },
        "requests": {
            "total": total_req,
            "success": success_req,
            "failed": failed_req,
        },
        "credits": {
            "limit": free_limit,
            "used": free_used,
            "remaining": free_limit - free_used,
        },
        "accounts": account_list,
    }


@router.get("/admin/api/models", dependencies=[Depends(verify_admin_key)])
async def get_models(request: Request):
    am = request.app.state.account_manager
    models_set = set()
    for aid, acct in am._accounts.items():
        if acct.model_cache:
            models_set.update(acct.model_cache.get_all_model_ids())
        elif acct.model_resolver:
            models_set.update(
                acct.model_resolver.get_available_models()
                if hasattr(acct.model_resolver, 'get_available_models')
                else []
            )
    return {"models": sorted(models_set)}


@router.post("/admin/api/accounts", dependencies=[Depends(verify_admin_key)])
async def add_account(cred: AccountCredential, request: Request):
    """Add a new AWS Q Developer account via admin panel."""
    am = request.app.state.account_manager

    # Validate required fields
    if not cred.clientId or not cred.clientSecret or not cred.refreshToken:
        raise HTTPException(status_code=400, detail="clientId, clientSecret, and refreshToken are required")

    # Generate next account number
    next_num = _next_account_number()
    filename = f"acct-{next_num:04d}.json"
    filepath = os.path.join(ACCOUNTS_DIR, filename)

    # Check if email already exists
    for f in glob.glob(os.path.join(ACCOUNTS_DIR, "*.json")):
        try:
            with open(f) as fh:
                existing = json.load(fh)
            if existing.get("email") == cred.email:
                raise HTTPException(status_code=409, detail=f"Account with email {cred.email} already exists")
        except Exception:
            pass

    # Build credential dict
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    cred_data = {
        "clientId": cred.clientId,
        "clientSecret": cred.clientSecret,
        "refreshToken": cred.refreshToken,
        "email": cred.email,
        "provider": cred.provider,
        "region": cred.region,
        "subscription": cred.subscription,
        "creditLimit": cred.creditLimit,
        "creditUsed": cred.creditUsed,
        "time": now_str,
        "accessToken": "",
        "expiresAt": "",
    }

    # Write file
    try:
        with open(filepath, "w") as f:
            json.dump(cred_data, f, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write credential file: {e}")

    # Add to account manager
    account_id = str(Path(filepath).resolve())
    from kiro.account_manager import Account
    am._accounts[account_id] = Account(id=account_id)

    # Initialize the account
    success = await am._initialize_account(account_id)

    if success:
        # Mark state dirty so it gets saved
        am._dirty = True
        return {
            "success": True,
            "message": f"Account {filename} added and initialized successfully",
            "account_id": filename.replace(".json", ""),
            "models": len(am._accounts[account_id].model_resolver.get_available_models())
            if am._accounts[account_id].model_resolver
            else 0,
        }
    else:
        # Account file was written but init failed. Still keep the file.
        return JSONResponse(
            status_code=202,
            content={
                "success": True,
                "message": f"Account {filename} file created but initialization failed. The account will retry on next refresh cycle.",
                "account_id": filename.replace(".json", ""),
                "warning": "init_failed",
            }
        )


class ProxySetting(BaseModel):
    proxy_url: str = Field(default="", description="Proxy URL (e.g. http://127.0.0.1:7890)")


@router.get("/admin/api/settings", dependencies=[Depends(verify_admin_key)])
async def get_settings(request: Request):
    """Return current admin settings (key masked, proxy)."""
    settings = _load_admin_settings()
    raw_key = _get_admin_key()
    proxy_url = settings.get("proxy_url", "")

    # Also read PROXY_API_KEY from env
    proxy_api_key = os.getenv("PROXY_API_KEY", "")

    return {
        "admin_key_masked": _mask_key(raw_key),
        "admin_key_prefix": raw_key[:8] + "...",
        "proxy_url": proxy_url,
        "proxy_api_key_masked": _mask_key(proxy_api_key) if proxy_api_key else "",
        "proxy_api_key": proxy_api_key,
    }


@router.post("/admin/api/settings/key/refresh", dependencies=[Depends(verify_admin_key)])
async def refresh_admin_key(request: Request):
    """Generate a new random admin API key."""
    # Generate 32-char random key
    alphabet = string.ascii_letters + string.digits
    new_key = "".join(secrets.choice(alphabet) for _ in range(24))

    settings = _load_admin_settings()
    settings["api_key"] = new_key
    _save_admin_settings(settings)

    return {
        "success": True,
        "new_key": new_key,
        "message": "Admin API key refreshed. Update your client configuration.",
    }


@router.post("/admin/api/settings/proxy", dependencies=[Depends(verify_admin_key)])
async def set_proxy(proxy: ProxySetting, request: Request):
    """Set proxy URL for outgoing Kiro API requests."""
    settings = _load_admin_settings()
    settings["proxy_url"] = proxy.proxy_url
    _save_admin_settings(settings)

    return {
        "success": True,
        "proxy_url": proxy.proxy_url,
        "message": "Proxy saved." if proxy.proxy_url else "Proxy removed.",
    }


@router.delete("/admin/api/settings/proxy", dependencies=[Depends(verify_admin_key)])
async def delete_proxy(request: Request):
    """Remove proxy setting."""
    settings = _load_admin_settings()
    settings.pop("proxy_url", None)
    _save_admin_settings(settings)

    return {"success": True, "message": "Proxy removed."}


class BatchImportRequest(BaseModel):
    accounts: list[AccountCredential]


@router.post("/admin/api/accounts/batch", dependencies=[Depends(verify_admin_key)])
async def batch_add_accounts(req: BatchImportRequest, request: Request):
    """Batch import multiple AWS Q Developer accounts from JSON array."""
    am = request.app.state.account_manager
    results = []
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    for i, cred in enumerate(req.accounts):
        result = {
            "index": i,
            "email": cred.email or f"index-{i}",
            "success": False,
            "file": None,
            "error": None,
        }

        # Validate required fields
        if not cred.clientId or not cred.clientSecret or not cred.refreshToken:
            result["error"] = "Missing required fields (clientId, clientSecret, refreshToken)"
            results.append(result)
            continue

        # Generate next account number
        next_num = _next_account_number()
        filename = f"acct-{next_num:04d}.json"
        filepath = os.path.join(ACCOUNTS_DIR, filename)
        result["file"] = filename

        # Check if email already exists
        if cred.email:
            email_exists = False
            for f in glob.glob(os.path.join(ACCOUNTS_DIR, "*.json")):
                try:
                    with open(f) as fh:
                        existing = json.load(fh)
                    if existing.get("email") == cred.email:
                        email_exists = True
                        break
                except Exception:
                    pass
            if email_exists:
                result["error"] = f"Email {cred.email} already exists"
                results.append(result)
                continue

        # Build credential dict
        cred_data = {
            "clientId": cred.clientId,
            "clientSecret": cred.clientSecret,
            "refreshToken": cred.refreshToken,
            "email": cred.email,
            "provider": cred.provider,
            "region": cred.region,
            "subscription": cred.subscription,
            "creditLimit": cred.creditLimit,
            "creditUsed": cred.creditUsed,
            "time": now_str,
            "accessToken": "",
            "expiresAt": "",
        }

        # Write file
        try:
            with open(filepath, "w") as f:
                json.dump(cred_data, f, indent=2)
        except Exception as e:
            result["error"] = f"Failed to write file: {e}"
            results.append(result)
            continue

        # Add to account manager and initialize
        try:
            account_id = str(Path(filepath).resolve())
            from kiro.account_manager import Account
            am._accounts[account_id] = Account(id=account_id)
            init_ok = await am._initialize_account(account_id)
            if init_ok:
                am._dirty = True
                result["success"] = True
            else:
                result["error"] = "Init failed (will retry on next refresh)"
        except Exception as e:
            result["error"] = f"Init error: {e}"

        results.append(result)

    success_count = sum(1 for r in results if r["success"])
    return {
        "total": len(results),
        "success": success_count,
        "failed": len(results) - success_count,
        "results": results,
    }


class BatchAccountIds(BaseModel):
    account_ids: list[str] = Field(..., description="List of account IDs to process (e.g. acct-0002)")


@router.post("/admin/api/accounts/batch/delete", dependencies=[Depends(verify_admin_key)])
async def batch_delete_accounts(req: BatchAccountIds, request: Request):
    """Delete multiple account files and remove from runtime."""
    am = request.app.state.account_manager
    deleted = 0
    errors = []

    for acct_id in req.account_ids:
        filename = f"{acct_id}.json"
        filepath = os.path.join(ACCOUNTS_DIR, filename)

        # Remove from account manager
        account_key = str(Path(filepath).resolve())
        if account_key in am._accounts:
            del am._accounts[account_key]
            am._dirty = True

        # Delete file
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                deleted += 1
            else:
                errors.append(f"{acct_id}: file not found")
        except Exception as e:
            errors.append(f"{acct_id}: {e}")

    # Also clean up state
    state_data = getattr(am, '_state_data', {})
    accounts_state = state_data.get("accounts", {})
    for acct_id in req.account_ids:
        filepath = str(Path(os.path.join(ACCOUNTS_DIR, f"{acct_id}.json")).resolve())
        accounts_state.pop(filepath, None)

    return {
        "success": True,
        "deleted": deleted,
        "errors": errors,
        "message": f"Deleted {deleted}/{len(req.account_ids)} accounts",
    }


@router.post("/admin/api/accounts/batch/export", dependencies=[Depends(verify_admin_key)])
async def batch_export_accounts(req: BatchAccountIds, request: Request):
    """Export account credentials as JSON array. Returns file data without secrets masking."""
    accounts = []

    for acct_id in req.account_ids:
        filename = f"{acct_id}.json"
        filepath = os.path.join(ACCOUNTS_DIR, filename)
        try:
            with open(filepath) as f:
                data = json.load(f)
            data["_id"] = acct_id
            accounts.append(data)
        except FileNotFoundError:
            continue
        except Exception as e:
            continue

    return {"accounts": accounts, "total": len(accounts)}


@router.post("/admin/api/accounts/refresh-credits", dependencies=[Depends(verify_admin_key)])
async def refresh_accounts_credits(request: Request):
    """Refresh credit usage data for all accounts from the remote Kiro API.
    
    For accounts with an active auth_manager, uses the existing token refresh.
    For uninitialized accounts, reads the JSON file and performs OIDC refresh directly.
    """
    from urllib.parse import quote

    am = request.app.state.account_manager
    results = []
    total_ok = 0
    total_fail = 0

    # Collect all account file paths
    account_files = []
    for aid, acct in am._accounts.items():
        account_files.append((aid, acct))
    # Also scan the directory for any files not in _accounts
    known_paths = {aid for aid, _ in account_files}
    for f in glob.glob(os.path.join(ACCOUNTS_DIR, "*.json")):
        resolved = str(Path(f).resolve())
        if resolved not in known_paths:
            from kiro.account_manager import Account
            account_files.append((resolved, Account(id=resolved)))

    for aid, acct in account_files:
        acct_id = os.path.basename(aid).replace(".json", "")
        result = {"id": acct_id, "success": False, "error": None, "creditLimit": None, "creditUsed": None}

        try:
            # Determine if we have an auth_manager
            auth_mgr = getattr(acct, 'auth_manager', None)

            if auth_mgr:
                # Fast path: use existing auth manager
                token = await auth_mgr.get_access_token()
                q_host = getattr(auth_mgr, 'q_host', 'https://q.us-east-1.amazonaws.com')
                profile_arn = getattr(auth_mgr, 'profile_arn', None) or ""
                region = getattr(auth_mgr, '_region', 'us-east-1')
            else:
                # Slow path: read file, do OIDC refresh ourselves
                filepath = aid
                if not os.path.exists(filepath):
                    result["error"] = "File not found"
                    total_fail += 1
                    results.append(result)
                    continue

                with open(filepath) as f:
                    creds = json.load(f)

                client_id = creds.get("clientId", "")
                client_secret = creds.get("clientSecret", "")
                refresh_token = creds.get("refreshToken", "")
                region = creds.get("region", "us-east-1")

                if not client_id or not client_secret or not refresh_token:
                    result["error"] = "Missing OIDC credentials in file"
                    total_fail += 1
                    results.append(result)
                    continue

                # AWS SSO OIDC refresh
                oidc_url = f"https://oidc.{region}.amazonaws.com/token"
                q_host = f"https://q.{region}.amazonaws.com"

                payload = {
                    "grantType": "refresh_token",
                    "clientId": client_id,
                    "clientSecret": client_secret,
                    "refreshToken": refresh_token,
                }

                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(
                        oidc_url,
                        json=payload,
                        headers={"Content-Type": "application/json"}
                    )

                    if resp.status_code != 200:
                        result["error"] = f"OIDC refresh HTTP {resp.status_code}"
                        total_fail += 1
                        results.append(result)
                        continue

                    oidc_data = resp.json()
                    token = oidc_data.get("accessToken", "")
                    if not token:
                        result["error"] = "No accessToken in OIDC response"
                        total_fail += 1
                        results.append(result)
                        continue

                    # Update the file with new token
                    creds["accessToken"] = token
                    creds["expiresAt"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() + oidc_data.get("expiresIn", 3600)))
                    with open(filepath, "w") as f:
                        json.dump(creds, f, indent=2)

                profile_arn = creds.get("profileArn", "") or ""

            # Build the getUsageLimits URL
            params = "origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true"
            if profile_arn:
                params += f"&profileArn={quote(profile_arn)}"

            url = f"{q_host}/getUsageLimits?{params}"

            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(
                    url,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                        "User-Agent": "KiroGateway/2.4",
                    }
                )

            if resp.status_code != 200:
                result["error"] = f"Usage API returned HTTP {resp.status_code}"
                total_fail += 1
                results.append(result)
                continue

            data = resp.json()

            # Parse usage breakdown
            credit_limit = 0
            credit_used = 0
            breakdown = data.get("usageBreakdownList", [])
            for item in breakdown:
                if item.get("resourceType") == "CREDIT":
                    credit_limit = item.get("usageLimitWithPrecision") or item.get("usageLimit", 0)
                    credit_used = item.get("currentUsageWithPrecision") or item.get("currentUsage", 0)
                    break

            # Update JSON file on disk
            filepath = aid
            if os.path.exists(filepath):
                with open(filepath) as f:
                    file_data = json.load(f)
                file_data["creditLimit"] = credit_limit
                file_data["creditUsed"] = credit_used
                file_data["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
                with open(filepath, "w") as f:
                    json.dump(file_data, f, indent=2)

            result["success"] = True
            result["creditLimit"] = credit_limit
            result["creditUsed"] = credit_used
            total_ok += 1

        except Exception as e:
            result["error"] = str(e)
            total_fail += 1

        results.append(result)

    return {
        "success": True,
        "total": len(results),
        "ok": total_ok,
        "fail": total_fail,
        "results": results,
    }


@router.post("/admin/api/accounts/refresh-credits-single", dependencies=[Depends(verify_admin_key)])
async def refresh_account_credit_single(req: Request):
    """Refresh credit usage for a single account.
    
    Request body: {"account_id": "acct-xxx"}
    Uses the same logic as the batch version but for one account.
    """
    from urllib.parse import quote
    import time

    body = await req.json()
    acct_id = body.get("account_id", "")
    if not acct_id:
        return {"success": False, "error": "Missing account_id"}

    am = req.app.state.account_manager
    filepath = os.path.join(ACCOUNTS_DIR, acct_id + ".json")

    result = {"id": acct_id, "success": False, "error": None, "creditLimit": None, "creditUsed": None}

    try:
        acct = am._accounts.get(filepath) or am._accounts.get(acct_id)
        auth_mgr = getattr(acct, 'auth_manager', None) if acct else None

        if auth_mgr:
            token = await auth_mgr.get_access_token()
            q_host = getattr(auth_mgr, 'q_host', 'https://q.us-east-1.amazonaws.com')
            profile_arn = getattr(auth_mgr, 'profile_arn', None) or ""
            region = getattr(auth_mgr, '_region', 'us-east-1')
        else:
            if not os.path.exists(filepath):
                result["error"] = "File not found"
                return result

            with open(filepath) as f:
                creds = json.load(f)

            client_id = creds.get("clientId", "")
            client_secret = creds.get("clientSecret", "")
            refresh_token = creds.get("refreshToken", "")
            region = creds.get("region", "us-east-1")

            if not client_id or not client_secret or not refresh_token:
                result["error"] = "Missing OIDC credentials in file"
                return result

            oidc_url = f"https://oidc.{region}.amazonaws.com/token"
            q_host = f"https://q.{region}.amazonaws.com"

            payload = {
                "grantType": "refresh_token",
                "clientId": client_id,
                "clientSecret": client_secret,
                "refreshToken": refresh_token,
            }

            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    oidc_url, json=payload,
                    headers={"Content-Type": "application/json"}
                )

            if resp.status_code != 200:
                result["error"] = f"OIDC refresh HTTP {resp.status_code}"
                return result

            oidc_data = resp.json()
            token = oidc_data.get("accessToken", "")
            if not token:
                result["error"] = "No accessToken in OIDC response"
                return result

            creds["accessToken"] = token
            creds["expiresAt"] = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(time.time() + oidc_data.get("expiresIn", 3600)))
            with open(filepath, "w") as f:
                json.dump(creds, f, indent=2)

            profile_arn = creds.get("profileArn", "") or ""

        # Call getUsageLimits API
        params = "origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true"
        if profile_arn:
            params += f"&profileArn={quote(profile_arn)}"

        url = f"{q_host}/getUsageLimits?{params}"

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                    "User-Agent": "KiroGateway/2.4",
                }
            )

        if resp.status_code != 200:
            result["error"] = f"Usage API returned HTTP {resp.status_code}"
            return result

        data = resp.json()

        credit_limit = 0
        credit_used = 0
        breakdown = data.get("usageBreakdownList", [])
        for item in breakdown:
            if item.get("resourceType") == "CREDIT":
                credit_limit = item.get("usageLimitWithPrecision") or item.get("usageLimit", 0)
                credit_used = item.get("currentUsageWithPrecision") or item.get("currentUsage", 0)
                break

        # Update file on disk
        if os.path.exists(filepath):
            with open(filepath) as f:
                file_data = json.load(f)
            file_data["creditLimit"] = credit_limit
            file_data["creditUsed"] = credit_used
            file_data["time"] = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(filepath, "w") as f:
                json.dump(file_data, f, indent=2)

        result["success"] = True
        result["creditLimit"] = credit_limit
        result["creditUsed"] = credit_used

    except Exception as e:
        result["error"] = str(e)

    return result

@router.post("/admin/api/accounts/check-aliveness", dependencies=[Depends(verify_admin_key)])
async def check_accounts_aliveness(request: Request):
    """Full aliveness check for all accounts: token refresh + API call."""
    results = []
    total_ok = 0
    total_fail = 0

    for filepath in sorted(glob.glob(os.path.join(ACCOUNTS_DIR, "*.json"))):
        acct_id = os.path.basename(filepath).replace(".json", "")
        result = {
            "id": acct_id, "alive": False,
            "token_ok": False, "api_ok": False,
            "token_error": None, "api_error": None,
            "creditLimit": None, "creditUsed": None,
        }

        try:
            # Step 1: Read file
            with open(filepath) as f:
                creds = json.load(f)

            client_id = creds.get("clientId", "")
            client_secret = creds.get("clientSecret", "")
            refresh_token = creds.get("refreshToken", "")
            region = creds.get("region", "us-east-1")

            if not client_id or not client_secret or not refresh_token:
                result["token_error"] = "Missing OIDC credentials"
                total_fail += 1
                results.append(result)
                continue

            # Step 2: OIDC token refresh
            oidc_url = f"https://oidc.{region}.amazonaws.com/token"
            q_host = f"https://q.{region}.amazonaws.com"

            payload = {
                "grantType": "refresh_token",
                "clientId": client_id,
                "clientSecret": client_secret,
                "refreshToken": refresh_token,
            }

            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    oidc_url, json=payload,
                    headers={"Content-Type": "application/json"}
                )

            if resp.status_code != 200:
                result["token_error"] = f"OIDC refresh HTTP {resp.status_code}"
                total_fail += 1
                results.append(result)
                continue

            oidc_data = resp.json()
            token = oidc_data.get("accessToken", "")
            if not token:
                result["token_error"] = "No accessToken in response"
                total_fail += 1
                results.append(result)
                continue

            result["token_ok"] = True

            # Step 3: Call getUsageLimits API
            usage_params = "origin=AI_EDITOR&resourceType=AGENTIC_REQUEST&isEmailRequired=true"
            profile_arn = creds.get("profileArn", "") or ""
            if profile_arn:
                from urllib.parse import quote
                usage_params += f"&profileArn={quote(profile_arn)}"

            async with httpx.AsyncClient(timeout=30) as client:
                resp2 = await client.get(
                    f"{q_host}/getUsageLimits?{usage_params}",
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Accept": "application/json",
                        "User-Agent": "KiroGateway/2.4",
                    }
                )

            if resp2.status_code == 200:
                result["api_ok"] = True
                data = resp2.json()
                breakdown = data.get("usageBreakdownList", [])
                for item in breakdown:
                    if item.get("resourceType") == "CREDIT":
                        result["creditLimit"] = item.get("usageLimitWithPrecision") or item.get("usageLimit", 0)
                        result["creditUsed"] = item.get("currentUsageWithPrecision") or item.get("currentUsage", 0)
                        break
            else:
                result["api_error"] = f"Usage API HTTP {resp2.status_code}"

            # Overall: alive if both token and API work
            result["alive"] = result["token_ok"] and result["api_ok"]
            if result["alive"]:
                total_ok += 1
            else:
                total_fail += 1

        except Exception as e:
            result["alive"] = False
            if not result["token_error"]:
                result["token_error"] = str(e)
            total_fail += 1

        results.append(result)

    # Update state.json with aliveness results
    state_path = getattr(request.app.state, '_state_data', None)
    if state_path is not None:
        try:
            state_data = state_path
            state_data["aliveness_check"] = {
                "time": time.time(),
                "total": len(results),
                "alive": total_ok,
                "dead": total_fail,
                "accounts": {r["id"]: {
                    "alive": r["alive"],
                    "token_ok": r["token_ok"],
                    "api_ok": r["api_ok"],
                } for r in results}
            }
        except Exception:
            pass

    return {
        "success": True,
        "total": len(results),
        "alive": total_ok,
        "dead": total_fail,
        "results": results,
    }


@router.get("/admin/api/console/logs", dependencies=[Depends(verify_admin_key)])
async def get_console_logs(request: Request, limit: int = 100):
    """Return recent request logs for the admin console."""
    logs = StatsCollector().get_logs(limit=limit)
    return {"success": True, "data": logs}


@router.get("/admin/api/console/stats", dependencies=[Depends(verify_admin_key)])
async def get_console_stats(request: Request, scale: str = "day"):
    """Return aggregated stats for the admin console chart."""
    if scale not in ("day", "week", "month"):
        scale = "day"
    stats = StatsCollector().get_stats(scale=scale)
    return {"success": True, **stats}

@router.get("/admin", include_in_schema=False)
@router.get("/admin/", include_in_schema=False)
async def admin_redirect():
    return RedirectResponse(url="/admin/static/admin.html")
