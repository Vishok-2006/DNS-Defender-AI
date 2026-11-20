"""Optional shared-secret protection for the API."""
import secrets

from fastapi import HTTPException, Request


def make_api_key_dependency(key):
    async def require_api_key(request: Request):
        if not key:
            return
        supplied = request.headers.get("x-api-key", "")
        if not secrets.compare_digest(supplied.encode(), key.encode()):
            raise HTTPException(status_code=401, detail="Missing or invalid API key")
    return require_api_key


def ws_authorized(key, supplied) -> bool:
    return not key or secrets.compare_digest((supplied or "").encode(), key.encode())
