import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 60))

_bearer_scheme = HTTPBearer(auto_error=False)


def _require_secret() -> str:
    if not JWT_SECRET:
        # Fail loudly at call time rather than signing/verifying tokens
        # with an empty or missing secret.
        raise RuntimeError(
            "JWT_SECRET environment variable is not set. "
            "Set a long, random value before issuing or verifying tokens."
        )
    return JWT_SECRET


def create_access_token(user_id: str) -> tuple[str, datetime]:
    """Returns (token, expires_at)."""
    secret = _require_secret()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": user_id,
        "iat": datetime.now(timezone.utc),
        "exp": expires_at,
    }
    token = jwt.encode(payload, secret, algorithm=JWT_ALGORITHM)
    return token, expires_at


def decode_access_token(token: str) -> dict:
    secret = _require_secret()
    try:
        return jwt.decode(token, secret, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_current_user_id(
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer_scheme),
) -> str:
    """FastAPI dependency: validates the Bearer token and returns the user id.

    Use this on any route that should require login, e.g.:

        @router.get("/me")
        def me(user_id: str = Depends(get_current_user_id)):
            ...
    """
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing bearer token")

    payload = decode_access_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    return user_id