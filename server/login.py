import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, model_validator

from register import get_connection, password_hash
from security import create_access_token

logger = logging.getLogger("own_login")

router = APIRouter()


class LoginRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def normalize_identifier(self):
        value = self.identifier.strip()
        if not value:
            raise ValueError("Email or mobile number is required")

        digits = value.lstrip("+")
        if digits.isdigit():
            has_plus = value.startswith("+")
            value = ("+" if has_plus else "+") + digits
        else:
            value = value.lower()

        self.identifier = value
        return self


class LoginData(BaseModel):
    userId: str
    fullName: str
    accessToken: str
    tokenType: str = "bearer"
    expiresAt: str


class LoginResponse(BaseModel):
    success: bool
    message: str
    data: LoginData


@router.post("/login", status_code=200, response_model=LoginResponse)
def login_user(request: LoginRequest):
    identifier = request.identifier

    try:
        with get_connection() as conn:
            rows = conn.run(
                """
                SELECT id, full_name, password_hash
                FROM paymentusers
                WHERE email = :identifier OR mobile_number = :identifier
                """,
                identifier=identifier,
            )

        if not rows:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        user_id, full_name, stored_hash = rows[0]

        if not password_hash.verify(request.password, stored_hash):
            raise HTTPException(status_code=401, detail="Invalid credentials")

        token, expires_at = create_access_token(user_id=str(user_id))

        return LoginResponse(
            success=True,
            message="Login successful",
            data=LoginData(
                userId=str(user_id),
                fullName=full_name,
                accessToken=token,
                expiresAt=expires_at.isoformat(),
            ),
        )

    except HTTPException:
        raise

    except Exception:
        logger.exception("Unexpected error during login")
        raise HTTPException(status_code=500, detail="Login failed")