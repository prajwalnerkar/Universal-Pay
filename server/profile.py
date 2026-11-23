import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from register import get_connection
from security import get_current_user_id

logger = logging.getLogger("own_profile")

router = APIRouter()


class ProfileData(BaseModel):
    userId: str
    fullName: str
    email: str | None
    mobileNumber: str | None
    createdAt: str


class ProfileResponse(BaseModel):
    success: bool
    data: ProfileData


@router.get("/me", status_code=200, response_model=ProfileResponse)
def get_my_profile(user_id: str = Depends(get_current_user_id)):
    try:
        with get_connection() as conn:
            rows = conn.run(
                """
                SELECT id, full_name, email, mobile_number, created_at
                FROM paymentusers
                WHERE id = :user_id
                """,
                user_id=user_id,
            )

        if not rows:
            # Token was valid but the user no longer exists (deleted account).
            raise HTTPException(status_code=404, detail="User not found")

        row_id, full_name, email, mobile_number, created_at = rows[0]

        return ProfileResponse(
            success=True,
            data=ProfileData(
                userId=str(row_id),
                fullName=full_name,
                email=email,
                mobileNumber=mobile_number,
                createdAt=created_at.isoformat(),
            ),
        )

    except HTTPException:
        raise

    except Exception:
        logger.exception("Unexpected error fetching profile")
        raise HTTPException(status_code=500, detail="Could not fetch profile")