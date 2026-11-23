import logging
import os
import queue
import threading
from contextlib import contextmanager

from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException
from pg8000.native import Connection, DatabaseError
from pydantic import BaseModel, EmailStr, Field, model_validator
from pwdlib import PasswordHash

load_dotenv()

logger = logging.getLogger("own_registration")

router = APIRouter()
password_hash = PasswordHash.recommended()


EMAIL_UNIQUE_CONSTRAINT = "paymentusers_email_key"
MOBILE_UNIQUE_CONSTRAINT = "paymentusers_mobile_number_key"



class SimpleConnectionPool:
    def __init__(self, min_size: int = 2, max_size: int = 10):
        self._max_size = max_size
        self._pool: "queue.LifoQueue[Connection]" = queue.LifoQueue(maxsize=max_size)
        self._created = 0
        self._lock = threading.Lock()

        for _ in range(min_size):
            self._pool.put(self._new_connection())
            self._created += 1

    def _new_connection(self) -> Connection:
        return Connection(
            host=os.getenv("DB_HOST"),
            port=int(os.getenv("DB_PORT", 5432)),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
        )

    def acquire(self) -> Connection:
        try:
            return self._pool.get_nowait()
        except Exception:
            with self._lock:
                if self._created < self._max_size:
                    self._created += 1
                    return self._new_connection()
            return self._pool.get(timeout=10)

    def release(self, conn: Connection, broken: bool = False) -> None:
        if broken:
            with self._lock:
                self._created -= 1
            try:
                conn.close()
            except Exception:
                pass
            return
        try:
            self._pool.put_nowait(conn)
        except Exception:
            conn.close()
            with self._lock:
                self._created -= 1

    def close_all(self) -> None:
        while not self._pool.empty():
            try:
                self._pool.get_nowait().close()
            except Exception:
                pass


_pool: SimpleConnectionPool | None = None


def init_pool() -> None:
    global _pool
    if _pool is None:
        _pool = SimpleConnectionPool(min_size=2, max_size=10)


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close_all()
        _pool = None


@contextmanager
def get_connection():
    if _pool is None:
        init_pool()
    assert _pool is not None

    conn = _pool.acquire()
    broken = False
    try:
        yield conn
    except Exception:
        broken = True
        raise
    finally:
        _pool.release(conn, broken=broken)


class RegisterRequest(BaseModel):
    fullName: str = Field(min_length=2, max_length=150)
    email: EmailStr | None = None
    mobileNumber: str | None = Field(default=None, min_length=10, max_length=20)
    password: str = Field(min_length=8, max_length=128)

    @model_validator(mode="after")
    def validate_contact(self):
        if not self.email and not self.mobileNumber:
            raise ValueError("Email or mobile number is required")

        if not self.fullName.strip():
            raise ValueError("Full name cannot be empty")

        if self.mobileNumber:
            normalized = self.mobileNumber.strip()
            has_plus = normalized.startswith("+")
            digits = normalized.lstrip("+")

            if not digits.isdigit():
                raise ValueError("Mobile number must contain only digits, optionally prefixed with '+'")

            if len(digits) < 8 or len(digits) > 15:
                raise ValueError("Mobile number must be between 8 and 15 digits")

            self.mobileNumber = ("+" if has_plus else "+") + digits

        return self


class RegisterData(BaseModel):
    userId: str
    fullName: str
    email: str | None
    mobileNumber: str | None
    createdAt: str


class RegisterResponse(BaseModel):
    success: bool
    message: str
    data: RegisterData



@router.post("/register", status_code=201, response_model=RegisterResponse)
def register_user(request: RegisterRequest):
    full_name = request.fullName.strip()
    email = str(request.email).lower() if request.email else None
    mobile_number = request.mobileNumber if request.mobileNumber else None

    hashed_password = password_hash.hash(request.password)

    try:
        with get_connection() as conn:
            rows = conn.run(
                """
                INSERT INTO paymentusers
                    (full_name, email, mobile_number, password_hash)
                VALUES (:full_name, :email, :mobile_number, :password_hash)
                RETURNING id, created_at
                """,
                full_name=full_name,
                email=email,
                mobile_number=mobile_number,
                password_hash=hashed_password,
            )
            user_id, created_at = rows[0]

        return RegisterResponse(
            success=True,
            message="User registered successfully",
            data=RegisterData(
                userId=str(user_id),
                fullName=full_name,
                email=email,
                mobileNumber=mobile_number,
                createdAt=created_at.isoformat(),
            ),
        )

    except DatabaseError as error:
        detail = str(error)
        sqlstate = error.args[0].get("C") if error.args else None

        if sqlstate == "23505":
            if EMAIL_UNIQUE_CONSTRAINT in detail:
                raise HTTPException(status_code=409, detail="Email already registered")
            if MOBILE_UNIQUE_CONSTRAINT in detail:
                raise HTTPException(status_code=409, detail="Mobile number already registered")
            raise HTTPException(
                status_code=409,
                detail="Email or mobile number already registered",
            )

        logger.exception("Database error during registration")
        raise HTTPException(status_code=500, detail="Registration failed")

    except HTTPException:
        raise

    except Exception:
        logger.exception("Unexpected error during registration")
        raise HTTPException(status_code=500, detail="Registration failed")