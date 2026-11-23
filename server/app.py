import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from login import router as login_router
from profile import router as profile_router
from register import close_pool, init_pool, router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_pool()
    yield
    close_pool()


app = FastAPI(
    title="own Registration API",
    description="API for user registration using email or mobile number",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(
    router,
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

app.include_router(
    login_router,
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

app.include_router(
    profile_router,
    prefix="/api/v1/users",
    tags=["Users"],
)


@app.get("/")
def home():
    return {
        "success": True,
        "message": "User Registration API is running",
    }