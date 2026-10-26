import base64
import hashlib
import hmac
import os
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
import jwt
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database.database import get_db
from database.models import User

SESSION_COOKIE_NAME = "student_session"
SESSION_LIFETIME = timedelta(days=7)
JWT_ISSUER = "fastapi-student-records"
JWT_ALGORITHM = "HS256"
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
if len(JWT_SECRET_KEY.encode("utf-8")) < 32:
    raise ValueError("JWT_SECRET_KEY must be set to a secret of at least 32 bytes in .env")

PASSWORD_HASH_ITERATIONS = 600_000
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").strip().casefold() == "true"
auth_router = APIRouter(prefix="/auth", tags=["authentication"])


class LoginCredentials(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    password: str = Field(min_length=1, max_length=128)


class RegistrationCredentials(LoginCredentials):
    password: str = Field(min_length=12, max_length=128)


class UserInfo(BaseModel):
    username: str


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
    )
    return "$".join(
        (
            "pbkdf2_sha256",
            str(PASSWORD_HASH_ITERATIONS),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(password_hash).decode("ascii"),
        )
    )


_DUMMY_PASSWORD_HASH = _hash_password(
    "not-a-real-password",
    salt=b"auth-dummy-salt!!",
)


def _verify_password(password: str, encoded_hash: str) -> bool:
    try:
        algorithm, iterations_value, salt_value, hash_value = encoded_hash.split("$")
        iterations = int(iterations_value)
        if algorithm != "pbkdf2_sha256" or not 100_000 <= iterations <= 1_000_000:
            return False
        salt = base64.b64decode(salt_value, validate=True)
        expected_hash = base64.b64decode(hash_value, validate=True)
    except (ValueError, TypeError):
        return False

    actual_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def get_optional_user(
    session_token: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> UserInfo | None:
    if not session_token:
        return None

    try:
        claims = jwt.decode(
            session_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            issuer=JWT_ISSUER,
            options={"require": ["exp", "iat", "iss", "sub", "username"]},
        )
    except jwt.InvalidTokenError:
        return None

    username = claims.get("username")
    if not isinstance(username, str):
        return None
    return UserInfo(username=username)


def get_current_user(user: UserInfo | None = Depends(get_optional_user)) -> UserInfo:
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user


def _issue_token(user: User, response: Response) -> None:
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + SESSION_LIFETIME
    token = jwt.encode(
        {
            "sub": str(user.id),
            "username": user.username,
            "iss": JWT_ISSUER,
            "iat": issued_at,
            "exp": expires_at,
        },
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


def _normalized_username(username: str) -> str:
    return username.strip().casefold()


@auth_router.post(
    "/register",
    response_model=UserInfo,
    status_code=status.HTTP_201_CREATED,
)
def register(
    credentials: RegistrationCredentials,
    response: Response,
    db: Session = Depends(get_db),
) -> UserInfo:
    username = _normalized_username(credentials.username)
    if len(username) < 3:
        raise HTTPException(status_code=422, detail="Username must be at least 3 characters")

    if db.scalar(select(User.id).where(User.username == username)) is not None:
        raise HTTPException(status_code=409, detail="Username is already registered")

    user = User(username=username, password_hash=_hash_password(credentials.password))
    try:
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username is already registered") from error

    _issue_token(user, response)
    return UserInfo(username=user.username)


@auth_router.post("/login", response_model=UserInfo)
def login(
    credentials: LoginCredentials,
    response: Response,
    db: Session = Depends(get_db),
) -> UserInfo:
    username = _normalized_username(credentials.username)
    user = db.scalar(select(User).where(User.username == username))
    stored_hash = user.password_hash if user is not None else _DUMMY_PASSWORD_HASH

    if not _verify_password(credentials.password, stored_hash) or user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    _issue_token(user, response)
    return UserInfo(username=user.username)


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    response: Response,
) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/",
    )


@auth_router.get("/me", response_model=UserInfo)
def current_user(user: UserInfo = Depends(get_current_user)) -> UserInfo:
    return user
