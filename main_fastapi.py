import os
import uuid
import jwt as pyjwt
import yaml
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.openapi.docs import get_swagger_ui_html
from auth.file_auth import authenticate_file
from auth.ldap_auth import authenticate_ldap, LDAP_AVAILABLE
from utils.api_key import get_additional_claims

# Load environment variables
load_dotenv()

# Configuration
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "dev-secret-key")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
REFRESH_TOKEN_EXPIRES = timedelta(days=30)
AUTH_METHOD = os.getenv("AUTH_METHOD", "file").lower()
ALWAYS_USE_BASE_CLAIMS = os.getenv("ALWAYS_USE_BASE_CLAIMS", "true").lower() == "true"

if AUTH_METHOD == "ldap" and not LDAP_AVAILABLE:
    AUTH_METHOD = "file"

# FastAPI app
app = FastAPI(
    title="JWT Auth API",
    description="API for generating, refreshing, decoding, and validating JWT tokens",
    version="1.0.0",
    docs_url="/jwt-docs",       # Swagger UI
    redoc_url="/redoc",         # ReDoc UI
    openapi_url="/openapi.json" # OpenAPI spec for Swagger UI
)

@app.get("/", include_in_schema=False)
def root():
    return {
        "message": "Welcome to JWT Auth API",
        "swagger_ui": "/jwt-docs",
        "redoc_ui": "/redoc"
    }
    
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

class LoginRequest(BaseModel):
    username: str
    password: str
    api_key: Optional[str] = None
    secret: Optional[str] = None

class TokenRequest(BaseModel):
    token: str
    skipVerification: Optional[bool] = False
    secret: Optional[str] = None

def get_team_id_from_user(username, user_data):
    groups = user_data.get("groups", [])
    if "administrators" in groups or "admins" in groups:
        return "admin-team"
    elif "ai-team" in groups:
        return "ai-team"
    elif "ml-team" in groups:
        return "ml-team"
    return "general-users"

def generate_token_pair(username, user_data, api_key=None, custom_secret=None):
    user_context = {
        "user_id": username,
        "email": user_data.get("email", ""),
        "groups": user_data.get("groups", []),
        "roles": user_data.get("roles", []),
        "team_id": get_team_id_from_user(username, user_data)
    }

    claims = get_additional_claims(api_key, user_context) if api_key else get_additional_claims(None, user_context)
    all_claims = {**user_data, **claims}
    expires_delta = timedelta(hours=all_claims.pop("exp_hours", 1))
    
    now = datetime.now(timezone.utc)
    access_payload = {
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "exp": now + expires_delta,
        "sub": username,
        "type": "access",
        "fresh": True,
        **all_claims
    }

    refresh_payload = {
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "exp": now + REFRESH_TOKEN_EXPIRES,
        "sub": username,
        "type": "refresh",
        **all_claims
    }

    secret = custom_secret or JWT_SECRET_KEY
    access_token = pyjwt.encode(access_payload, secret, algorithm=JWT_ALGORITHM)
    refresh_token = pyjwt.encode(refresh_payload, secret, algorithm=JWT_ALGORITHM)

    return access_token, refresh_token

@app.post("/token")
def generate_token(request: LoginRequest):
    if AUTH_METHOD == "ldap":
        authenticated, user_data = authenticate_ldap(request.username, request.password)
    else:
        authenticated, user_data = authenticate_file(request.username, request.password)

    if not authenticated:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    access_token, refresh_token = generate_token_pair(
        username=request.username,
        user_data=user_data,
        api_key=request.api_key,
        custom_secret=request.secret
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "note": "Custom secret used" if request.secret else "Standard token"
    }

@app.post("/decode")
def decode_token(request: TokenRequest):
    secret = request.secret or JWT_SECRET_KEY
    try:
        decoded = pyjwt.decode(request.token, secret, algorithms=[JWT_ALGORITHM])
        return {"decoded": decoded}
    except Exception as e:
        if request.skipVerification:
            try:
                decoded = pyjwt.decode(request.token, options={"verify_signature": False})
                return {
                    "decoded": decoded,
                    "warning": "Signature verification skipped"
                }
            except Exception as e2:
                raise HTTPException(status_code=400, detail=f"Invalid token: {str(e2)}")
        else:
            raise HTTPException(status_code=400, detail=f"Decode error: {str(e)}")

@app.post("/validate")
def validate_token(request: TokenRequest):
    try:
        decoded = pyjwt.decode(request.token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        exp = datetime.fromtimestamp(decoded['exp'])
        iat = datetime.fromtimestamp(decoded['iat'])
        return {
            "valid": True,
            "expired": exp < datetime.utcnow(),
            "issued_at": iat.isoformat(),
            "expiry_time": exp.isoformat(),
            "subject": decoded.get('sub', 'unknown')
        }
    except Exception as e:
        return {
            "valid": False,
            "error": str(e)
        }

@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        decoded = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return {"message": "Access granted", "user": decoded.get("sub")}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.post("/refresh")
def refresh_token(token: str = Depends(oauth2_scheme)):
    try:
        decoded = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if decoded.get("type") != "refresh":
            raise HTTPException(status_code=400, detail="Not a refresh token")

        username = decoded["sub"]
        claims = {k: v for k, v in decoded.items() if k not in {"exp", "iat", "nbf", "jti", "type", "fresh"}}
        new_token = pyjwt.encode({
            "sub": username,
            "type": "access",
            "iat": datetime.now(timezone.utc),
            "nbf": datetime.now(timezone.utc),
            "jti": str(uuid.uuid4()),
            "exp": datetime.now(timezone.utc) + ACCESS_TOKEN_EXPIRES,
            "fresh": False,
            **claims
        }, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        return {"access_token": new_token}
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Refresh failed: {str(e)}")

@app.post("/sensitive-action")
def sensitive_action(token: str = Depends(oauth2_scheme)):
    try:
        decoded = pyjwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if not decoded.get("fresh", False):
            raise HTTPException(status_code=403, detail="Fresh token required")

        return {
            "message": "Sensitive action succeeded",
            "user": decoded.get("sub"),
            "claims": decoded
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))
