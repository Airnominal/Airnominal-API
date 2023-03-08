import os
from typing import Union
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from fastapi_sso.sso.github import GithubSSO
from datetime import datetime, timedelta
from fastapi import FastAPI, Request, Depends, HTTPException, APIRouter, Response
from config import CLIENT_ID, CLIENT_SECRET, redirect_url, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, redirect_url_main_page
from fastapi.responses import RedirectResponse
router = APIRouter()


#config for github SSO
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"



sso = GithubSSO(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri=redirect_url,
    allow_insecure_http=True,
)

security = HTTPBearer()

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def has_access_and_get_user(credentials: HTTPAuthorizationCredentials):
    """
        Function that is used to validate the token in the case that it requires it
    """
    try:
        token = credentials.credentials
        payload = jwt.decode(token, key='secret', options={"verify_signature": False,
                                                           "verify_aud": False,
                                                           "verify_iss": False})
        return payload
    except JOSEError as e:
        raise HTTPException(
            status_code=401,
            detail=str(e))

@router.get("/auth/login")
async def auth_init():
    """Initialize auth and redirect"""
    return await sso.get_login_redirect()

@router.get("/auth/callback")
async def auth_callback(request: Request, response: Response):
    """Verify login"""
    user = await sso.verify_and_process(request)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=dict(user), expires_delta=access_token_expires
    )
    print(dict(user))
    response.set_cookie("Authorization", access_token)
    return RedirectResponse(redirect_url_main_page)

@router.get("/auth/logout")
async def auth_logout(response: Response):
    response.delete_cookie("Authorization")
    return True