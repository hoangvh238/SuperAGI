from fastapi import Depends, HTTPException, Security, status, Request
from fastapi.security import APIKeyHeader
from fastapi_jwt_auth import AuthJWT
from fastapi_sqlalchemy import db
from sqlalchemy import or_

from superagi.config.config import get_config
from superagi.models.organisation import Organisation
from superagi.models.user import User
from superagi.models.api_key import ApiKey


def check_auth(Authorize: AuthJWT = Depends()):
    """
    Check user authentication using JWT.
    Skips validation in DEV environment.
    """
    env = get_config("ENV", "DEV")
    if env == "PROD":
        Authorize.jwt_required()
    return Authorize


def get_user_organisation(Authorize: AuthJWT = Depends(check_auth), request: Request = None):
    """
    Retrieve the organisation associated with the authenticated user.
    """
    user = get_current_user(Authorize, request)
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthenticated")
    organisation = db.session.query(Organisation).filter(Organisation.id == user.organisation_id).first()
    return organisation


def get_current_user(
    Authorize: AuthJWT = Depends(check_auth),
    request: Request
):
    """
    Retrieve the current user from JWT or HTTP Basic Auth in production.
    """
    env = get_config("ENV", "DEV")

    if env == "DEV":
        email = "super6@agi.com"
    else:
        # In PROD: Check the Authorization header
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Basic '):
            import base64
            auth_decoded = base64.b64decode(auth_header.split(' ')[1]).decode('utf-8')
            username, _ = auth_decoded.split(':')
            email = username
        else:
            email = Authorize.get_jwt_subject()

    user = db.session.query(User).filter(User.email == email).first()
    return user


api_key_header = APIKeyHeader(name="X-API-Key")


def validate_api_key(api_key: str = Security(api_key_header)) -> str:
    """
    Validate whether the provided API key is valid and not expired.
    """
    query_result = db.session.query(ApiKey).filter(
        ApiKey.key == api_key,
        or_(ApiKey.is_expired == False, ApiKey.is_expired == None)
    ).first()
    if query_result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )

    return query_result.key


def get_organisation_from_api_key(api_key: str = Security(api_key_header)) -> Organisation:
    """
    Retrieve the organisation associated with the provided API key.
    """
    query_result = db.session.query(ApiKey).filter(
        ApiKey.key == api_key,
        or_(ApiKey.is_expired == False, ApiKey.is_expired == None)
    ).first()
    if query_result is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API Key",
        )

    organisation = db.session.query(Organisation).filter(
        Organisation.id == query_result.org_id
    ).first()
    return organisation
