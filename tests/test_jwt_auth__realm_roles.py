from fastapi import HTTPException
import pytest
from sag_py_auth.jwt_auth import JwtAuth
from sag_py_auth.models import AuthConfig
from .helpers import get_token


def test__verify_realm_roles__has_multiple():
    # Arrange
    jwt_auth = JwtAuth(
        AuthConfig("https://authserver.com/auth/realms/projectName", "audienceOne"),
        None,
        ["realmRoleOne", "realmRoleTwo"])

    realm_access = {
        "roles": ["realmRoleOne", "realmRoleTwo"]
    }

    token = get_token(realm_access, None)

    # Act
    try:
        jwt_auth._verify_realm_roles(token)
    except Exception:
        pytest.fail("No exception expected if the user has all realm roles")


def test__verify_realm_roles__requires_none():
    # Arrange
    jwt_auth = JwtAuth(
        AuthConfig("https://authserver.com/auth/realms/projectName", "audienceOne"),
        None,
        None)

    realm_access = {
        "roles": ["realmRoleOne", "realmRoleTwo"]
    }

    token = get_token(realm_access, None)

    # Act
    try:
        jwt_auth._verify_realm_roles(token)
    except Exception:
        pytest.fail("No exception expected if no roles are required")


def test__verify_realm_roles__requires_empty():
    # Arrange
    jwt_auth = JwtAuth(
        AuthConfig("https://authserver.com/auth/realms/projectName", "audienceOne"),
        None,
        [])

    realm_access = {
        "roles": ["realmRoleOne", "realmRoleTwo"]
    }

    token = get_token(realm_access, None)

    # Act
    try:
        jwt_auth._verify_realm_roles(token)
    except Exception:
        pytest.fail("No exception expected if no roles are required")


def test__verify_realm_roles__missing_realm_role():
    with pytest.raises(HTTPException) as exception:

        # Arrange
        jwt_auth = JwtAuth(
            AuthConfig("https://authserver.com/auth/realms/projectName", "audienceOne"),
            None,
            ["realmRoleOne", "realmRoleTwo"])

        realm_access = {
            "roles": ["realmRoleOne"]
        }

        token = get_token(realm_access, None)

        # Act
        jwt_auth._verify_realm_roles(token)

    # Assert
    assert exception.value.status_code == 403
    assert exception.value.detail == "Missing realm role."


def test__verify_realm_roles__token_with_empty_realm_roles():
    with pytest.raises(HTTPException) as exception:

        # Arrange
        jwt_auth = JwtAuth(
            AuthConfig("https://authserver.com/auth/realms/projectName", "audienceOne"),
            None,
            ["realmRoleOne", "realmRoleTwo"])

        token = get_token({}, None)

        # Act
        jwt_auth._verify_realm_roles(token)

    # Assert
    assert exception.value.status_code == 403
    assert exception.value.detail == "Missing realm role."


def test__verify_realm_roles__token_without_realm_roles():
    with pytest.raises(HTTPException) as exception:

        # Arrange
        jwt_auth = JwtAuth(
            AuthConfig("https://authserver.com/auth/realms/projectName", "audienceOne"),
            None,
            ["realmRoleOne", "realmRoleTwo"])

        token = get_token(None, None)

        # Act
        jwt_auth._verify_realm_roles(token)

    # Assert
    assert exception.value.status_code == 403
    assert exception.value.detail == "Missing realm role."
