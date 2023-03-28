import pytest
from sag_py_auth.jwt_auth import JwtAuth
from sag_py_auth.models import AuthConfig, TokenRole


def test__jwt_auth__init__with_valid_params__verify_flow():
    # Arrange
    auth_config = AuthConfig("https://authserver.com/auth/realms/projectName", "audienceOne")
    required_roles = [TokenRole("clientOne", "clientOneRoleOne")]
    required_realm_roles = ["realmRoleOne"]

    # Act
    jwt = JwtAuth(auth_config, required_roles, required_realm_roles)

    # Assert
    assert jwt.required_roles == required_roles
    assert jwt.required_realm_roles == required_realm_roles
    assert jwt.model.flows.authorizationCode.authorizationUrl \
        == "https://authserver.com/auth/realms/projectName/protocol/openid-connect/auth"
    assert jwt.model.flows.authorizationCode.tokenUrl \
        == "https://authserver.com/auth/realms/projectName/protocol/openid-connect/token"


def test__jwt_auth__init__with_invalid_issuer():
    with pytest.raises(Exception) as exception:
        # Arrange
        auth_config = AuthConfig("malformedUrl", "audienceOne")
        required_roles = [TokenRole("clientOne", "clientOneRoleOne")]
        required_realm_roles = ["realmRoleOne"]

        # Act
        JwtAuth(auth_config, required_roles, required_realm_roles)

    # Assert
    assert "Invalid issuer or audience" in str(exception)


def test__jwt_auth__init__with_empty_audience():
    with pytest.raises(Exception) as exception:
        # Arrange
        auth_config = AuthConfig("https://authserver.com/auth/realms/projectName", "")
        required_roles = [TokenRole("clientOne", "clientOneRoleOne")]
        required_realm_roles = ["realmRoleOne"]

        # Act
        JwtAuth(auth_config, required_roles, required_realm_roles)

    # Assert
    assert "Invalid issuer or audience" in str(exception)


def test__jwt_auth__init__with_none_audience():
    with pytest.raises(Exception) as exception:
        # Arrange
        auth_config = AuthConfig("https://authserver.com/auth/realms/projectName", None)
        required_roles = [TokenRole("clientOne", "clientOneRoleOne")]
        required_realm_roles = ["realmRoleOne"]

        # Act
        JwtAuth(auth_config, required_roles, required_realm_roles)

    # Assert
    assert "Invalid issuer or audience" in str(exception)
