from .helpers import get_token


def test__token__get_field_value__with_existing_key():
    # Arrange
    token = get_token(None, None)

    # Act
    actual = token.get_field_value("azp")

    # Assert
    assert actual == "public-project-swagger"


def test__token__get_field_value__with_missing_key():
    # Arrange
    token = get_token(None, None)

    # Act
    actual = token.get_field_value("missingKey")

    # Assert
    assert actual == ""


def test__token__roles():
    # Arrange
    resource_access = {
            "clientOne": {
                "roles": [
                    "clientOneRoleOne",
                    "clientOneRoleTwo"
                ]
            },
            "clientTwo": {
                "roles": [
                    "clientTwoRoleOne",
                    "clientTwoRoleTwo"
                ]
            }
        }

    token = get_token(None, resource_access)

    # Act
    actual_client_one = token.get_roles("clientOne")
    actual_missing_client = token.get_roles("missingClient")

    actual_has_one = token.has_role("clientOne", "clientOneRoleOne")
    actual_has_missing_role = token.has_role("clientOne", "missingRole")
    actual_has_missing_client = token.has_role("missingClient", "missingRole")

    # Assert
    assert actual_client_one == ["clientOneRoleOne", "clientOneRoleTwo"]
    assert actual_missing_client == []
    assert actual_has_one
    assert not actual_has_missing_role
    assert not actual_has_missing_client


def test__token__realm_roles():
    # Arrange
    realm_access = {
        "roles": ["realmRoleOne", "realmRoleTwo"]
    }

    token = get_token(realm_access, None)

    # Act
    actual_realm_roles = token.get_realm_roles()

    actual_has_one = token.has_realm_role("realmRoleOne")
    actual_has_missing = token.has_realm_role("missingRole")

    # Assert
    assert actual_realm_roles == ["realmRoleOne", "realmRoleTwo"]
    assert actual_has_one
    assert not actual_has_missing
