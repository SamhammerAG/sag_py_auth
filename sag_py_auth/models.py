from typing import List
from .token_types import TokenDict


class AuthConfig():
    """Auth configuration used to validate the token
    """
    def __init__(self, issuer: str, audience: str):
        self.issuer = issuer
        self.audience = audience


class Token():
    """The authentication token
    """
    def __init__(self, token_dict: TokenDict):
        self.token_dict = token_dict

    def get_field_value(self, field_name: str) -> str:
        """Gets the value of a specified token claim field

        Returns: The claim field value
        """
        try:
            return self.token_dict[field_name]
        except KeyError:
            return ""

    def get_roles(self, client) -> List[str]:
        """Gets all roles of a specific client

        Returns: The client roles
        """
        try:
            return self.token_dict['resource_access'][client]['roles']
        except KeyError:
            return []

    def has_role(self, client, role_name) -> bool:
        """Checks if a specific client of the token has a role

        Returns: True if the client has the role
        """
        roles: List[str] = self.get_roles(client)
        return role_name in roles

    def get_realm_roles(self) -> List[str]:
        """Gets all realm roles

        Returns: The realm roles
        """
        try:
            return self.token_dict['realm_access']['roles']
        except KeyError:
            return []

    def has_realm_role(self, role_name) -> bool:
        """Checks if the token has a realm role

        Returns: True if the token has the client role
        """
        roles: List[str] = self.get_realm_roles()
        return role_name in roles


class TokenRole():
    """
    Define required token auth roles
    """
    def __init__(self, client: str, role: str):
        self.client = client
        self.role = role
