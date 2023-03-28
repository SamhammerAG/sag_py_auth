import requests

from jose import jwt

from .token_types import JwkDict, JwksDict, TokenDict
from .models import AuthConfig

CACHED_JWK = None


def verify_and_decode_token(auth_config: AuthConfig, token_string: str) -> TokenDict:
    """Decode and verify the token

    Returns: The token
    """
    global CACHED_JWK

    if not CACHED_JWK:
        CACHED_JWK = _get_token_jwk(auth_config.issuer, token_string)

    # "decode" also verifies signature, issuer, audience, expiration and more
    token: TokenDict = jwt.decode(
        token=token_string,
        key=CACHED_JWK,
        audience=auth_config.audience,
        issuer=auth_config.issuer
    )
    return token


def _get_token_jwk(issuer: str, token_string: str) -> JwksDict:
    """Gets the key set sent from the auth provider (idp)
    that belongs to the token in the parameter. The correct
    key set is identified by key id (kid). The kid is part
    of the header information of the token.

    Returns: The key set that belongs to the token
    """

    token_header: dict = jwt.get_unverified_header(token_string)
    token_key_id: str = token_header['kid']

    auth_provider_jwks: JwksDict = _get_auth_provider_jwks(issuer)
    token_jwk: JwkDict = auth_provider_jwks[token_key_id]
    return token_jwk


def _get_auth_provider_jwks(issuer: str) -> JwksDict:
    """Json web tokens are completely verified on the client side.
    The token is signed by the auth provider (idp) to avoid manipulation.
    To verify if the token is from the expected idp we need to request the
    public key and signing algorithm information from the idp.
    One idp can have multiple json web key sets (jwks). The key set is
    identified by the key id (kid) sent by the server.

    Returns: All key sets of the idp
    """
    jwks_request_url = f"{issuer}/protocol/openid-connect/certs"
    jwks_request_headers: dict = {'content-type': 'application/json'}
    timeout_seconds = 30
    jwks_response: dict = requests.get(jwks_request_url, headers=jwks_request_headers, timeout=timeout_seconds).json()

    jwks: JwksDict = {jwk["kid"]: jwk for jwk in jwks_response['keys']}
    return jwks
