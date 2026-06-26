import requests


def get_client_credentials_token(
    token_url: str, client_id: str, client_secret: str
) -> str:
    """Fetch an access token from the url using the client credentials flow.

    Returns: The access token string
    """
    response = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]
