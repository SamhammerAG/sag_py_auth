from sag_py_auth.auth_context import get_token as get_token_from_context, set_token as set_token_to_context
from tests.helpers import get_token as get_test_token


# Note: This test is not entirely independent of the other test
# because they run in the same context and therefor share a context.
# That's why the "not_set_token" test has to run befoe the "with_previously_set_token"
# Forthermore other tests that run the __call__ method of jwt_auth could breatk that one.
def test__get_token__not_set_token():
    # Act
    actual = get_token_from_context()

    assert actual is None


def test__get_token__with_perviously_set_token():
    # Arrange
    token = get_test_token(None, None)

    # Act
    set_token_to_context(token)
    actual = get_token_from_context()

    assert actual == token
