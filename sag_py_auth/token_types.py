"""Token type definitions
"""

from typing import Any

JwkDict = dict[str, str]
JwksDict = dict[str, JwkDict]
TokenDict = dict[str, Any]
