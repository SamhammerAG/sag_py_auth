"""Token type definitions
"""
from typing import Dict, Any

JwkDict = Dict[str, str]
JwksDict = Dict[str, JwkDict]
TokenDict = Dict[str, Any]
