"""
waf/normalizer.py
-----------------
Input normalization before inspection.

Attackers often encode their payloads to bypass simple pattern matching.
For example: %3Cscript%3E is URL-encoded <script>
Normalizing first gives us a cleaner string to inspect.
"""

import html
from urllib.parse import unquote_plus


def normalize(value: str) -> str:
    """
    Apply multiple decoding passes to a string.

    Why multiple passes?
    Double-encoding is a common evasion: %253Cscript%253E
    First decode: %3Cscript%3E
    Second decode: <script>
    """
    if not value:
        return value

    result = value

    # Pass 1: URL decode (handles %3C, +, etc.)
    result = unquote_plus(result)

    # Pass 2: URL decode again (catches double-encoded payloads)
    result = unquote_plus(result)

    # Pass 3: HTML entity decode (&lt; → <, &#60; → <, etc.)
    result = html.unescape(result)

    # Pass 4: Lower-case for case-insensitive matching
    # We return the lowercase version for pattern matching only.
    # The original value is preserved separately for logging.
    result = result.lower()

    return result
