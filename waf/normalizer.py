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
import base64
import unicodedata

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

    #Multiple URL decode passes (handles deep encoding)
    for _ in range(3):
        decoded = unquote_plus(result)
        if decoded == result:
            break
        result = decoded

    #HTML decode
    result = html.unescape(result)

    #Unicode normalization (important for obfuscation)
    result = unicodedata.normalize("NFKC", result)

    #Attempt base64 decode (safe attempt)
    try:
        #Basic heuristic: base64 strings are longer & no spaces
        if len(result) > 8 and " " not in result:
            decoded = base64.b64decode(result).decode(errors="ignore")
            if decoded:
                result += " " + decoded  
    except:
        pass

    result = result.lower()

    return result