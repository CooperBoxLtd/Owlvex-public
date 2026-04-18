# Demo fixture 43 - Safe Python outbound request

import requests


def fetch_avatar():
    return requests.get("https://example.com/avatar.png")
