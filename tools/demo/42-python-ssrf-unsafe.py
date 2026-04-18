# Demo fixture 42 - Unsafe Python outbound request

import requests


def fetch_avatar(request):
    url = request.args.get("url")
    return requests.get(url)
