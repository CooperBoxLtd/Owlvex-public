# Demo fixture 27 — Untrusted payload parsed as JSON and validated as data
#
# Companion to 26. The input stays in a data-only structure.

import json


def load_profile(request):
    payload = json.loads(request.body)
    return {
        "name": payload.get("name"),
        "role": payload.get("role"),
    }
