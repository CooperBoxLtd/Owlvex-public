# Demo fixture 45 - Safe Python JWT verification

import jwt


def parse_token(token, secret):
    return jwt.decode(token, secret, algorithms=["HS256"])
