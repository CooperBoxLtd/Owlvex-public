# Demo fixture 38 - Unsafe Python SQL f-string


def load_user(cursor, request):
    user_id = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
