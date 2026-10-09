import jwt
import yaml
from flask import redirect, request

SESSION_COOKIE_SECURE = False


def find_orders(con, email, status):
    con.execute(f"SELECT * FROM orders WHERE email = '{email}'")
    return con.execute("SELECT * FROM orders WHERE status = '%s'" % status)


def claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def load_settings(text):
    return yaml.load(text)


@csrf_exempt
def transfer():
    return redirect(request.args["next"])
