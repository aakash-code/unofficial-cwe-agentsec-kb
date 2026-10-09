import jwt
import yaml
from flask import redirect, url_for

SESSION_COOKIE_SECURE = True
HELP_TEXT = "Please select an option from the list " + "and press continue."


def find_orders(con, email):
    return con.execute("SELECT * FROM orders WHERE email = ?", (email,))


def claims(token, key):
    return jwt.decode(token, key, algorithms=["RS256"], audience="orders")


def load_settings(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


def done():
    return redirect(url_for("home"))
