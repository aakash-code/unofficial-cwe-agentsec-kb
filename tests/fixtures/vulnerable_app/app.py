import os
import requests


def run_report(user_argument):
    return os.system("report-tool " + user_argument)


def fetch_status():
    return requests.get("https://status.invalid", verify=False)


api_key = "TOKENVALUE123456789"
