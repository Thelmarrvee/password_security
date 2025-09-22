import hashlib
import requests
import re

def check_strength(password: str) -> str:
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[!@#$%^&*(),.?\":{}|<>]", password) is None

    errors = [length_error, digit_error, uppercase_error, lowercase_error, symbol_error]

    if all(not e for e in errors):
        return "Strong ✅"
    else:
        return "Weak ❌ (Use 8+ chars, mix upper/lowercase, numbers, symbols)"
def check_breach(password: str) -> str:
    sha1_pw = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_pw[:5], sha1_pw[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)

    if res.status_code != 200:
        return "Error checking breaches ⚠️"
    hashes = (line.split(':') for line in res.text.splitlines())
    for h, count in hashes:
        if h == suffix:
            return f"⚠️ Found in breaches {count} times!"
    return "✅ Not found in known breaches"

if __name__ == "__main__":
    pwd = input("Enter a password to check: ")
    print("\n--- Password Check ---")
    print("Strength:", check_strength(pwd))
    print("Breach Check:", check_breach(pwd))
