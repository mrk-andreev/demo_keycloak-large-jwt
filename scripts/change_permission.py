#!/usr/bin/env python3
"""Revoke or restore orders:cancel; observe cached decisions expire after 20s."""
import json
import sys
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

BASE = "http://localhost:8080"
REALM = "large-jwt-demo"


def call(method, path, payload=None, access_token=None):
    data = None if payload is None else json.dumps(payload).encode()
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    if access_token:
        headers["Authorization"] = "Bearer " + access_token
    with urlopen(Request(BASE + path, data=data, headers=headers, method=method), timeout=30) as response:
        text = response.read()
        return json.loads(text) if text else None


def main(action):
    form = urlencode({"grant_type": "password", "client_id": "admin-cli", "username": "admin", "password": "admin"})
    with urlopen(Request(BASE + "/realms/master/protocol/openid-connect/token", data=form.encode(),
                         headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=30) as response:
        token = json.load(response)["access_token"]
    endpoint = "/admin/realms/" + REALM
    clients = call("GET", endpoint + "/clients?clientId=permission-catalog", access_token=token)
    catalog_id = clients[0]["id"]
    path = endpoint + f"/clients/{catalog_id}/roles"
    child = call("GET", path + "/orders%3Acancel", access_token=token)
    composites_path = path + "/trader/composites"
    composite = call("GET", composites_path, access_token=token)
    present = any(role["id"] == child["id"] for role in composite)
    if action == "revoke" and present:
        call("DELETE", composites_path, [child], token)
    elif action == "restore" and not present:
        call("POST", composites_path, [child], token)
    print(f"orders:cancel: {action} complete; observe API after local cache TTL (20 seconds)")


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"revoke", "restore"}:
        sys.exit("Usage: python3 scripts/change_permission.py revoke|restore")
    main(sys.argv[1])
