#!/usr/bin/env python3
"""Reproduce the HTTP header failure and verify the lean-token authorization flow."""
import base64
import json
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

KEYCLOAK = "http://localhost:8080/realms/large-jwt-demo/protocol/openid-connect/token"
API = "http://localhost:8081"


def post_form(url, form):
    req = Request(url, data=urlencode(form).encode(), headers={
        "Content-Type": "application/x-www-form-urlencoded"
    }, method="POST")
    with urlopen(req, timeout=30) as response:
        return json.load(response)


def token(client):
    return post_form(KEYCLOAK, {
        "client_id": client, "grant_type": "password",
        "username": "trader", "password": "trader"
    })["access_token"]


def payload(jwt):
    middle = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(middle + "=" * (-len(middle) % 4)))


def call(path, bearer, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else (b"" if method == "POST" else None)
    req = Request(API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + bearer,
        "Content-Type": "application/json"
    })
    try:
        with urlopen(req, timeout=30) as response:
            raw = response.read().decode()
            return response.status, json.loads(raw) if raw.startswith("{") or raw.startswith("[") else raw
    except HTTPError as exc:
        return exc.code, exc.read().decode(errors="replace")[:200]


def main():
    verbose = token("verbose-cli")
    lean = token("lean-cli")
    big_payload = payload(verbose)
    small_payload = payload(lean)
    verbose_roles = big_payload.get("resource_access", {}).get("permission-catalog", {}).get("roles", [])
    lean_roles = small_payload.get("resource_access", {}).get("permission-catalog", {}).get("roles", [])
    print(f"Verbose JWT: {len(verbose):,} bytes; catalog roles: {len(verbose_roles)}")
    print(f"Lean JWT:    {len(lean):,} bytes; catalog roles: {len(lean_roles)}")
    print(f"JWT reduction: {(1 - len(lean) / len(verbose)) * 100:.1f}%")

    verbose_status, _ = call("/api/me/permissions?prefix=orders:", verbose)
    print(f"Verbose JWT API call: HTTP {verbose_status} (expected 400, >8 KB request-header limit)")

    status, permissions = call("/api/me/permissions?prefix=orders:", lean)
    print(f"Lean JWT GET effective permissions: HTTP {status}: {permissions}")
    status_check, decisions = call("/api/me/permissions/check", lean, "POST", {
        "permissions": ["orders:read", "orders:cancel", "orders:create"]
    })
    print(f"Lean JWT batch permission check: HTTP {status_check}: {decisions}")
    status_read, _ = call("/api/orders", lean)
    status_cancel, _ = call("/api/orders/cancel", lean, "POST")
    status_create, _ = call("/api/orders", lean, "POST")
    print(f"Backend enforcement: read={status_read}, cancel={status_cancel}, create={status_create}")

    assert len(verbose_roles) >= 400, "Keycloak did not expand user composite roles into verbose token"
    assert len(lean_roles) == 0, "Lean token contains catalog roles; roles scope removal failed"
    assert len(verbose) > 8192, "Verbose JWT did not exceed the configured header size"
    assert len(lean) < 8192, "Lean JWT still exceeds the configured header size"
    assert verbose_status == 400, f"Expected HTTP 400 for oversized header, got {verbose_status}"
    assert status == 200 and permissions["permissions"] == ["orders:cancel", "orders:read"], permissions
    assert status_check == 200 and decisions["decisions"] == {
        "orders:read": True, "orders:cancel": True, "orders:create": False
    }, decisions
    assert (status_read, status_cancel, status_create) == (200, 200, 403)
    print("PASS: oversized JWT reproduced; lean JWT and backend permission checks verified.")


if __name__ == "__main__":
    try:
        main()
    except (URLError, AssertionError, KeyError, ValueError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
