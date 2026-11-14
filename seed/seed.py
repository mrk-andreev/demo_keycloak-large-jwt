#!/usr/bin/env python3
"""Idempotent provisioning for a disposable Keycloak demo; Python stdlib only."""
import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

BASE = os.getenv("KC_INTERNAL_URL", "http://keycloak:8080").rstrip("/")
REALM = "large-jwt-demo"
ADMIN = f"{BASE}/admin/realms/{REALM}"
SECRET = os.environ.get("AUTHZ_CLIENT_SECRET", "demo-authz-secret")
N = int(os.environ.get("SYNTHETIC_ROLES", "450"))


def request(method, path, payload=None, token=None, form=False):
    if payload is None:
        data = None
    elif form:
        data = urlencode(payload).encode("utf-8")
    else:
        data = json.dumps(payload).encode("utf-8")
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded" if form else "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else None
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path}: HTTP {exc.code}: {body[:500]}") from exc


def wait_for_admin():
    for attempt in range(150):
        try:
            response = request("POST", "/realms/master/protocol/openid-connect/token", {
                "grant_type": "password", "client_id": "admin-cli",
                "username": os.getenv("KC_ADMIN_USERNAME", "admin"),
                "password": os.getenv("KC_ADMIN_PASSWORD", "admin")
            }, form=True)
            if response and response.get("access_token"):
                return response["access_token"]
        except (URLError, RuntimeError, TimeoutError):
            if attempt % 10 == 0:
                print("Waiting for Keycloak readiness...", flush=True)
            time.sleep(2)
    raise RuntimeError("Keycloak did not become ready")


def main():
    token = wait_for_admin()
    print("Keycloak is ready; provisioning demo realm", flush=True)

    realms = request("GET", "/admin/realms", token=token)
    if not any(item["realm"] == REALM for item in realms):
        request("POST", "/admin/realms", {
            "realm": REALM, "enabled": True, "accessTokenLifespan": 900,
            "registrationAllowed": False, "loginWithEmailAllowed": True
        }, token)
        print(f"Created realm {REALM}", flush=True)

    def admin_req(method, path, payload=None):
        return request(method, f"/admin/realms/{REALM}{path}", payload, token)

    clients = {
        "permission-catalog": {
            "clientId": "permission-catalog", "enabled": True, "protocol": "openid-connect",
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False, "publicClient": False,
            "fullScopeAllowed": False
        },
        "verbose-cli": {
            "clientId": "verbose-cli", "enabled": True, "protocol": "openid-connect",
            "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
            "publicClient": True, "fullScopeAllowed": True,
            "redirectUris": ["http://localhost:8081/*"],
            "webOrigins": ["http://localhost:8081"],
            "attributes": {"pkce.code.challenge.method": "S256"}
        },
        "lean-cli": {
            "clientId": "lean-cli", "enabled": True, "protocol": "openid-connect",
            "standardFlowEnabled": True, "directAccessGrantsEnabled": True,
            "publicClient": True, "fullScopeAllowed": False,
            "redirectUris": ["http://localhost:8081/*"],
            "webOrigins": ["http://localhost:8081"],
            "attributes": {"pkce.code.challenge.method": "S256"}
        },
        "authz-svc": {
            "clientId": "authz-svc", "enabled": True, "protocol": "openid-connect",
            "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": True, "publicClient": False,
            "secret": SECRET, "clientAuthenticatorType": "client-secret",
            "fullScopeAllowed": True
        }
    }
    client_ids = {}
    for name, details in clients.items():
        matches = admin_req("GET", "/clients?clientId=" + quote(name))
        if not matches:
            admin_req("POST", "/clients", details)
            matches = admin_req("GET", "/clients?clientId=" + quote(name))
            print(f"Created client {name}", flush=True)
        if len(matches) != 1:
            raise RuntimeError(f"Ambiguous client {name}: {matches}")
        client_ids[name] = matches[0]["id"]

    # A fixed audience binds both token types to THIS API.
    for name in ("verbose-cli", "lean-cli"):
        client_id = client_ids[name]
        mapper_path = f"/clients/{client_id}/protocol-mappers/models"
        mappers = admin_req("GET", mapper_path)
        if not any(m["name"] == "demo-api-audience" for m in mappers):
            admin_req("POST", mapper_path, {
                "name": "demo-api-audience", "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": "demo-api",
                    "access.token.claim": "true",
                    "id.token.claim": "false"
                }
            })

    # Keycloak's built-in 'roles' scope adds realm_access and resource_access.
    scopes = admin_req("GET", "/client-scopes")
    roles_scope = next(scope for scope in scopes if scope["name"] == "roles")
    verbose_id = client_ids["verbose-cli"]
    verbose_defaults = admin_req("GET", f"/clients/{verbose_id}/default-client-scopes")
    if not any(scope["id"] == roles_scope["id"] for scope in verbose_defaults):
        admin_req("PUT", f"/clients/{verbose_id}/default-client-scopes/{roles_scope['id']}")
    lean_id = client_ids["lean-cli"]
    defaults = admin_req("GET", f"/clients/{lean_id}/default-client-scopes")
    if any(scope["id"] == roles_scope["id"] for scope in defaults):
        admin_req("DELETE", f"/clients/{lean_id}/default-client-scopes/{roles_scope['id']}")
        print("Detached 'roles' client scope from lean-cli", flush=True)

    # Grant the backend service account read-only Keycloak Admin API access.
    service_user = admin_req("GET", f"/clients/{client_ids['authz-svc']}/service-account-user")
    management = admin_req("GET", "/clients?clientId=realm-management")[0]["id"]
    admin_roles = [admin_req("GET", f"/clients/{management}/roles/{role}")
                   for role in ("view-users", "view-clients")]
    admin_req("POST", f"/users/{service_user['id']}/role-mappings/clients/{management}", admin_roles)

    users = admin_req("GET", "/users?username=trader&exact=true")
    if not users:
        admin_req("POST", "/users", {
            "username": "trader", "firstName": "Demo", "lastName": "Trader",
            "email": "trader@example.test", "enabled": True, "emailVerified": True,
            "credentials": [{"type": "password", "value": "trader", "temporary": False}]
        })
        users = admin_req("GET", "/users?username=trader&exact=true")
        print("Created demo user trader/trader", flush=True)
    user_id = users[0]["id"]

    # Put permissions under CLIENT roles. On large role sets the client /composite
    # Admin REST endpoint is preferable to the realm /composite endpoint.
    catalog_id = client_ids["permission-catalog"]
    role_path = f"/clients/{catalog_id}/roles"
    essential = ["orders:read", "orders:cancel", "orders:create", "trades:read"]
    synthetic = [f"reporting:desk:global:dataset:{i:04d}:read:instrument-universe"
                 for i in range(1, N + 1)]
    expected = ["trader"] + essential + synthetic
    existing_roles = {role["name"]: role for role in admin_req("GET", role_path + "?max=10000")}
    missing = [name for name in expected if name not in existing_roles]
    for index, name in enumerate(missing, 1):
        admin_req("POST", role_path, {"name": name, "description": "Demo permission role"})
        if index % 100 == 0:
            print(f"Created {index}/{len(missing)} new roles", flush=True)
    if missing:
        existing_roles = {role["name"]: role for role in admin_req("GET", role_path + "?max=10000")}

    composite = existing_roles["trader"]
    # Do NOT include 'orders:create' in the composite: it is used for a 403 test.
    allowed = ["orders:read", "orders:cancel", "trades:read"] + synthetic
    children = [existing_roles[name] for name in allowed]
    composite_path = f"{role_path}/trader/composites"
    already = {role["id"] for role in admin_req("GET", composite_path)}
    additions = [role for role in children if role["id"] not in already]
    if additions:
        admin_req("POST", composite_path, additions)
        print(f"Linked {len(additions)} permission roles to composite 'trader'", flush=True)

    assigned = admin_req("GET", f"/users/{user_id}/role-mappings/clients/{catalog_id}")
    if not any(role["name"] == "trader" for role in assigned):
        admin_req("POST", f"/users/{user_id}/role-mappings/clients/{catalog_id}", [composite])
    print(f"Provisioned {len(allowed)} effective permissions for trader", flush=True)
    print("Demo ready: login trader/trader; clients verbose-cli and lean-cli", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"SEED FAILED: {exc}", file=sys.stderr, flush=True)
        raise
