"""Unit tests mirroring openai/php2shell-checker behaviour (run: python -m pytest -q or python test_checker.py)."""
import asyncio
import os
import socket

import pytest
from fastapi import HTTPException

from app import (patch_status, pick_version, advise, check_url, authorise_subscriptions, _is_public,
                 _public_transport, PublicOnlyBackend)


def test_patch_status_table():
    cases = {
        "8.4.26": "vulnerable", "8.4.27": "ok", "8.3.35": "vulnerable", "8.3.36": "ok",
        "8.2.34": "vulnerable", "8.2.35": "ok", "8.5.11": "vulnerable", "8.5.12": "ok",
        "8.1.34": "vulnerable", "8.1.35": "ok", "7.4.33": "vulnerable", "5.4.0": "vulnerable",
        "5.3.29": "unknown", "9.0.0": "unknown", "8.5.12-dev": "unknown", "8.5.13RC1": "unknown",
        "8.4.27-1ubuntu1": "ok", "garbage": "unknown", "": "unknown",
    }
    for v, expected in cases.items():
        assert patch_status(v) == expected, (v, patch_status(v), expected)


def test_worst_wins():
    v, s = pick_version("Apache PHP/8.4.27\nPHP/8.1.2")
    assert (v, s) == ("8.1.2", "vulnerable")
    v, s = pick_version("nginx/1.30.6\n")
    assert (v, s) == (None, "unknown")


def test_advise():
    a = advise("8.1.27", "app-service-linux", "front-door")
    assert a["patch_status"] == "vulnerable" and a["end_of_life"] is True
    assert "99006001" in a["azure_waf"]
    b = advise("8.3.35", "container", "app-gateway")
    assert b["recommended_version"] == "8.3.36" and "PHPSESSID" in b["azure_waf"]


def test_non_public_destinations_blocked():
    for ip in ("127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.1", "169.254.169.254", "::1", "fd00::1",
               "::ffff:127.0.0.1", "0.0.0.0", "100.64.0.1"):
        assert not _is_public(ip), ip
    assert _is_public("20.0.0.1")
    for target in ("http://127.0.0.1", "http://169.254.169.254/metadata/instance", "localhost",
                   "http://[::1]/", "http://10.1.2.3:8080", "http://example.com:22"):
        r = asyncio.run(check_url(target, timeout=3))
        assert r.patch_status == "unknown" and r.reason.startswith(("Not checked", "Only ports")), (target, r.reason)


def test_embedded_ipv4_forms():
    for ip in ("64:ff9b::a9fe:a9fe", "64:ff9b::7f00:1", "64:ff9b:1::a00:1", "2002:a9fe:a9fe::1", "2002:7f00:1::1",
               "2001:0:4136:e378:8000:63bf:3fff:fdd2"):
        assert not _is_public(ip), ip
    assert _is_public("64:ff9b::1400:1")  # 20.0.0.1 via the well-known NAT64 prefix
    assert _is_public("64:ff9b::808:808")  # 8.8.8.8
    assert not _is_public("64:ff9b:1:1400:1::")  # local-use NAT64 prefix is never treated as public


def test_connection_path_blocks_rebinding(monkeypatch):
    """A public-looking hostname that resolves to loopback must be refused inside the transport itself."""
    real = socket.getaddrinfo

    def fake(host, *a, **k):
        if host == "rebind.example.com":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", a[0] if a else 80))]
        return real(host, *a, **k)

    monkeypatch.setattr(socket, "getaddrinfo", fake)
    t = _public_transport()
    assert isinstance(t._pool._network_backend, PublicOnlyBackend)
    r = asyncio.run(check_url("http://rebind.example.com", timeout=3))
    assert r.patch_status == "unknown" and r.reason.startswith("Not checked"), r.reason


def test_subscription_allow_list():
    a, b = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"
    os.environ["ALLOWED_SUBSCRIPTION_IDS"] = a
    assert authorise_subscriptions([a.upper()]) == [a]
    with pytest.raises(HTTPException):
        authorise_subscriptions([b])
    os.environ["ALLOWED_SUBSCRIPTION_IDS"] = ""
    with pytest.raises(HTTPException):
        authorise_subscriptions([a])


if __name__ == "__main__":
    test_patch_status_table(); test_worst_wins(); test_advise()
    test_non_public_destinations_blocked(); test_embedded_ipv4_forms(); test_subscription_allow_list(); print("all tests passed")
