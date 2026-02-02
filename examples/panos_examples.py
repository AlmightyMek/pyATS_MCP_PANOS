#!/usr/bin/env python3
"""
panos_examples.py — Demonstrates pyats_mcp_panos usage with mock device objects.

This script creates lightweight mock objects that mimic pyATS Device instances
so you can see the call signatures and return-value shapes without needing a
real PAN-OS device.

To test against a real device, load a pyATS testbed instead:

    from pyats.topology import loader
    tb = loader.load("testbed.yaml")
    device = tb.devices["palo-fw1"]
    result = run_show(device, "show system info")

Example testbed.yaml — standalone firewall:

    devices:
      palo-fw1:
        os: panos
        type: firewall
        connections:
          mgmt:
            protocol: https
            ip: 10.0.0.10
        credentials:
          default:
            username: admin
            password: "%ENV{PANOS_PASSWORD}"

Example testbed.yaml — Panorama + managed firewall:

    devices:
      panorama1:
        os: panos
        type: panorama
        connections:
          mgmt:
            protocol: https
            ip: 10.0.0.5
        credentials:
          default:
            username: admin
            password: "%ENV{PANORAMA_PASSWORD}"
      palo-managed-fw:
        os: panos
        type: firewall
        custom:
          managed_by: panorama1
          device_group: "DG-Prod"
          serial: "0123456789"
        connections:
          via_panorama:
            protocol: api
            host: 10.0.0.5
        credentials:
          default:
            username: admin
            password: "%ENV{PANORAMA_PASSWORD}"

Integration snippet for pyats_mcp_server.py:

    from pyats_mcp_panos import run_show, get_running_config, apply_config

    if getattr(device, "os", "").lower() in ("panos", "panorama"):
        result = run_show(device, command)
        return json.dumps(result, indent=2)
"""

from __future__ import annotations

import json
import sys
import os

# ---------------------------------------------------------------------------
# Mock helpers — simulate pyATS Device objects for demonstration purposes
# ---------------------------------------------------------------------------

class _MockCred:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password


class _MockCreds:
    def __init__(self, username: str, password: str):
        self.default = _MockCred(username, password)

    def get(self, key, default=None):
        if key == "default":
            return self.default
        return default


class _MockConn:
    def __init__(self, ip: str, protocol: str = "https"):
        self.ip = ip
        self.host = ip
        self.protocol = protocol


class _MockDevice:
    """Minimal stand-in for a pyATS Device object."""

    def __init__(
        self,
        name: str,
        os: str = "panos",
        type: str = "firewall",
        host: str = "10.0.0.10",
        username: str = "admin",
        password: str = "mock_password",
        custom: dict | None = None,
        testbed: object | None = None,
    ):
        self.name = name
        self.os = os
        self.type = type
        self.connections = {"mgmt": _MockConn(host)}
        self.credentials = _MockCreds(username, password)
        self.custom = custom or {}
        self.testbed = testbed


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main() -> None:
    # Add repo root to path so we can import the module
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, repo_root)

    from pyats_mcp_panos import run_show, get_running_config, apply_config, _get_connection_info

    # 1. Show connection info extraction (no secrets printed)
    fw = _MockDevice(name="palo-fw1", host="10.0.0.10")
    info = _get_connection_info(fw)
    safe_info = {k: ("***" if k in ("password", "api_key") and v else v) for k, v in info.items()}
    print("=== Connection info (redacted) ===")
    print(json.dumps(safe_info, indent=2))
    print()

    # 2. run_show — will fail against mock (no real device), showing error shape
    print("=== run_show (expected error — no real device) ===")
    result = run_show(fw, "show system info")
    print(json.dumps(result, indent=2))
    print()

    # 3. get_running_config
    print("=== get_running_config (expected error) ===")
    result = get_running_config(fw)
    print(json.dumps(result, indent=2))
    print()

    # 4. apply_config
    print("=== apply_config (expected error) ===")
    xml_snippet = "<network><interface><ethernet><entry name='ethernet1/1'><layer3><ip><entry name='10.1.1.1/24'/></ip></layer3></entry></ethernet></interface></network>"
    result = apply_config(fw, xml_snippet, commit=False)
    print(json.dumps(result, indent=2))
    print()

    # 5. Panorama-managed device example
    class _MockTestbed:
        pass

    tb = _MockTestbed()
    panorama = _MockDevice(name="panorama1", os="panos", type="panorama", host="10.0.0.5")
    managed_fw = _MockDevice(
        name="palo-managed-fw",
        host="10.0.0.5",
        custom={"managed_by": "panorama1", "device_group": "DG-Prod", "serial": "0123456789"},
    )
    tb.devices = {"panorama1": panorama, "palo-managed-fw": managed_fw}
    managed_fw.testbed = tb

    print("=== Panorama-managed device connection info (redacted) ===")
    info = _get_connection_info(panorama)
    safe_info = {k: ("***" if k in ("password", "api_key") and v else v) for k, v in info.items()}
    print(json.dumps(safe_info, indent=2))


if __name__ == "__main__":
    main()
