#!/usr/bin/env python3
"""
pyats_mcp_panos.py — API-first PAN-OS / Panorama helper for pyATS MCP Server.

Provides run_show(), get_running_config(), and apply_config() using the
PAN-OS XML API (via pan-os-python).

All functions accept a pyATS Device object and return JSON-serializable dicts
with a normalized shape: {status, method, device, output/error, ...}.

Credentials:
  - API key: env var PANOS_API_KEY (global) or PANOS_API_KEY_<DEVICE> (per-device).
  - Username/password: from device.credentials.default in the pyATS testbed.

Panorama-managed firewalls:
  - Set device.custom.managed_by = "<panorama_device_name>" in the testbed.
  - Optionally set device.custom.device_group and device.custom.serial.
"""

from __future__ import annotations

import logging
import os
import time
import traceback
from typing import Any, Dict, Optional, Tuple, Union
from xml.etree.ElementTree import Element, tostring as xml_tostring

import xmltodict
from panos.firewall import Firewall
from panos.panorama import Panorama

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _xml_to_dict(xml_text: str) -> Dict[str, Any]:
    """Parse an XML string into a Python dict via xmltodict.

    Returns a dict on success or {"_parse_error": "<message>"} on failure.
    """
    try:
        return xmltodict.parse(xml_text)
    except Exception as exc:
        logger.warning("XML parse failed: %s", exc)
        return {"_parse_error": str(exc)}


def _element_to_str(element: Union[Element, str]) -> str:
    """Convert an xml.etree Element (or plain string) to a UTF-8 string."""
    if isinstance(element, str):
        return element
    try:
        return xml_tostring(element, encoding="unicode")
    except Exception:
        return str(element)


def _get_connection_info(device: object) -> Dict[str, Any]:
    """Extract host, protocol, username, password, and api_key from a pyATS Device.

    Looks for the management connection under keys 'mgmt', 'cli', or the first
    available connection.  API key is resolved from environment variables
    PANOS_API_KEY_<DEVICE_NAME> (per-device) or PANOS_API_KEY (global).

    Never logs secrets.
    """
    info: Dict[str, Any] = {
        "host": None,
        "protocol": "https",
        "username": None,
        "password": None,
        "api_key": None,
        "conn_name": None,
    }

    # --- connection / host ---------------------------------------------------
    connections = getattr(device, "connections", {}) or {}
    conn = None
    for name in ("mgmt", "cli"):
        if name in connections:
            conn = connections[name]
            info["conn_name"] = name
            break
    if conn is None and connections:
        first_name = next(iter(connections))
        conn = connections[first_name]
        info["conn_name"] = first_name

    if conn is not None:
        info["host"] = getattr(conn, "ip", None) or getattr(conn, "host", None)
        if isinstance(conn, dict):
            info["host"] = conn.get("ip") or conn.get("host")
            info["protocol"] = conn.get("protocol", "https")
        else:
            info["protocol"] = getattr(conn, "protocol", "https") or "https"

    # --- credentials ---------------------------------------------------------
    creds = getattr(device, "credentials", {})
    default_cred = creds.get("default") if isinstance(creds, dict) else getattr(creds, "default", None)
    if default_cred is not None:
        info["username"] = str(getattr(default_cred, "username", "") or "")
        pw = getattr(default_cred, "password", None)
        if pw is not None:
            info["password"] = str(pw)

    # --- API key from env vars -----------------------------------------------
    dev_name = getattr(device, "name", "")
    env_key_specific = os.environ.get(f"PANOS_API_KEY_{dev_name.upper().replace('-', '_')}")
    env_key_global = os.environ.get("PANOS_API_KEY")
    info["api_key"] = env_key_specific or env_key_global or None

    return info


def _resolve_panorama_device(device: object) -> Optional[object]:
    """If device.custom.managed_by names another device in the testbed, return it."""
    custom = getattr(device, "custom", None) or {}
    if isinstance(custom, dict):
        managed_by = custom.get("managed_by")
    else:
        managed_by = getattr(custom, "managed_by", None)
    if not managed_by:
        return None

    testbed = getattr(device, "testbed", None)
    if testbed is None:
        return None
    devices = getattr(testbed, "devices", {})
    return devices.get(managed_by)


def _get_panos_client(device: object) -> Tuple[Union[Firewall, Panorama], bool, Dict[str, Any]]:
    """Build a pan-os-python client from a pyATS Device.

    Returns (client, is_panorama, metadata) where metadata may include
    device_group and serial for Panorama-managed firewalls.

    Raises RuntimeError if no usable credentials or host are found.
    """
    meta: Dict[str, Any] = {}
    custom = getattr(device, "custom", None) or {}
    if not isinstance(custom, dict):
        custom = {k: getattr(custom, k, None) for k in ("managed_by", "device_group", "serial", "panorama_host")}

    # Determine if this device is managed by Panorama
    panorama_dev = _resolve_panorama_device(device)
    is_panorama_type = getattr(device, "type", "").lower() == "panorama" or getattr(device, "os", "").lower() == "panorama"

    if panorama_dev is not None:
        # Use the Panorama device's connection info
        conn_info = _get_connection_info(panorama_dev)
        meta["device_group"] = custom.get("device_group")
        meta["serial"] = custom.get("serial")
        is_panorama = True
    elif is_panorama_type:
        conn_info = _get_connection_info(device)
        is_panorama = True
    else:
        conn_info = _get_connection_info(device)
        is_panorama = False

    host = conn_info["host"]
    if not host:
        raise RuntimeError(f"No host/IP found for device '{getattr(device, 'name', '?')}'")

    api_key = conn_info["api_key"]
    username = conn_info["username"]
    password = conn_info["password"]

    if is_panorama:
        if api_key:
            client = Panorama(hostname=host, api_key=api_key)
        elif username and password:
            client = Panorama(hostname=host, api_username=username, api_password=password)
        else:
            raise RuntimeError("No API key or username/password available for Panorama")
    else:
        if api_key:
            client = Firewall(hostname=host, api_key=api_key)
        elif username and password:
            client = Firewall(hostname=host, api_username=username, api_password=password)
        else:
            raise RuntimeError("No API key or username/password available for firewall")

    logger.info("Created %s client for host %s", "Panorama" if is_panorama else "Firewall", host)
    return client, is_panorama, meta


def _error_result(device: object, message: str, exc: Optional[Exception] = None) -> Dict[str, Any]:
    """Build a normalized error dict."""
    result: Dict[str, Any] = {
        "status": "error",
        "error": message,
        "device": getattr(device, "name", "unknown"),
    }
    if exc is not None:
        result["trace"] = traceback.format_exception_only(type(exc), exc)[-1].strip()
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_show(device: object, command: str, timeout_s: int = 60) -> Dict[str, Any]:
    """Run an operational / show command on a PAN-OS device via the XML API.

    Args:
        device:    pyATS Device instance.
        command:   CLI command string (e.g. ``"show system info"``).
        timeout_s: Timeout in seconds for the operation.

    Returns:
        A JSON-serializable dict with keys *status*, *method*, *device*, and
        *output* (structured dict from XML).
    """
    dev_name = getattr(device, "name", "unknown")

    try:
        client, is_panorama, meta = _get_panos_client(device)
        logger.info("API run_show on %s: %s", dev_name, command)
        response = client.op(command, cmd_xml=False)
        raw_xml = _element_to_str(response)
        parsed = _xml_to_dict(raw_xml)
        return {
            "status": "success",
            "method": "api",
            "device": dev_name,
            "output": parsed,
            "raw_xml": raw_xml,
        }
    except Exception as exc:
        return _error_result(device, f"API run_show failed: {exc}", exc)


def get_running_config(device: object, timeout_s: int = 120) -> Dict[str, Any]:
    """Fetch the running configuration from a PAN-OS device via the XML API.

    Args:
        device:    pyATS Device instance.
        timeout_s: Timeout in seconds.

    Returns:
        JSON-serializable dict with *status*, *method*, *device*, *output*.
    """
    dev_name = getattr(device, "name", "unknown")

    try:
        client, is_panorama, meta = _get_panos_client(device)
        logger.info("API get_running_config on %s", dev_name)

        cmd = "<show><config><running/></config></show>"
        response = client.op(cmd, cmd_xml=False)
        raw_xml = _element_to_str(response)
        parsed = _xml_to_dict(raw_xml)
        return {
            "status": "success",
            "method": "api",
            "device": dev_name,
            "output": parsed,
            "raw_xml": raw_xml,
        }
    except Exception as exc:
        return _error_result(device, f"API get_running_config failed: {exc}", exc)


def apply_config(
    device: object,
    xml_config: str,
    commit: bool = True,
    push: bool = False,
    timeout_s: int = 300,
) -> Dict[str, Any]:
    """Load configuration onto a PAN-OS device and optionally commit.

    API-first.  For Panorama devices, supports commit-and-push to managed
    firewalls when *push=True*.

    Args:
        device:     pyATS Device instance.
        xml_config: XML (or set-command) configuration payload to load.
        commit:     Whether to commit after loading (default True).
        push:       For Panorama — commit-and-push to managed devices.
        timeout_s:  Timeout in seconds for commit/push operations.

    Returns:
        JSON-serializable dict with *status*, *method*, *device*, and details.
    """
    dev_name = getattr(device, "name", "unknown")

    # --- API attempt ---------------------------------------------------------
    try:
        client, is_panorama, meta = _get_panos_client(device)
        logger.info("API apply_config on %s (commit=%s, push=%s)", dev_name, commit, push)

        # Load the candidate configuration via the XML API type=config action=set
        client.xapi.set(xpath="/config", element=xml_config)
        logger.info("Configuration loaded on %s", dev_name)

        details: Dict[str, Any] = {"config_loaded": True}

        # --- commit ---
        if commit:
            logger.info("Committing on %s ...", dev_name)
            if is_panorama:
                client.commit(sync=True, timeout=timeout_s)
                details["panorama_commit"] = "ok"
            else:
                client.commit(sync=True, timeout=timeout_s)
                details["commit"] = "ok"

        # --- push (Panorama only) ---
        if push and is_panorama:
            device_group = meta.get("device_group")
            serial = meta.get("serial")
            logger.info("Pushing config from Panorama to device_group=%s serial=%s", device_group, serial)

            cmd_parts = ["<commit-all><shared-policy>"]
            if device_group:
                cmd_parts.append(f"<device-group><entry name=\"{device_group}\">")
                if serial:
                    cmd_parts.append(f"<devices><entry name=\"{serial}\"/></devices>")
                cmd_parts.append("</entry></device-group>")
            cmd_parts.append("</shared-policy></commit-all>")
            push_cmd = "".join(cmd_parts)

            client.op(push_cmd, cmd_xml=False)

            # Poll for push completion
            deadline = time.time() + timeout_s
            push_status = "initiated"
            while time.time() < deadline:
                time.sleep(10)
                try:
                    resp = client.op("<show><jobs><all/></jobs></show>", cmd_xml=False)
                    raw = _element_to_str(resp)
                    if "FIN" in raw:
                        push_status = "completed"
                        break
                except Exception:
                    pass
            details["push"] = push_status

        return {
            "status": "success",
            "method": "api",
            "device": dev_name,
            "message": "commit ok" if commit else "config loaded (no commit)",
            "details": details,
        }

    except Exception as exc:
        return _error_result(device, f"API apply_config failed: {exc}", exc)
