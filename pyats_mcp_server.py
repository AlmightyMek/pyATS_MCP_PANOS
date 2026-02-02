#!/usr/bin/env python3
# pyats_mcp_server.py - FIXED VERSION (FastMCP + Ping Tool)

from __future__ import annotations

import os
import re
import sys
import json
import time
import string
import logging
import textwrap
import asyncio
import tempfile
import subprocess
import shutil
from pathlib import Path
from functools import partial
from typing import Dict, Any, Optional, List, Union

import xmltodict
from xml.etree.ElementTree import Element, tostring as xml_tostring

from panos.firewall import Firewall
from panos.panorama import Panorama
from dotenv import load_dotenv
from pyats.topology import loader
from genie.libs.parser.utils import get_parser
from mcp.server.fastmcp import FastMCP

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("PyatsFastMCPServer")

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------
load_dotenv()
TESTBED_PATH = os.getenv("PYATS_TESTBED_PATH")

if not TESTBED_PATH or not os.path.exists(TESTBED_PATH):
    logger.critical(f"❌ CRITICAL: PYATS_TESTBED_PATH not set or file not found: {TESTBED_PATH}")
    sys.exit(1)

logger.info(f"✅ Using testbed file: {TESTBED_PATH}")

# Artifact retention
ARTIFACTS_DIR = Path(os.getenv("PYATS_MCP_ARTIFACTS_DIR", str(Path.home() / ".pyats-mcp" / "artifacts"))).resolve()
KEEP_ARTIFACTS = os.getenv("PYATS_MCP_KEEP_ARTIFACTS", "1") == "1"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

# Caching
_CACHE_TTL_S = int(os.getenv("PYATS_MCP_TESTBED_CACHE_TTL", "30"))
_TESTBED_CACHE: Dict[str, Any] = {"loaded_at": 0.0, "tb": None}

_CONN_CACHE_TTL_S = int(os.getenv("PYATS_MCP_CONN_CACHE_TTL", "0"))
_CONN_CACHE: Dict[str, Dict[str, Any]] = {}

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
ANSI_ESCAPE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def clean_output(output: str) -> str:
    output = ANSI_ESCAPE.sub("", output)
    return "".join(ch for ch in output if ch in string.printable)


# ---------------------------------------------------------------------------
# PAN-OS helpers
# ---------------------------------------------------------------------------

def _is_panos(device) -> bool:
    """Check if device is a PAN-OS firewall or Panorama."""
    return getattr(device, "os", "").lower() in ("panos", "panorama")


def _panos_xml_to_dict(xml_text: str) -> Dict[str, Any]:
    """Parse an XML string into a Python dict via xmltodict."""
    try:
        return xmltodict.parse(xml_text)
    except Exception as exc:
        logger.warning("XML parse failed: %s", exc)
        return {"_parse_error": str(exc)}


def _panos_element_to_str(element) -> str:
    """Convert an xml.etree Element (or plain string) to a UTF-8 string."""
    if isinstance(element, str):
        return element
    try:
        return xml_tostring(element, encoding="unicode")
    except Exception:
        return str(element)


def _panos_get_connection_info(device) -> Dict[str, Any]:
    """Extract host, protocol, username, password, and api_key from a pyATS Device."""
    info: Dict[str, Any] = {
        "host": None, "protocol": "https",
        "username": None, "password": None, "api_key": None, "conn_name": None,
    }
    connections = getattr(device, "connections", {}) or {}
    conn = None
    for name in ("mgmt", "api", "cli"):
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

    creds = getattr(device, "credentials", {})
    default_cred = creds.get("default") if isinstance(creds, dict) else getattr(creds, "default", None)
    if default_cred is not None:
        info["username"] = str(getattr(default_cred, "username", "") or "")
        pw = getattr(default_cred, "password", None)
        if pw is not None:
            info["password"] = str(pw)

    dev_name = getattr(device, "name", "")
    env_key_specific = os.environ.get(f"PANOS_API_KEY_{dev_name.upper().replace('-', '_')}")
    env_key_global = os.environ.get("PANOS_API_KEY")
    info["api_key"] = env_key_specific or env_key_global or None
    return info


def _panos_resolve_panorama_device(device):
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
    return getattr(testbed, "devices", {}).get(managed_by)


def _get_panos_client(device):
    """Build a pan-os-python Firewall or Panorama client from a pyATS Device.

    Returns (client, is_panorama, metadata).
    """
    meta: Dict[str, Any] = {}
    custom = getattr(device, "custom", None) or {}
    if not isinstance(custom, dict):
        custom = {k: getattr(custom, k, None) for k in ("managed_by", "device_group", "serial", "panorama_host")}

    panorama_dev = _panos_resolve_panorama_device(device)
    is_panorama_type = getattr(device, "type", "").lower() == "panorama" or getattr(device, "os", "").lower() == "panorama"

    if panorama_dev is not None:
        conn_info = _panos_get_connection_info(panorama_dev)
        meta["device_group"] = custom.get("device_group")
        meta["serial"] = custom.get("serial")
        is_panorama = True
    elif is_panorama_type:
        conn_info = _panos_get_connection_info(device)
        is_panorama = True
    else:
        conn_info = _panos_get_connection_info(device)
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


def _panos_error_result(device, message: str, exc: Optional[Exception] = None) -> Dict[str, Any]:
    """Build a normalized error dict for PAN-OS operations."""
    result: Dict[str, Any] = {
        "status": "error",
        "error": message,
        "device": getattr(device, "name", "unknown"),
    }
    if exc is not None:
        result["trace"] = traceback.format_exception_only(type(exc), exc)[-1].strip()
    return result


# ---------------------------------------------------------------------------
# PAN-OS public API functions
# ---------------------------------------------------------------------------

def panos_run_show(device, command: str, timeout_s: int = 60) -> Dict[str, Any]:
    """Run an operational / show command on a PAN-OS device via the XML API."""
    dev_name = getattr(device, "name", "unknown")
    try:
        client, is_panorama, meta = _get_panos_client(device)
        logger.info("API run_show on %s: %s", dev_name, command)
        response = client.op(command, cmd_xml=False)
        raw_xml = _panos_element_to_str(response)
        parsed = _panos_xml_to_dict(raw_xml)
        return {
            "status": "success",
            "method": "api",
            "device": dev_name,
            "output": parsed,
            "raw_xml": raw_xml,
        }
    except Exception as exc:
        return _panos_error_result(device, f"API run_show failed: {exc}", exc)


def panos_get_running_config(device, timeout_s: int = 120) -> Dict[str, Any]:
    """Fetch the running configuration from a PAN-OS device via the XML API."""
    dev_name = getattr(device, "name", "unknown")
    try:
        client, is_panorama, meta = _get_panos_client(device)
        logger.info("API get_running_config on %s", dev_name)
        cmd = "<show><config><running/></config></show>"
        response = client.op(cmd, cmd_xml=False)
        raw_xml = _panos_element_to_str(response)
        parsed = _panos_xml_to_dict(raw_xml)
        return {
            "status": "success",
            "method": "api",
            "device": dev_name,
            "output": parsed,
            "raw_xml": raw_xml,
        }
    except Exception as exc:
        return _panos_error_result(device, f"API get_running_config failed: {exc}", exc)


def panos_apply_config(device, xml_config: str, commit: bool = True, push: bool = False, timeout_s: int = 300) -> Dict[str, Any]:
    """Load configuration onto a PAN-OS device and optionally commit."""
    dev_name = getattr(device, "name", "unknown")
    try:
        client, is_panorama, meta = _get_panos_client(device)
        logger.info("API apply_config on %s (commit=%s, push=%s)", dev_name, commit, push)

        client.xapi.set(xpath="/config", element=xml_config)
        logger.info("Configuration loaded on %s", dev_name)
        details: Dict[str, Any] = {"config_loaded": True}

        if commit:
            logger.info("Committing on %s ...", dev_name)
            client.commit(sync=True, timeout=timeout_s)
            details["panorama_commit" if is_panorama else "commit"] = "ok"

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
            client.op("".join(cmd_parts), cmd_xml=False)

            deadline = time.time() + timeout_s
            push_status = "initiated"
            while time.time() < deadline:
                time.sleep(10)
                try:
                    resp = client.op("<show><jobs><all/></jobs></show>", cmd_xml=False)
                    raw = _panos_element_to_str(resp)
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
        return _panos_error_result(device, f"API apply_config failed: {exc}", exc)


def _load_testbed():
    """Cache testbed for TTL"""
    now = time.time()
    if _TESTBED_CACHE["tb"] is None or (now - _TESTBED_CACHE["loaded_at"]) > _CACHE_TTL_S:
        _TESTBED_CACHE["tb"] = loader.load(TESTBED_PATH)
        _TESTBED_CACHE["loaded_at"] = now
    return _TESTBED_CACHE["tb"]


def _evict_expired_connections() -> None:
    if _CONN_CACHE_TTL_S <= 0:
        return
    now = time.time()
    expired = [k for k, v in _CONN_CACHE.items() if (now - float(v.get("last_used", 0))) > _CONN_CACHE_TTL_S]
    for name in expired:
        dev = _CONN_CACHE.get(name, {}).get("device")
        try:
            if dev and getattr(dev, "is_connected", lambda: False)():
                logger.info(f"Conn cache TTL expired; disconnecting {name}...")
                dev.disconnect()
        except Exception:
            pass
        _CONN_CACHE.pop(name, None)


def _get_device(device_name: str):
    tb = _load_testbed()
    device = tb.devices.get(device_name)
    if not device:
        raise ValueError(f"Device '{device_name}' not found in testbed '{TESTBED_PATH}'.")

    if _CONN_CACHE_TTL_S > 0:
        _evict_expired_connections()
        if device_name in _CONN_CACHE:
            cached = _CONN_CACHE[device_name].get("device")
            if cached and getattr(cached, "is_connected", lambda: False)():
                _CONN_CACHE[device_name]["last_used"] = time.time()
                return cached

    # Skip SSH connection for PAN-OS devices (API-only)
    if _is_panos(device):
        logger.info(f"PAN-OS device {device_name} — skipping SSH (API-only)")
    elif not device.is_connected():
        logger.info(f"Connecting to {device_name}...")
        device.connect(
            connection_timeout=120,
            learn_hostname=True,
            log_stdout=False,
            mit=True,
        )
        logger.info(f"Connected to {device_name}")

    if _CONN_CACHE_TTL_S > 0:
        _CONN_CACHE[device_name] = {"device": device, "last_used": time.time()}

    return device


def _disconnect_device(device, force: bool = False):
    if not device:
        return

    if _CONN_CACHE_TTL_S > 0 and not force:
        try:
            _CONN_CACHE[getattr(device, "name", "unknown")]["last_used"] = time.time()
        except Exception:
            pass
        return

    if getattr(device, "is_connected", lambda: False)():
        try:
            logger.info(f"Disconnecting from {device.name}...")
            device.disconnect()
            logger.info(f"Disconnected from {device.name}")
        except Exception as e:
            logger.warning(f"Error disconnecting: {e}")


# -----------------------------------------------------------------------------
# Show command validation
# -----------------------------------------------------------------------------
SHOW_BLOCK_CHARS = ["|", ">", "<"]
SHOW_BLOCK_WORDS = {"copy", "delete", "erase", "reload", "write", "configure", "conf"}


def validate_show_command(command: str) -> Optional[str]:
    cmd = (command or "").strip()
    cmd_lower = cmd.lower()

    if not cmd_lower.startswith("show"):
        return f"Command '{command}' is not a 'show' command."

    if any(ch in cmd_lower for ch in SHOW_BLOCK_CHARS):
        return f"Command '{command}' contains disallowed pipe/redirection."

    tokens = re.findall(r"[a-zA-Z0-9_-]+", cmd_lower)
    for t in tokens:
        if t in SHOW_BLOCK_WORDS:
            return f"Command '{command}' contains disallowed term '{t}'."

    return None


# -----------------------------------------------------------------------------
# CRITICAL FIX: Config normalization
# -----------------------------------------------------------------------------
_WRAPPER_LINES = {
    "configure terminal",
    "conf t",
    "config t",
    "configure t",
    "end",
}

def _normalize_config_lines(config_commands: Union[str, List[Any], None]) -> List[str]:
    """
    Normalize config payload into list of CLI lines.
    
    Key behaviors:
    1. Accepts list[str] or multiline string
    2. Splits semicolon-joined commands
    3. Strips wrapper commands (configure terminal, end)
    4. Preserves indentation for submode commands
    5. Does NOT remove 'exit' (needed for interface context)
    """
    if config_commands is None:
        return []

    # Build initial lines
    if isinstance(config_commands, list):
        raw_lines = [str(x) for x in config_commands]
    else:
        # Handle multiline string
        cleaned = textwrap.dedent(str(config_commands)).strip("\n")
        raw_lines = cleaned.splitlines()

    out: List[str] = []
    for line in raw_lines:
        s = line.rstrip("\r\n")
        if not s.strip():
            continue

        # Split semicolon-separated commands
        if ";" in s:
            parts = [p.strip() for p in s.split(";") if p.strip()]
            for p in parts:
                low = p.lower()
                if low in _WRAPPER_LINES:
                    continue
                out.append(p)
            continue

        # Check if line is a wrapper command
        low = s.strip().lower()
        if low in _WRAPPER_LINES:
            continue

        out.append(s)

    return out


def _config_guardrails(config_lines: List[str]) -> Optional[str]:
    """Basic safety checks for dangerous commands"""
    joined = "\n".join(config_lines).lower()

    if re.search(r"\bwrite\s+erase\b", joined):
        return "Dangerous command detected: 'write erase'. Operation aborted."
    if re.search(r"^\s*erase\b", joined, flags=re.MULTILINE):
        return "Dangerous command detected: 'erase'. Operation aborted."
    if re.search(r"\breload\b", joined):
        return "Dangerous command detected: 'reload'. Operation aborted."
    if re.search(r"\bdelete\b", joined):
        return "Dangerous command detected: 'delete'. Operation aborted."
    if re.search(r"\bformat\b", joined):
        return "Dangerous command detected: 'format'. Operation aborted."

    return None


# -----------------------------------------------------------------------------
# Async wrappers
# -----------------------------------------------------------------------------
async def run_show_command_async(device_name: str, command: str) -> Dict[str, Any]:
    """Execute and parse show command"""
    try:
        err = validate_show_command(command)
        if err:
            return {"status": "error", "error": err}

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, partial(_execute_show_command, device_name, command))
    except Exception as e:
        logger.error(f"Error in run_show_command_async: {e}", exc_info=True)
        return {"status": "error", "error": f"Execution error: {e}"}


def _execute_show_command(device_name: str, command: str) -> Dict[str, Any]:
    device = None
    try:
        device = _get_device(device_name)

        # Route PAN-OS devices to API
        if _is_panos(device):
            logger.info(f"Routing to PAN-OS API for show command: '{command}' on {device_name}")
            result = panos_run_show(device, command)
            if result.get("status") == "success":
                return {
                    "status": "completed",
                    "device": device_name,
                    "command": command,
                    "output": result.get("output", {}),
                    "parsed": True,
                    "method": "api",
                }
            return {"status": "error", "device": device_name, "error": result.get("error", "Unknown API error")}

        try:
            logger.info(f"Attempting to parse: '{command}' on {device_name}")
            parsed_output = device.parse(command)
            return {
                "status": "completed",
                "device": device_name,
                "command": command,
                "output": parsed_output,
                "parsed": True
            }
        except Exception as parse_exc:
            logger.warning(f"Parse failed for '{command}' on {device_name}: {parse_exc}; using raw output.")
            raw_output = device.execute(command)
            raw_output = clean_output(raw_output) if isinstance(raw_output, str) else raw_output
            return {
                "status": "completed",
                "device": device_name,
                "command": command,
                "output": raw_output,
                "parsed": False
            }

    except Exception as e:
        logger.error(f"Error executing show command: {e}", exc_info=True)
        return {"status": "error", "error": f"Execution error: {e}"}
    finally:
        _disconnect_device(device)


async def apply_device_configuration_async(device_name: str, config_commands: Union[str, List[Any], None]) -> Dict[str, Any]:
    """
    Apply configuration using device.configure().
    
    CRITICAL:
    - Do NOT include 'configure terminal'/'conf t'/'end'
    - device.configure() handles config mode entry/exit
    """
    try:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, partial(_execute_config, device_name, config_commands))
    except Exception as e:
        logger.error(f"Error in apply_device_configuration_async: {e}", exc_info=True)
        return {"status": "error", "error": f"Configuration error: {e}"}


def _execute_config(device_name: str, config_commands: Union[str, List[Any], None]) -> Dict[str, Any]:
    device = None
    try:
        device = _get_device(device_name)

        # Route PAN-OS devices to API
        if _is_panos(device):
            logger.info(f"Routing to PAN-OS API for configuration on {device_name}")
            xml_config = config_commands if isinstance(config_commands, str) else "\n".join(str(x) for x in (config_commands or []))
            result = panos_apply_config(device, xml_config, commit=True)
            if result.get("status") == "success":
                return {
                    "status": "success",
                    "device": device_name,
                    "message": result.get("message", "Configuration applied successfully."),
                    "output": result.get("details", {}),
                    "method": "api",
                }
            return {"status": "error", "device": device_name, "error": result.get("error", "Unknown API error")}

        config_lines = _normalize_config_lines(config_commands)
        if not config_lines:
            return {"status": "error", "error": "Empty configuration provided (after normalization)."}

        reason = _config_guardrails(config_lines)
        if reason:
            return {"status": "error", "error": reason}

        logger.info(f"Applying configuration on {device_name}:")
        for line in config_lines:
            logger.info(f"  {line}")

        # CRITICAL: Pass as list to unicon for proper submode handling
        out = device.configure(config_lines)

        out = clean_output(out) if isinstance(out, str) else out
        return {
            "status": "success",
            "device": device_name,
            "message": "Configuration applied successfully.",
            "output": out,
            "commands_applied": config_lines
        }

    except Exception as e:
        logger.error(f"Error applying configuration: {e}", exc_info=True)
        return {"status": "error", "error": f"Configuration error: {e}"}
    finally:
        _disconnect_device(device)


async def execute_learn_config_async(device_name: str) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(_execute_learn_config, device_name))


def _execute_learn_config(device_name: str) -> Dict[str, Any]:
    device = None
    try:
        device = _get_device(device_name)

        # Route PAN-OS devices to API
        if _is_panos(device):
            logger.info(f"Routing to PAN-OS API for running config on {device_name}")
            result = panos_get_running_config(device)
            if result.get("status") == "success":
                return {"status": "completed", "device": device_name, "output": result.get("output", {}), "method": "api"}
            return {"status": "error", "device": device_name, "error": result.get("error", "Unknown API error")}

        device.enable()
        raw = device.execute("show running-config brief")
        return {
            "status": "completed",
            "device": device_name,
            "output": clean_output(raw)
        }
    except Exception as e:
        logger.error(f"Error learning config: {e}", exc_info=True)
        return {"status": "error", "error": f"Error learning config: {e}"}
    finally:
        _disconnect_device(device)


async def execute_learn_logging_async(device_name: str) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(_execute_learn_logging, device_name))


def _execute_learn_logging(device_name: str) -> Dict[str, Any]:
    device = None
    try:
        device = _get_device(device_name)

        # Route PAN-OS devices to API
        if _is_panos(device):
            logger.info(f"Routing to PAN-OS API for logging on {device_name}")
            result = panos_run_show(device, "show logging")
            if result.get("status") == "success":
                return {"status": "completed", "device": device_name, "output": result.get("output", {}), "method": "api"}
            return {"status": "error", "device": device_name, "error": result.get("error", "Unknown API error")}

        device.enable()
        raw = device.execute("show logging")
        return {
            "status": "completed",
            "device": device_name,
            "output": clean_output(raw)
        }
    except Exception as e:
        logger.error(f"Error learning logs: {e}", exc_info=True)
        return {"status": "error", "error": f"Error learning logs: {e}"}
    finally:
        _disconnect_device(device)


# -----------------------------------------------------------------------------
# NEW: Ping implementation (Structured)
# -----------------------------------------------------------------------------
async def run_ping_command_async(device_name: str, command: str) -> Dict[str, Any]:
    cmd = (command or "").strip().lower()
    if not cmd.startswith("ping"):
        return {"status": "error", "error": f"Command '{command}' is not a 'ping' command."}

    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(_execute_ping, device_name, command))


def _execute_ping(device_name: str, command: str) -> Dict[str, Any]:
    device = None
    try:
        device = _get_device(device_name)

        if _is_panos(device):
            return {
                "status": "error",
                "device": device_name,
                "error": "Ping not supported via this tool for PAN-OS devices. Use pyats_run_show_command with 'ping host <target>' instead.",
            }

        # ✅ FIX: Ensure Privileged Exec Mode for advanced ping options
        try:
            if not getattr(device, "is_connected", lambda: False)():
                device.connect()
            device.enable()
        except Exception as e:
            logger.warning(f"Could not enable {device_name}: {e}")

        try:
            # Attempt to parse first to get structured JSON
            parsed = device.parse(command)
            return {
                "status": "completed",
                "device": device_name,
                "command": command,
                "output": parsed,
                "parsed": True
            }
        except Exception as parse_err:
            logger.warning(f"Ping parse failed on {device_name} ({parse_err}). Falling back to raw execution.")
            # Fallback to raw execution if parser fails or syntax is unsupported
            raw = device.execute(command)
            return {
                "status": "completed",
                "device": device_name,
                "command": command,
                "output": clean_output(raw),
                "parsed": False
            }
    except Exception as e:
        logger.error(f"Error executing ping: {e}", exc_info=True)
        return {"status": "error", "error": f"Ping execution error: {e}"}
    finally:
        _disconnect_device(device)

async def run_linux_command_async(device_name: str, command: str) -> Dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, partial(_execute_linux_command, device_name, command))


def _execute_linux_command(device_name: str, command: str) -> Dict[str, Any]:
    device = None
    try:
        tb = _load_testbed()
        if device_name not in tb.devices:
            return {"status": "error", "error": f"Device '{device_name}' not found in testbed."}

        device = tb.devices[device_name]
        if not device.is_connected():
            device.connect()

        cmd = command or ""
        if ">" in cmd or "|" in cmd:
            cmd = f'sh -c "{cmd}"'

        try:
            parser = get_parser(cmd, device)
            output = device.parse(cmd) if parser else device.execute(cmd)
        except Exception:
            output = device.execute(cmd)

        output = clean_output(output) if isinstance(output, str) else output
        return {
            "status": "completed",
            "device": device_name,
            "command": command,
            "output": output
        }
    except Exception as e:
        logger.error(f"Error executing Linux command: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}
    finally:
        _disconnect_device(device)


# -----------------------------------------------------------------------------
# Dynamic test execution
# -----------------------------------------------------------------------------
BANNED_IMPORT_ROOTS = {
    "os", "sys", "subprocess", "shutil", "socket", "pathlib",
    "pickle", "yaml", "requests", "urllib", "http", "ssl",
}

BANNED_CALL_PATTERNS = [
    r"\b__import__\b",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"\bcompile\s*\(",
    r"\bopen\s*\(",
    r"\bjson\.loads\s*\(",
]

IMPORT_RE = re.compile(r"^\s*(import|from)\s+([a-zA-Z0-9_\.]+)", re.M)

def reject_unsafe_script(script: str) -> Optional[str]:
    s = script or ""

    # Block banned imports
    for m in IMPORT_RE.finditer(s):
        mod = (m.group(2) or "").strip()
        root = mod.split(".")[0].lower()
        if root in BANNED_IMPORT_ROOTS:
            return f"Unsafe import blocked: {root}"

    # Block banned calls
    for pat in BANNED_CALL_PATTERNS:
        if re.search(pat, s, flags=re.I):
            return f"Unsafe pattern blocked: {pat}"

    # Enforce TEST_DATA exists
    if "TEST_DATA" not in s:
        return "Test script must define TEST_DATA as a Python dict literal."

    return None

def _extract_overall_result(stdout: str) -> Optional[str]:
    m = re.search(r"Result\s+:\s+([A-Z]+)", stdout or "")
    return m.group(1) if m else None


def _run_test_script(script_content: str, timeout_s: int = 300) -> Dict[str, Any]:
    ts = time.strftime("%Y%m%d_%H%M%S")
    run_dir = ARTIFACTS_DIR / f"run_{ts}_{os.getpid()}"
    run_dir.mkdir(parents=True, exist_ok=True)

    script_path = run_dir / "testscript.py"
    job_path = run_dir / "job.py"
    report_path = run_dir / "job_report.json"

    try:
        script_path.write_text(script_content, encoding="utf-8")

        safe_script_path = str(script_path).replace("\\", "\\\\")
        job_content = f"""from pyats.easypy import run
def main(runtime):
    run(testscript='{safe_script_path}', runtime=runtime)
"""
        job_path.write_text(job_content, encoding="utf-8")

        pyats_exec = shutil.which("pyats") or "pyats"
        cmd = [pyats_exec, "run", "job", str(job_path), "--json-job", str(report_path)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env={**os.environ, "PYATS_TESTBED_PATH": TESTBED_PATH},
                timeout=timeout_s,
            )
        except subprocess.TimeoutExpired:
            return {
                "status": "error",
                "error": f"pyATS job timed out after {timeout_s}s",
                "artifacts_dir": str(run_dir)
            }

        report_data = None
        if report_path.exists():
            try:
                txt = report_path.read_text(encoding="utf-8")
                report_data = json.loads(txt) if txt.strip() else None
            except Exception as e:
                logger.warning(f"Failed to parse report JSON: {e}")

        overall = _extract_overall_result(result.stdout)

        payload = {
            "status": "completed",
            "returncode": result.returncode,
            "overall_result": overall,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "report": report_data,
            "artifacts_dir": str(run_dir),
            "paths": {
                "script": str(script_path),
                "job": str(job_path),
                "report": str(report_path),
            },
        }

        if not KEEP_ARTIFACTS:
            shutil.rmtree(run_dir, ignore_errors=True)

        return payload

    except Exception as e:
        logger.error(f"Error executing dynamic test: {e}", exc_info=True)
        return {"status": "error", "error": str(e), "artifacts_dir": str(run_dir)}


# -----------------------------------------------------------------------------
# MCP Server + Tools
# -----------------------------------------------------------------------------
mcp = FastMCP("pyATS Network Automation Server")


@mcp.tool()
async def pyats_list_devices() -> str:
    """List all devices available in the testbed with their properties."""
    try:
        tb = _load_testbed()
        devices: Dict[str, Any] = {}
        for name, dev in tb.devices.items():
            devices[name] = {
                "os": getattr(dev, "os", None),
                "type": getattr(dev, "type", None),
                "platform": getattr(dev, "platform", None),
                "connections": list(getattr(dev, "connections", {}).keys()),
            }
        return json.dumps({"status": "completed", "devices": devices}, indent=2)
    except Exception as e:
        logger.error(f"Error in pyats_list_devices: {e}", exc_info=True)
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def pyats_run_show_command(device_name: str, command: str) -> str:
    """
    Execute a show command on a device and return parsed output (or raw if parsing fails).
    Supports IOS-XE devices via SSH/CLI and PAN-OS devices via XML API.
    DO NOT use this for 'show logging' or 'show running-config' - use dedicated tools.
    DO NOT include pipes or redirects in commands.
    """
    try:
        result = await run_show_command_async(device_name, command)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Error in pyats_run_show_command: {e}", exc_info=True)
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def pyats_configure_device(device_name: str, config_commands: Any) -> str:
    """
    Apply configuration to a device.

    IMPORTANT:
    - Pass configuration as a list of strings or multiline string
    - Do NOT include 'configure terminal', 'conf t', or 'end'
    - The server automatically handles config mode entry/exit
    - Preserve proper indentation for submode commands (interfaces, routing protocols, etc.)
    
    Example list format:
    ["cdp run", "interface GigabitEthernet0/0", " cdp enable", " exit"]
    
    Example multiline string format:
    '''
    cdp run
    interface GigabitEthernet0/0
     cdp enable
     exit
    '''
    """
    try:
        result = await apply_device_configuration_async(device_name, config_commands)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Error in pyats_configure_device: {e}", exc_info=True)
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def pyats_configure_panos_device(
    device_name: str,
    xml_config: str,
    commit: bool = True,
    push: bool = False,
) -> str:
    """
    Apply XML configuration to a PAN-OS firewall or Panorama device.

    Args:
        device_name: Name of the PAN-OS device in the testbed.
        xml_config: XML configuration snippet to load.
        commit: Whether to commit the configuration (default: True).
        push: For Panorama — push to managed devices after commit (default: False).

    Example xml_config:
        '<network><interface><ethernet><entry name="ethernet1/1"><layer3><ip><entry name="10.1.1.1/24"/></ip></layer3></entry></ethernet></interface></network>'
    """
    try:
        tb = _load_testbed()
        device = tb.devices.get(device_name)
        if not device:
            return json.dumps({"status": "error", "error": f"Device '{device_name}' not found in testbed."}, indent=2)
        if not _is_panos(device):
            return json.dumps({"status": "error", "error": f"Device '{device_name}' is not a PAN-OS device. Use pyats_configure_device instead."}, indent=2)
        result = panos_apply_config(device, xml_config, commit=commit, push=push)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Error in pyats_configure_panos_device: {e}", exc_info=True)
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def pyats_show_running_config(device_name: str) -> str:
    """Get the complete running configuration from a device (raw output)."""
    try:
        result = await execute_learn_config_async(device_name)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Error in pyats_show_running_config: {e}", exc_info=True)
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def pyats_show_logging(device_name: str) -> str:
    """Get device logs using 'show logging' (raw output)."""
    try:
        result = await execute_learn_logging_async(device_name)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Error in pyats_show_logging: {e}", exc_info=True)
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def pyats_ping_from_network_device(device_name: str, command: str) -> str:
    """
    Execute a ping command from a network device (e.g., 'ping 1.1.1.1' or 'ping 1.1.1.1 repeat 100').
    Returns structured JSON (success rate, rtt) if parsing succeeds, otherwise raw output.
    This is preferred over pyats_run_show_command for connectivity checks.
    """
    try:
        result = await run_ping_command_async(device_name, command)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Error in pyats_ping_from_network_device: {e}", exc_info=True)
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def pyats_run_linux_command(device_name: str, command: str) -> str:
    """Execute a Linux command on a device (for Linux-based network devices)."""
    try:
        result = await run_linux_command_async(device_name, command)
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Error in pyats_run_linux_command: {e}", exc_info=True)
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


@mcp.tool()
async def pyats_run_dynamic_test(test_script_content: str) -> str:
    """
    Execute a standalone pyATS AEtest script for programmatic validation.
    
    CRITICAL REQUIREMENTS:
    - Script must NOT connect to devices (all data must be embedded)
    - Script must define TEST_DATA as a Python dict literal (no json.loads)
    - Embed all collected command outputs directly in TEST_DATA
    - Use this for health checks, validation, and complex troubleshooting
    
    Returns: Full job report with PASS/FAIL result and detailed test outcomes
    """
    if not (test_script_content or "").strip():
        return json.dumps({"status": "error", "error": "Empty test script content provided."}, indent=2)

    reason = reject_unsafe_script(test_script_content)
    if reason:
        return json.dumps({"status": "error", "error": reason}, indent=2)

    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, partial(_run_test_script, test_script_content, 300))
        return json.dumps(result, indent=2)
    except Exception as e:
        logger.error(f"Error in pyats_run_dynamic_test: {e}", exc_info=True)
        return json.dumps({"status": "error", "error": str(e)}, indent=2)


if __name__ == "__main__":
    logger.info("🚀 Starting pyATS FastMCP Server...")
    mcp.run()