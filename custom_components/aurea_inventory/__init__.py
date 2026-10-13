from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
import base64
import ipaddress
import json
import re
import yaml
from pathlib import Path
from typing import Any
from urllib import error, request

import voluptuous as vol

from homeassistant.const import EVENT_HOMEASSISTANT_STARTED
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import area_registry as ar
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.util import dt as dt_util

from .kim_report import select_kim_attributes

DOMAIN = "aurea_inventory"
COMPONENT_VERSION = "1.2.3"
CONF_GITHUB_TOKEN = "github_token"
CONF_GITHUB_REPOSITORY = "github_repository"
CONF_GITHUB_PATH = "github_path"
DEFAULT_GITHUB_REPOSITORY = ""
DEFAULT_GITHUB_PATH = "inventory/aurea_inventory.json"
OUTPUT_FILE = Path("/share/aurea_inventory.json")
LOCAL_SCAN_INTERVAL = timedelta(minutes=5)
GITHUB_SYNC_INTERVAL = timedelta(minutes=30)
AUTOMATIONS_FILE = Path("/config/automations.yaml")

CONFIG_SCHEMA = vol.Schema(
    {
        DOMAIN: vol.Schema(
            {
                vol.Optional(CONF_GITHUB_TOKEN): cv.string,
                vol.Optional(CONF_GITHUB_REPOSITORY, default=DEFAULT_GITHUB_REPOSITORY): cv.string,
                vol.Optional(CONF_GITHUB_PATH, default=DEFAULT_GITHUB_PATH): cv.string,
            }
        )
    },
    extra=vol.ALLOW_EXTRA,
)

SAFE_ATTRS = {
    "friendly_name", "device_class", "unit_of_measurement", "state_class",
    "supported_features", "options", "min", "max", "step", "mode",
    "hvac_modes", "preset_modes", "fan_modes", "swing_modes",
    "temperature", "current_temperature", "humidity", "current_humidity",
    "brightness", "color_temp_kelvin", "percentage", "position",
    "current_position", "battery", "battery_level", "illuminance",
    "power", "current", "voltage", "energy", "duration", "remaining",
}
BLOCKED = {
    "latitude", "longitude", "gps_accuracy", "access_token", "entity_picture",
    "token", "password", "ssid", "bssid", "mac", "ip_address",
}



SENSITIVE_CONFIG_KEYS = {
    "token", "password", "secret", "api_key", "apikey", "authorization",
    "username", "latitude", "longitude", "gps", "mac", "ssid", "bssid",
    "entity_picture", "webhook", "webhook_id", "url", "host",
}
SENSITIVE_TEXT_PATTERNS = (
    (re.compile(r"github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|sk-[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[REDACTED_CREDENTIAL]"),
    (re.compile(r"(?i)(?:token|password|api[_ -]?key|chiave api)\s*[:=]\s*[^\s,;]+"), "[REDACTED_CREDENTIAL]"),
    (re.compile(r"https?://[^\s'\"]+", re.IGNORECASE), "[REDACTED_URL]"),
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+\-/]+=*"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(password[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"), "[REDACTED_IP]"),
    (
        re.compile(
            r"(?i)(?<![0-9A-F])(?:[0-9A-F]{2}[:-]){5}[0-9A-F]{2}(?![0-9A-F])"
        ),
        "[REDACTED_MAC]",
    ),
    (
        re.compile(r"(?i)(?<![0-9A-F])[0-9A-F]{12}(?![0-9A-F])"),
        "[REDACTED_MAC]",
    ),
)
IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f]{0,4}"
    r"(?![0-9A-Fa-f:])"
)


def _is_sensitive_key(key: Any) -> bool:
    text = str(key).lower().replace("-", "_")
    return any(part in text for part in SENSITIVE_CONFIG_KEYS)


def _sanitize_text(value: str) -> str:
    out = value
    for pattern, replacement in SENSITIVE_TEXT_PATTERNS:
        out = pattern.sub(replacement, out)

    def _redact_ipv6(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            if isinstance(ipaddress.ip_address(candidate), ipaddress.IPv6Address):
                return "[REDACTED_IP]"
        except ValueError:
            pass
        return candidate

    return IPV6_CANDIDATE_PATTERN.sub(_redact_ipv6, out)


def _sanitize_config(value: Any, key: Any = None) -> Any:
    if key is not None and _is_sensitive_key(key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _sanitize_config(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_config(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_config(item) for item in value]
    if isinstance(value, str):
        return _sanitize_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


def _load_automation_configs(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    if not path.exists():
        return [], f"File non trovato: {path}"
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if raw is None:
            return [], None
        if not isinstance(raw, list):
            return [], "automations.yaml non contiene una lista YAML"
        automations: list[dict[str, Any]] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            clean = _sanitize_config(item)
            if isinstance(clean, dict):
                automations.append(clean)
        return automations, None
    except Exception as exc:
        return [], f"{type(exc).__name__}: {str(exc)[:300]}"

def _plain(value: Any) -> Any:
    return getattr(value, "value", value)


def _safe_attrs(attrs: dict[str, Any], entity_id: str = "") -> dict[str, Any]:
    standard = {
        key: _sanitize_config(value, key)
        for key, value in attrs.items()
        if key in SAFE_ATTRS and key not in BLOCKED
    }
    standard.update(_sanitize_config(select_kim_attributes(entity_id, attrs)))
    return standard


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)


def _github_api(method: str, url: str, token: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "AUREA-Inventory",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, headers=headers, method=method)
    with request.urlopen(req, timeout=30) as response:
        raw = response.read().decode("utf-8")
        return json.loads(raw) if raw else {}


def _sync_file_to_github(path: Path, token: str, repository: str, github_path: str) -> dict[str, Any]:
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    url = f"https://api.github.com/repos/{repository}/contents/{github_path}"
    sha = None
    try:
        existing = _github_api("GET", url, token)
        sha = existing.get("sha")
    except error.HTTPError as exc:
        if exc.code != 404:
            raise
    body: dict[str, Any] = {
        "message": "Aggiorna inventario Home Assistant",
        "content": encoded,
        "branch": "main",
    }
    if sha:
        body["sha"] = sha
    return _github_api("PUT", url, token, body)


async def _build_inventory(hass: HomeAssistant) -> dict[str, Any]:
    automations_path = Path(hass.config.path("automations.yaml"))
    automation_configs, automation_config_error = await hass.async_add_executor_job(
        _load_automation_configs, automations_path
    )
    ent_reg = er.async_get(hass)
    dev_reg = dr.async_get(hass)
    area_reg = ar.async_get(hass)
    entities: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    by_device: defaultdict[str, list[str]] = defaultdict(list)

    for state in sorted(hass.states.async_all(), key=lambda s: s.entity_id):
        entity_id = state.entity_id
        domain = entity_id.split(".", 1)[0]
        counts[domain] += 1
        reg = ent_reg.async_get(entity_id)
        device = None
        area_name = None
        platform = None
        original_name = None
        entity_category = None
        disabled_by = None
        hidden_by = None
        if reg:
            platform = reg.platform
            original_name = reg.original_name
            entity_category = _plain(reg.entity_category)
            disabled_by = _plain(reg.disabled_by)
            hidden_by = _plain(reg.hidden_by)
            if reg.area_id:
                area = area_reg.async_get_area(reg.area_id)
                area_name = area.name if area else None
            if reg.device_id:
                device = dev_reg.async_get(reg.device_id)
                by_device[reg.device_id].append(entity_id)
                if area_name is None and device and device.area_id:
                    area = area_reg.async_get_area(device.area_id)
                    area_name = area.name if area else None
        device_info = None
        if device:
            device_info = {
                "name": _sanitize_config(device.name_by_user or device.name),
                "manufacturer": _sanitize_config(device.manufacturer),
                "model": _sanitize_config(device.model),
                "sw_version": _sanitize_config(device.sw_version),
                "hw_version": _sanitize_config(device.hw_version),
            }
        entities.append({
            "entity_id": entity_id,
            "domain": domain,
            "name": _sanitize_config(state.name),
            "state": _sanitize_config(state.state),
            "area": _sanitize_config(area_name),
            "platform": platform,
            "original_name": _sanitize_config(original_name),
            "entity_category": entity_category,
            "disabled_by": disabled_by,
            "hidden_by": hidden_by,
            "device": device_info,
            "attributes": _safe_attrs(dict(state.attributes), entity_id),
            "last_changed": state.last_changed.isoformat(),
            "last_updated": state.last_updated.isoformat(),
        })

    devices: list[dict[str, Any]] = []
    for device in sorted(dev_reg.devices.values(), key=lambda d: (d.name_by_user or d.name or "").lower()):
        area_name = None
        if device.area_id:
            area = area_reg.async_get_area(device.area_id)
            area_name = area.name if area else None
        devices.append({
            "name": _sanitize_config(device.name_by_user or device.name),
            "manufacturer": _sanitize_config(device.manufacturer),
            "model": _sanitize_config(device.model),
            "sw_version": _sanitize_config(device.sw_version),
            "hw_version": _sanitize_config(device.hw_version),
            "area": _sanitize_config(area_name),
            "entities": sorted(by_device.get(device.id, [])),
        })

    areas = sorted(
        [_sanitize_text(area.name) for area in area_reg.async_list_areas()],
        key=str.lower,
    )
    return {
        "schema": "aurea_ha_inventory_v1",
        "component_version": COMPONENT_VERSION,
        "generated_at": dt_util.utcnow().isoformat(),
        "summary": {
            "entity_count": len(entities),
            "device_count": len(devices),
            "area_count": len(areas),
            "automation_config_count": len(automation_configs),
            "entities_by_domain": dict(sorted(counts.items())),
        },
        "areas": areas,
        "devices": devices,
        "entities": entities,
        "automation_configs": automation_configs,
        "automation_config_status": "ok" if automation_config_error is None else "error",
        "automation_config_error": _sanitize_config(automation_config_error),
        "privacy_note": (
            "GPS, token, password, credenziali, URL/webhook, stati e nomi contenenti "
            "IP/MAC/SSID ed entity_picture sono esclusi o oscurati. Gli entity_id sono "
            "conservati invariati perché necessari per l'audit e la generazione YAML. "
            "Le configurazioni delle automazioni sono esportate in forma sanitizzata."
        ),
    }


async def _refresh_local(hass: HomeAssistant) -> dict[str, Any]:
    payload = await _build_inventory(hass)
    await hass.async_add_executor_job(_write_json, OUTPUT_FILE, payload)
    hass.states.async_set(
        "sensor.aurea_inventory_status",
        payload["summary"]["entity_count"],
        {
            "friendly_name": "AUREA Inventory",
            "unit_of_measurement": "entità",
            "generated_at": payload["generated_at"],
            "file": str(OUTPUT_FILE),
            "devices": payload["summary"]["device_count"],
            "areas": payload["summary"]["area_count"],
            "automation_configs": payload["summary"]["automation_config_count"],
            "automation_config_status": payload["automation_config_status"],
        },
    )
    return payload


async def _sync_github(hass: HomeAssistant, token: str | None, repository: str, github_path: str) -> None:
    if not repository:
        hass.states.async_set(
            "sensor.aurea_github_sync",
            "repository_missing",
            {"friendly_name": "AUREA GitHub Sync", "path": github_path},
        )
        return
    if not token:
        hass.states.async_set(
            "sensor.aurea_github_sync",
            "token_missing",
            {"friendly_name": "AUREA GitHub Sync", "repository": repository, "path": github_path},
        )
        return
    if not OUTPUT_FILE.exists():
        await _refresh_local(hass)
    try:
        result = await hass.async_add_executor_job(_sync_file_to_github, OUTPUT_FILE, token, repository, github_path)
        commit = (result.get("commit") or {}).get("sha")
        hass.states.async_set(
            "sensor.aurea_github_sync",
            "ok",
            {
                "friendly_name": "AUREA GitHub Sync",
                "repository": repository,
                "path": github_path,
                "last_sync": dt_util.utcnow().isoformat(),
                "commit": commit,
            },
        )
    except Exception as exc:
        hass.states.async_set(
            "sensor.aurea_github_sync",
            "error",
            {
                "friendly_name": "AUREA GitHub Sync",
                "repository": repository,
                "path": github_path,
                "last_error": str(exc)[:300],
            },
        )


async def async_setup(hass: HomeAssistant, config: dict[str, Any]) -> bool:
    cfg = config.get(DOMAIN, {})
    token = cfg.get(CONF_GITHUB_TOKEN)
    repository = cfg.get(CONF_GITHUB_REPOSITORY, DEFAULT_GITHUB_REPOSITORY)
    github_path = cfg.get(CONF_GITHUB_PATH, DEFAULT_GITHUB_PATH)

    async def handle_refresh(call: ServiceCall) -> None:
        await _refresh_local(hass)

    async def handle_sync(call: ServiceCall) -> None:
        await _refresh_local(hass)
        await _sync_github(hass, token, repository, github_path)

    hass.services.async_register(DOMAIN, "refresh", handle_refresh)
    hass.services.async_register(DOMAIN, "sync_github", handle_sync)

    async def started(_event) -> None:
        await _refresh_local(hass)
        await _sync_github(hass, token, repository, github_path)

    hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STARTED, started)

    async def periodic_local(_now) -> None:
        await _refresh_local(hass)

    async def periodic_github(_now) -> None:
        await _refresh_local(hass)
        await _sync_github(hass, token, repository, github_path)

    async_track_time_interval(hass, periodic_local, LOCAL_SCAN_INTERVAL)
    async_track_time_interval(hass, periodic_github, GITHUB_SYNC_INTERVAL)
    return True
