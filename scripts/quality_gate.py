#!/usr/bin/env python3
"""Local quality gate for the Konke Smart Home Assistant integration."""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION = ROOT / "custom_components" / "konke"

ALLOWED_HTTP_FILES = {
    INTEGRATION / "api.py",
    INTEGRATION / "const.py",
    INTEGRATION / "diagnostics.py",
    INTEGRATION / "config_flow.py",
    INTEGRATION / "profile.py",
    INTEGRATION / "__init__.py",
}
ALLOWED_DEVICE_TYPE_FILES = {
    INTEGRATION / "capabilities.py",
    INTEGRATION / "device_profiles.py",
    INTEGRATION / "models.py",
    INTEGRATION / "mappings.py",
}
ALLOWED_SECRET_WORD_FILES = {
    INTEGRATION / "api.py",
    INTEGRATION / "config_flow.py",
    INTEGRATION / "const.py",
    INTEGRATION / "coordinator.py",
    INTEGRATION / "diagnostics.py",
    INTEGRATION / "translations" / "en.json",
    INTEGRATION / "translations" / "zh-Hans.json",
}
DEVICE_TYPE_TERMS = (
    "AirCondition",
    "FloorHeating",
    "AirFresher",
    "CurtainsMotor",
    "MultiInOneManager",
    "fan_coil",
    "floor_heating",
    "air_fresher",
    "curtain",
    "multi_one_controller",
)
SECRET_VALUE_PATTERNS = (
    re.compile(r"eyJ[A-Za-z0-9_-]{40,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._-]{20,}", re.IGNORECASE),
    re.compile(r"Authorization['\"]?\s*[:=]\s*['\"][A-Za-z0-9._-]{20,}"),
)
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def main() -> int:
    """Run all local checks."""
    failures: list[str] = []

    failures.extend(check_required_files())
    failures.extend(check_manifest())
    failures.extend(check_translations())
    failures.extend(check_python_parse())
    failures.extend(check_compileall())
    failures.extend(check_pytest())
    failures.extend(check_platform_boundaries())
    failures.extend(check_write_audit_boundaries())
    failures.extend(check_removed_raw_command())
    failures.extend(check_device_type_boundaries())
    failures.extend(check_platform_helpers_boundary())
    failures.extend(check_secret_literals())
    failures.extend(check_release_package_hygiene())

    if failures:
        print("QUALITY GATE FAILED")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("QUALITY GATE PASSED")
    return 0


def check_required_files() -> list[str]:
    """Check project guardrail files exist."""
    required = (
        ROOT / "README.md",
        ROOT / "pyproject.toml",
        ROOT / "docs" / "api.md",
        INTEGRATION / "manifest.json",
        INTEGRATION / "capabilities.py",
        INTEGRATION / "options.py",
        INTEGRATION / "profile.py",
        INTEGRATION / "device_profiles.py",
        INTEGRATION / "models.py",
        INTEGRATION / "mappings.py",
        INTEGRATION / "entity.py",
        INTEGRATION / "registry.py",
        INTEGRATION / "command.py",
        INTEGRATION / "api.py",
        INTEGRATION / "forensics.py",
        INTEGRATION / "sensor.py",
    )
    return [
        f"Missing required file: {path.relative_to(ROOT)}"
        for path in required
        if not path.exists()
    ]


def check_manifest() -> list[str]:
    """Check manifest shape."""
    manifest_path = INTEGRATION / "manifest.json"
    if not manifest_path.exists():
        return []
    try:
        manifest = json.loads(manifest_path.read_text())
    except json.JSONDecodeError as err:
        return [f"manifest.json is invalid JSON: {err}"]

    failures: list[str] = []
    if manifest.get("domain") != "konke":
        failures.append("manifest domain must be 'konke'")
    version = manifest.get("version")
    if not isinstance(version, str) or not SEMVER_RE.match(version):
        failures.append("manifest version must be semantic x.y.z")
    if manifest.get("config_flow") is not True:
        failures.append("manifest config_flow must remain true")
    if manifest.get("iot_class") != "cloud_polling":
        failures.append("manifest iot_class must remain cloud_polling")
    return failures


def check_translations() -> list[str]:
    """Check translation files are valid JSON and include service keys."""
    failures: list[str] = []
    required_services = {
        "execute_scene",
        "refresh",
        "clear_forensic_history",
    }
    for path in sorted((INTEGRATION / "translations").glob("*.json")):
        try:
            payload = json.loads(path.read_text())
        except json.JSONDecodeError as err:
            failures.append(f"{path.relative_to(ROOT)} is invalid JSON: {err}")
            continue
        services = payload.get("services", {})
        missing = sorted(required_services - set(services))
        if missing:
            failures.append(
                f"{path.relative_to(ROOT)} missing service translations: {', '.join(missing)}"
            )
    return failures


def check_python_parse() -> list[str]:
    """Check all Python files parse."""
    failures: list[str] = []
    for path in python_files():
        try:
            ast.parse(path.read_text(), filename=str(path))
        except SyntaxError as err:
            failures.append(f"Syntax error in {path.relative_to(ROOT)}: {err}")
    return failures


def check_compileall() -> list[str]:
    """Run compileall on the integration."""
    env = dict(os.environ)
    with tempfile.TemporaryDirectory(prefix="konke-pycache-") as cache_dir:
        env["PYTHONPYCACHEPREFIX"] = cache_dir
        result = subprocess.run(
            [sys.executable, "-m", "compileall", "-q", str(INTEGRATION)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    if result.returncode == 0:
        return []
    return [
        "compileall failed: "
        + (result.stderr.strip() or result.stdout.strip() or "unknown error")
    ]


def check_pytest() -> list[str]:
    """Run Home Assistant pytest tests."""
    tests_dir = ROOT / "tests" / "components" / "konke"
    if not tests_dir.exists():
        return ["Missing Home Assistant pytest directory: tests/components/konke"]
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/components/konke"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0:
        return []
    return [
        "pytest failed: "
        + (result.stderr.strip() or result.stdout.strip() or "unknown error")
    ]


def check_platform_boundaries() -> list[str]:
    """Prevent direct HTTP/client access outside API/coordinator boundaries."""
    failures: list[str] = []
    for path in python_files():
        if path in ALLOWED_HTTP_FILES or "scripts" in path.relative_to(ROOT).parts:
            continue
        text = path.read_text()
        forbidden_patterns = (
            "aiohttp",
            "ClientSession",
            "async_get_clientsession",
            "self._session.",
            "kapp.ikonke.com",
            "ACCOUNT_BASE_URL",
            "API_BASE_URL",
        )
        hits = [pattern for pattern in forbidden_patterns if pattern in text]
        if hits:
            failures.append(
                f"{path.relative_to(ROOT)} contains direct HTTP/API boundary terms: {', '.join(hits)}"
            )
    return failures


def check_write_audit_boundaries() -> list[str]:
    """Ensure production writes cannot bypass the forensic coordinator."""
    allowed = {
        INTEGRATION / "api.py",
        INTEGRATION / "coordinator.py",
    }
    failures: list[str] = []
    write_methods = {
        "control_device",
        "control_device_exchange",
        "execute_scene",
        "execute_scene_exchange",
        "pause_device",
        "set_air_conditioner_fan_speed",
        "set_device_mode",
        "set_device_temperature",
        "turn_off_device",
        "turn_on_device",
    }
    for path in python_files():
        if path in allowed or "tests" in path.relative_to(ROOT).parts:
            continue
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in write_methods
            ):
                failures.append(
                    f"{path.relative_to(ROOT)} bypasses forensic write audit: "
                    f"{node.func.attr}()"
                )
    return failures


def check_removed_raw_command() -> list[str]:
    """Ensure the removed arbitrary-write service cannot return to production."""
    failures: list[str] = []
    for path in sorted(INTEGRATION.rglob("*")):
        if not path.is_file() or path.suffix not in {".py", ".json", ".yaml"}:
            continue
        text = path.read_text(errors="ignore")
        if "raw_command" not in text and "debug_raw_command" not in text:
            continue
        if path == INTEGRATION / "__init__.py":
            occurrences = [
                line.strip()
                for line in text.splitlines()
                if "raw_command" in line or "debug_raw_command" in line
            ]
            if occurrences == ['options.pop("debug_raw_command", None)']:
                continue
        failures.append(
            f"{path.relative_to(ROOT)} still contains the removed raw-command surface"
        )
    return failures


def check_device_type_boundaries() -> list[str]:
    """Keep device type string matching centralized."""
    failures: list[str] = []
    for path in python_files():
        relative_parts = path.relative_to(ROOT).parts
        if (
            path in ALLOWED_DEVICE_TYPE_FILES
            or "scripts" in relative_parts
            or "tests" in relative_parts
        ):
            continue
        try:
            tree = ast.parse(path.read_text(), filename=str(path))
        except SyntaxError:
            continue
        string_values = [
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        hits = sorted(
            {
                term
                for value in string_values
                for term in DEVICE_TYPE_TERMS
                if term in value
            }
        )
        if hits:
            failures.append(
                f"{path.relative_to(ROOT)} contains device type strings outside models/mappings: {', '.join(hits)}"
            )
    return failures


def check_platform_helpers_boundary() -> list[str]:
    """Keep platform_helpers as a narrow pure platform helper module."""
    path = INTEGRATION / "platform_helpers.py"
    if not path.exists():
        return ["Missing platform_helpers.py"]

    text = path.read_text()
    forbidden_terms = (
        "api",
        "client",
        "command",
        "profile",
        "services",
        "ACTION_",
        "build_device_action_body",
        "aiohttp",
        "ClientSession",
        "kapp.ikonke.com",
        "ACCOUNT_BASE_URL",
        "API_BASE_URL",
    )
    failures = [
        f"platform_helpers.py must not contain boundary term: {term}"
        for term in forbidden_terms
        if term in text
    ]
    for term in DEVICE_TYPE_TERMS:
        if term in text:
            failures.append(
                f"platform_helpers.py must not contain device type string: {term}"
            )
    return failures


def check_secret_literals() -> list[str]:
    """Look for likely pasted tokens or auth headers."""
    failures: list[str] = []
    for path in project_text_files():
        if path in ALLOWED_SECRET_WORD_FILES:
            continue
        text = path.read_text(errors="ignore")
        for pattern in SECRET_VALUE_PATTERNS:
            if pattern.search(text):
                failures.append(
                    f"{path.relative_to(ROOT)} contains a likely secret literal"
                )
                break
    return failures


def check_release_package_hygiene() -> list[str]:
    """Prevent generated Python cache files inside the project."""
    failures: list[str] = []
    for path in ROOT.rglob("*"):
        if "__pycache__" in path.parts:
            failures.append(f"Generated __pycache__ present: {path.relative_to(ROOT)}")
        elif path.suffix == ".pyc":
            failures.append(f"Generated pyc present: {path.relative_to(ROOT)}")
    return failures


def python_files() -> list[Path]:
    """Return Python files that are part of the project."""
    return sorted(
        path for path in ROOT.rglob("*.py") if "__pycache__" not in path.parts
    )


def project_text_files() -> list[Path]:
    """Return text files worth scanning for accidental secrets."""
    suffixes = {".py", ".json", ".yaml", ".yml", ".md", ".txt"}
    return sorted(
        path
        for path in ROOT.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix in suffixes
    )


if __name__ == "__main__":
    raise SystemExit(main())
