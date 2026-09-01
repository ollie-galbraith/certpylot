import re
import sys
from pathlib import Path

import toml


def get_dependecies():
    pyproject_path = Path(__file__).resolve().parents[2] / "pyproject.toml"
    with pyproject_path.open("r") as f:
        pyproject = toml.load(f)
    return pyproject["tool"]["poetry"]["dependencies"]


def _python_version_matches(requirement):
    """Return True when the current Python satisfies a Poetry python constraint."""
    if not requirement:
        return True

    requirement = str(requirement).strip()
    if not requirement:
        return True

    current = sys.version_info[:3]

    def parse_version(version):
        version = re.sub(r"[^0-9.]", "", str(version))
        parts = [int(part) for part in version.split(".") if part]
        return tuple(parts) if parts else (0,)

    def compare_versions(left, right, operator):
        if operator == "==":
            return left == right
        if operator == "!=":
            return left != right
        if operator == ">":
            return left > right
        if operator == ">=":
            return left >= right
        if operator == "<":
            return left < right
        if operator == "<=":
            return left <= right
        return True

    for clause in requirement.split(","):
        clause = clause.strip()
        if not clause:
            continue

        match = re.match(r"^(==|!=|>=|<=|>|<)?\s*(.+)$", clause)
        if match is None:
            operator = "=="
            version = clause
        else:
            operator, version = match.groups()
            operator = operator or "=="

        if version.startswith("python"):
            version = version[6:].strip()

        if operator == "==" and version and not re.match(r"^[0-9]", version):
            operator = "=="
            version = version

        if not version:
            return True

        if not compare_versions(current, parse_version(version), operator):
            return False

    return True


def _format_dependency(name, version):
    """Convert a dependency specifier into a pip-compatible requirement string."""
    if not isinstance(version, str):
        return None

    def normalize_version(value):
        if value.startswith("^") or value.startswith("~"):
            return value[1:]
        return value

    def get_operator(value):
        if value.startswith(("^", "~")):
            return ">="
        if value.startswith(("=", ">", "<", "!")):
            return ""
        return "=="

    operator = get_operator(version)
    normalized = normalize_version(version) if operator != "" else version
    return f"{name}{operator}{normalized}"


def convert_dependencies_to_string(dependencies):
    """Convert dependencies dictionary to a pip-compatible string."""
    resolved = []

    for key, value in dependencies.items():
        if key == "python":
            continue

        if isinstance(value, str):
            requirement = _format_dependency(key, value)
            if requirement:
                resolved.append(requirement)
            continue

        if isinstance(value, list):
            for candidate in value:
                if not isinstance(candidate, dict):
                    continue

                version = candidate.get("version")
                python_requirement = candidate.get("python")
                if version is None:
                    continue

                if _python_version_matches(python_requirement):
                    requirement = _format_dependency(key, str(version))
                    if requirement:
                        resolved.append(requirement)
                    break

    return " ".join(resolved)


if __name__ == "__main__":
    print(convert_dependencies_to_string(get_dependecies()))