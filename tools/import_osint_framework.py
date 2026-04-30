from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.request import urlopen


DEFAULT_SOURCE_URL = "https://raw.githubusercontent.com/lockfale/osint-framework/master/public/arf.json"
SOURCE_NAME = "OSINT Framework"
SOURCE_REPO = "https://github.com/lockfale/osint-framework"
SOURCE_LICENSE = "MIT"


def load_source(source: str) -> dict[str, Any]:
    if source.startswith(("http://", "https://")):
        with urlopen(source, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))

    with Path(source).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def flatten(node: dict[str, Any], parents: list[str] | None = None) -> list[dict[str, Any]]:
    parents = parents or []
    name = str(node.get("name", "")).strip()
    node_type = str(node.get("type", "")).strip() or "folder"
    path = parents + ([name] if name else [])

    if node_type == "url":
        item = dict(node)
        item["frameworkPath"] = " / ".join(parents)
        return [item]

    tools: list[dict[str, Any]] = []
    for child in node.get("children", []) or []:
        if isinstance(child, dict):
            tools.extend(flatten(child, path))
    return tools


def sql_string(value: Any) -> str:
    if value is None:
        return "NULL"
    text = str(value).replace("'", "''")
    return f"'{text}'"


def sql_bool(value: Any) -> str:
    return "true" if bool(value) else "false"


def insert_sql(tool: dict[str, Any]) -> str:
    columns = [
        "framework_path",
        "name",
        "type",
        "url",
        "description",
        "status",
        "pricing",
        "best_for",
        "input_type",
        "output_type",
        "opsec",
        "opsec_note",
        "local_install",
        "google_dork",
        "registration",
        "edit_url",
        "api",
        "invitation_only",
        "deprecated",
        "source_name",
        "source_url",
        "source_license",
    ]
    values = [
        sql_string(tool.get("frameworkPath", "")),
        sql_string(tool.get("name", "")),
        sql_string(tool.get("type", "url")),
        sql_string(tool.get("url")),
        sql_string(tool.get("description", "")),
        sql_string(tool.get("status")),
        sql_string(tool.get("pricing")),
        sql_string(tool.get("bestFor")),
        sql_string(tool.get("input")),
        sql_string(tool.get("output")),
        sql_string(tool.get("opsec")),
        sql_string(tool.get("opsecNote")),
        sql_bool(tool.get("localInstall")),
        sql_bool(tool.get("googleDork")),
        sql_bool(tool.get("registration")),
        sql_bool(tool.get("editUrl")),
        sql_bool(tool.get("api")),
        sql_bool(tool.get("invitationOnly")),
        sql_bool(tool.get("deprecated")),
        sql_string(SOURCE_NAME),
        sql_string(SOURCE_REPO),
        sql_string(SOURCE_LICENSE),
    ]
    return (
        f"INSERT INTO osint_tools ({', '.join(columns)})\n"
        f"VALUES ({', '.join(values)})\n"
        "ON CONFLICT DO NOTHING;"
    )


def build_sql(source: str) -> str:
    root = load_source(source)
    tools = flatten(root)
    lines = [
        "-- Generated OSINT Framework import.",
        f"-- Source data: {source}",
        f"-- Upstream: {SOURCE_REPO}",
        f"-- License: {SOURCE_LICENSE}",
        "BEGIN;",
    ]
    lines.extend(insert_sql(tool) for tool in tools)
    lines.append("COMMIT;")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate SQL to import OSINT Framework tools.")
    parser.add_argument("--source", default=DEFAULT_SOURCE_URL, help="arf.json URL or local path")
    parser.add_argument("--output", help="SQL output path. Defaults to stdout.")
    args = parser.parse_args()

    sql = build_sql(args.source)
    if args.output:
        Path(args.output).write_text(sql, encoding="utf-8")
    else:
        sys.stdout.write(sql)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
