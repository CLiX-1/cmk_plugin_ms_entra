#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# Copyright (C) 2024  Christopher Pommer <cp.software@outlook.de>

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.


import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    check_levels,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    render,
    Result,
    Service,
    State,
    StringTable,
)


@dataclass(frozen=True)
class EntraApps:
    app_name: str
    app_id: str
    cred_type: str
    app_creds: list


# Example data from special agent:
# <<<ms_entra_app_creds:sep(0)>>>
# [
#   {
#     "app_name": "App Registration 1",
#     "app_id": "00000000-0000-0000-0000-000000000000",
#     "cred_type": "Certificate",
#     "app_creds": [
#       {
#         "cred_id": "00000000-0000-0000-0000-000000000000",
#         "cred_name": "Cert Name 1",
#         "cred_expiration": "2032-09-26T22:00:00Z"
#       }
#     ]
#   },
#   {
#     "app_name": "App Registration 2",
#     "app_id": "00000000-0000-0000-0000-000000000000",
#     "cred_type": "Secret",
#     "app_creds": [
#       {
#         "cred_id": "00000000-0000-0000-0000-000000000000",
#         "cred_name": "Secret Name 1",
#         "cred_expiration": "2026-06-03T12:44:17.463Z"
#       },
#       {
#         "cred_id": "00000000-0000-0000-0000-000000000000",
#         "cred_name": "Secret Name 2",
#         "cred_expiration": "2025-02-07T10:45:13.016Z"
#       }
#     ]
#   },
#   ...
# ]

Section = Mapping[str, Sequence[EntraApps]]


def parse_ms_entra_app_creds(string_table: StringTable) -> Section:
    parsed = {}
    for item in json.loads("".join(string_table[0])):
        parsed[item["app_name"] + " - " + item["cred_type"]] = item
    return parsed


def discover_ms_entra_app_creds(section: Section) -> DiscoveryResult:
    for group in section:
        yield Service(item=group)


def get_cred_with_earliest_expiration(app_creds):
    cred_earliest_expiration = app_creds[0]
    for cred in app_creds:
        if cred["cred_expiration_timestamp"] < cred_earliest_expiration["cred_expiration_timestamp"]:
            cred_earliest_expiration = cred
    return cred_earliest_expiration


def check_ms_entra_app_creds(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    app = section.get(item)
    if not app:
        return

    params_levels_cred_expiration = params.get("cred_expiration")

    app_id = app["app_id"]
    app_name = app["app_name"]
    cred_type = app["cred_type"].capitalize()
    app_creds = app["app_creds"]

    result_details_list = []
    for cred in app_creds:
        cred_expiration_datetime = datetime.fromisoformat(cred["cred_expiration"])
        cred_expiration_timestamp = cred_expiration_datetime.timestamp()
        cred["cred_expiration_timestamp"] = cred_expiration_timestamp
        cred_id = cred["cred_id"]
        cred_name = cred["cred_name"]
        cred_expiration_timestamp_render = render.datetime(cred_expiration_timestamp)
        cred_details = (
            f"{cred_name}\\n - {cred_type} ID: {cred_id}\\n - Expiration time: {cred_expiration_timestamp_render}"
        )
        result_details_list.append(cred_details)

    result_details = f"App name: {app_name}\\nApp ID: {app_id}\\n\\n{'\\n\\n'.join(result_details_list)}"

    cred_earliest_expiration = get_cred_with_earliest_expiration(app_creds)

    cred_earliest_expiration_name = cred_earliest_expiration["cred_name"]
    cred_earliest_expiration_timestamp = int(cred_earliest_expiration["cred_expiration_timestamp"])
    cred_earliest_expiration_timestamp_render = render.datetime(cred_earliest_expiration_timestamp)

    cred_expiration_timespan = cred_earliest_expiration_timestamp - datetime.now().timestamp()

    result_summary = f"Expiration time: {cred_earliest_expiration_timestamp_render}"
    result_summary += (
        f", {cred_type} name: {cred_earliest_expiration_name}" if cred_earliest_expiration_name is not None else ""
    )

    if cred_expiration_timespan > 0:
        yield from check_levels(
            cred_expiration_timespan,
            levels_lower=(params_levels_cred_expiration),
            label="Remaining",
            render_func=render.timespan,
        )
    else:
        yield from check_levels(
            cred_expiration_timespan,
            levels_lower=(params_levels_cred_expiration),
            label="Expired",
            render_func=lambda x: "%s ago" % render.timespan(abs(x)),
        )

    yield Result(
        state=State.OK,
        summary=result_summary,
        details=f"\\n{result_details}",
    )


agent_section_ms_entra_app_creds = AgentSection(
    name="ms_entra_app_creds",
    parse_function=parse_ms_entra_app_creds,
)


check_plugin_ms_entra_app_creds = CheckPlugin(
    name="ms_entra_app_creds",
    service_name="Entra app creds %s",
    discovery_function=discover_ms_entra_app_creds,
    check_function=check_ms_entra_app_creds,
    check_ruleset_name="ms_entra_app_creds",
    check_default_parameters={"cred_expiration": ("fixed", (1209600.0, 432000.0))},
)
