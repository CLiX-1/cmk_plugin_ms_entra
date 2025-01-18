#!/usr/bin/env python3
# -*- coding: utf-8; py-indent-offset: 4; max-line-length: 100 -*-

# Copyright (C) 2025  Christopher Pommer <cp.software@outlook.de>

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


####################################################################################################
# Checkmk check plugin for monitoring the expiration of secrests and certificates from
# Microsoft Entra App Registrations.
# The plugin works with data from the Microsoft Entra Special Agent (ms_entra).

# Example data from special agent:
# <<<ms_entra_app_creds:sep(0)>>>
# [
#   {
#     "app_name": "App Registration 1",
#     "app_appid": "00000000-0000-0000-0000-000000000000",
#     "app_id": "00000000-0000-0000-0000-000000000000",
#     "app_notes": "Description of App Registration 1",
#     "cred_type": "Certificate",
#     "app_creds": [
#       {
#         "cred_id": "00000000-0000-0000-0000-000000000000",
#         "cred_name": "Cert Name 1",
#         "cred_expiration": "1970-01-01T01:00:00Z"
#       }
#     ]
#   },
#   {
#     "app_name": "App Registration 2",
#     "app_appid": "00000000-0000-0000-0000-000000000000",
#     "app_id": "00000000-0000-0000-0000-000000000000",
#     "app_notes": "Description of App Registration 2",
#     "cred_type": "Secret",
#     "app_creds": [
#       {
#         "cred_id": "00000000-0000-0000-0000-000000000000",
#         "cred_name": "Secret Name 1",
#         "cred_expiration": "1970-01-01T01:00:00Z"
#       },
#       {
#         "cred_id": "00000000-0000-0000-0000-000000000000",
#         "cred_name": "Secret Name 2",
#         "cred_expiration": "1970-01-01T01:00:00Z"
#       }
#     ]
#   },
#   ...
# ]


import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, List, Optional, TypedDict

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


class AppCred(TypedDict):
    cred_id: str
    cred_name: Optional[str]
    cred_expiration: str


@dataclass(frozen=True)
class AppRegistration:
    app_name: str
    app_appid: str
    app_id: str
    app_notes: Optional[str]
    cred_type: str
    app_creds: List[AppCred]


Section = Mapping[str, AppRegistration]


def parse_ms_entra_app_creds(string_table: StringTable) -> Section:
    parsed = {}
    for item in json.loads("".join(string_table[0])):
        service_name = f"{item['app_name']} - {item['cred_type']}"
        parsed[service_name] = AppRegistration(**item)
    return parsed


def discover_ms_entra_app_creds(section: Section) -> DiscoveryResult:
    for group in section:
        yield Service(item=group)


def get_cred_with_earliest_expiration(app_creds):
    cred_earliest_expiration = app_creds[0]
    for cred in app_creds:
        if (
            cred["cred_expiration_timestamp"]
            < cred_earliest_expiration["cred_expiration_timestamp"]
        ):
            cred_earliest_expiration = cred
    return cred_earliest_expiration


def check_ms_entra_app_creds(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    app = section.get(item)
    if not app:
        return

    params_cred_exclude_list = params.get("cred_exclude")

    compiled_patterns = [re.compile(pattern) for pattern in params_cred_exclude_list]

    cred_type = app.cred_type.capitalize()

    credentials = []
    result_details_list = []
    for cred in app.app_creds:
        cred_name = cred.get("cred_name") or ""

        cred_excluded = False
        for pattern in compiled_patterns:
            if pattern.match(cred_name):
                cred_excluded = True
                break

        if not cred_excluded:
            cred_expiration_datetime = datetime.fromisoformat(cred["cred_expiration"])
            cred_expiration_timestamp = cred_expiration_datetime.timestamp()
            cred_expiration_timestamp_render = render.datetime(cred_expiration_timestamp)

            cred_id = cred["cred_id"]
            cred_details = (
                f"{cred_type} ({cred_name})"
                f"\n - ID: {cred_id}"
                f"\n - Expiration time: {cred_expiration_timestamp_render}"
            )
            result_details_list.append(cred_details)

            credential_dict = {
                "cred_expiration_timestamp": cred_expiration_timestamp,
                "cred_id": cred_id,
                "cred_name": cred_name,
            }
            credentials.append(credential_dict)

    if not credentials:
        return

    result_details = (
        f"App name: {app.app_name}\nApp ID: {app.app_appid}\nObject ID: {app.app_id}"
        "\n\nDescription: "
    )
    result_details += f"{app.app_notes}" if app.app_notes else "---"
    result_details += f"\n\n{'\n\n'.join(result_details_list)}"

    # Credential with earliest expiration time and timespan calculation
    cred_earliest_expiration = get_cred_with_earliest_expiration(credentials)
    cred_earliest_expiration_name = cred_earliest_expiration["cred_name"]
    cred_earliest_expiration_timestamp = int(cred_earliest_expiration["cred_expiration_timestamp"])
    cred_earliest_expiration_timestamp_render = render.datetime(cred_earliest_expiration_timestamp)
    cred_expiration_timespan = cred_earliest_expiration_timestamp - datetime.now().timestamp()

    result_summary = f"Expiration time: {cred_earliest_expiration_timestamp_render}"
    result_summary += (
        f", Name: {cred_earliest_expiration_name}"
        if cred_earliest_expiration_name is not None
        else ""
    )

    params_cred_expiration_levels = params.get("cred_expiration")

    if cred_expiration_timespan > 0:
        yield from check_levels(
            cred_expiration_timespan,
            levels_lower=(params_cred_expiration_levels),
            label="Remaining",
            render_func=render.timespan,
        )
    else:
        yield from check_levels(
            cred_expiration_timespan,
            levels_lower=(params_cred_expiration_levels),
            label="Expired",
            render_func=lambda x: f"{render.timespan(abs(x))} ago",
        )

    yield Result(
        state=State.OK,
        summary=result_summary,
        details=f"\n{result_details}",
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
