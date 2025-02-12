#!/usr/bin/env python3
# -*- coding: utf-8; py-indent-offset: 4; max-line-length: 100 -*-

# Copyright (C) 2024, 2025  Christopher Pommer <cp.software@outlook.de>

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
# Checkmk check plugin for monitoring the expiration of secrets and certificates from
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
#         "cred_identifier": 239527ECF41F3FCFADBF68F93689FD4EBE19A3B0,
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
#         "cred_name": null",
#         "cred_identifier": "Q1dBUF9BdXRoU2VjcmV0",
#         "cred_expiration": "1970-01-01T01:00:00Z"
#       },
#       {
#         "cred_id": "00000000-0000-0000-0000-000000000000",
#         "cred_name": "Secret Name 2",
#         "cred_identifier": null,
#         "cred_expiration": "1970-01-01T01:00:00Z"
#       }
#     ]
#   },
#   ...
# ]

import base64
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
    cred_identifier: Optional[str]
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


def check_ms_entra_app_creds(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    app = section.get(item)
    if not app:
        return

    params_cred_exclude_list = params.get("cred_exclude", [])

    compiled_patterns = [re.compile(pattern) for pattern in params_cred_exclude_list]

    # The type of the credentials is capitalized for the check result details.
    cred_type = app.cred_type.capitalize()

    result_details_cred_list = []
    cred_earliest_expiration = None
    for cred in app.app_creds:
        cred_description = cred["cred_name"] or ""
        cred_identifier = cred["cred_identifier"]

        # It is possible that the credential displayName (cred_name) is not set, but the
        # customKeyIdentifier (cred_identifier) is. For secrets, both values are used as
        # the description. For certificates, only the displayName is used as the description.
        # The customKeyIdentifier for certificates is usually the certificate thumbprint, but
        # not always a valid one. The identifier is base64 encoded and will be decoded for
        # secrets if possible, because sometimes it is not a valid base64 string. It also
        # happens that both values are set or not. If both are set, the dsiplayName is used.
        if not cred_description and cred_identifier and cred_type == "Secret":
            try:
                cred_description = base64.b64decode(cred_identifier).decode("utf-8")
            except Exception:
                pass

        cred_expiration_timestamp = datetime.fromisoformat(cred["cred_expiration"]).timestamp()

        cred_id = cred["cred_id"]

        # This is used to find the credential with the earliest expiration time.
        # The expiration time of this credential will be used for the check result.
        # Only credentials that are not excluded by a Checkmk rule are considered.
        if not any(pattern.match(cred_description) for pattern in compiled_patterns) and (
            cred_earliest_expiration is None
            or cred_expiration_timestamp < cred_earliest_expiration["cred_expiration_timestamp"]
        ):
            cred_earliest_expiration = {
                "cred_expiration_timestamp": cred_expiration_timestamp,
                "cred_id": cred_id,
                "cred_description": cred_description,
            }

        # Build a list of credential details to be displayed in the check result details.
        cred_details_list = [
            f"{cred_type} ID: {cred_id}",
            f" - Description: {cred_description or '(Not available)'}",
            f" - Expiration time: {render.datetime(cred_expiration_timestamp)}",
        ]
        result_details_cred_list.append("\n".join(cred_details_list))

    # This content will be used to display the application details in the check result details with
    # all available credentials.
    app_details_list = [
        f"App name: {app.app_name}",
        f"App ID: {app.app_appid}",
        f"Object ID: {app.app_id}",
        "",
        f"Description: {app.app_notes or '(Not available)'}",
    ]
    result_details = "\n".join(app_details_list) + "\n\n" + "\n\n".join(result_details_cred_list)

    # It will only be None, if all credentials are excluded by a Checkmk rule.
    if cred_earliest_expiration is not None:
        cred_earliest_expiration_description = cred_earliest_expiration["cred_description"]
        cred_earliest_expiration_timestamp = cred_earliest_expiration["cred_expiration_timestamp"]

        # Calculate the timespan until the earliest credential expires or has expired.
        cred_expiration_timespan = cred_earliest_expiration_timestamp - datetime.now().timestamp()

        # This content will be used as the check result summary.
        result_summary = f"Expiration time: {render.datetime(cred_earliest_expiration_timestamp)}"
        result_summary += (
            f", Description: {cred_earliest_expiration_description}"
            if cred_earliest_expiration_description
            else ""
        )

        params_cred_expiration_levels = params.get("cred_expiration")

        # For state calculation, check_levels is used.
        # It will take the expiration time of the credential with the earliest expiration time.
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

    else:
        result_summary = "All application credentials are excluded"

    # To display custom summary and details we need to yield Result.
    # The real state is calculated using the worst state of Result and check_levels.
    # Also if all credentials are excluded, we need to yield Result with state OK.
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
