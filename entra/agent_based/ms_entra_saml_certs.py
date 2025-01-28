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
# Checkmk check plugin for monitoring the expiration of SAML certificates on
# Microsoft Entra Service Principals.
# The plugin works with data from the Microsoft Entra Special Agent (ms_entra).

# Example data from special agent:
# <<<ms_entra_saml_certs:sep(0)>>>
# [
#  {
#    "app_id": "00000000-0000-0000-0000-000000000000",
#    "app_appid": "00000000-0000-0000-0000-000000000000",
#    "app_name": "SAML App 1,
#    "app_notes": "SAML App 1 description",
#    "cert_expiration": "1970-01-01T01:00:00Z",
#    "cert_thumbprint": "0000000000000000000000000000000000000000"
#  },
#  {
#    "app_id": "00000000-0000-0000-0000-000000000000",
#    "app_appid": "00000000-0000-0000-0000-000000000000",
#    "app_name": "SAML App 2",
#    "app_notes": "SAML App 2 description",
#    "cert_expiration": "1970-01-01T01:00:00Z",
#    "cert_thumbprint": "0000000000000000000000000000000000000000"
#  },
#  ...
# ]


import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

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
class SamlInfo:
    app_appid: str
    app_id: str
    app_name: str
    app_notes: Optional[str]
    cert_expiration: str
    cert_thumbprint: str


Section = Mapping[str, SamlInfo]


def parse_ms_entra_saml_certs(string_table: StringTable) -> Section:
    parsed = {}
    app_names = set()
    for item in json.loads("".join(string_table[0])):
        app_name = item["app_name"]
        # generate unique names, because entra app name is not unique
        if app_name in app_names:
            app_name_unique = f"{app_name} {item['app_id'][-4:]}"
        else:
            app_name_unique = app_name
            app_names.add(app_name)

        parsed[app_name_unique] = SamlInfo(**item)

    return parsed


def discover_ms_entra_saml_certs(section: Section) -> DiscoveryResult:
    for group in section:
        yield Service(item=group)


def check_ms_entra_saml_certs(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    app = section.get(item)
    if not app:
        return

    params_levels_cert_expiration = params.get("cert_expiration")

    # Cert expiration time and timespan calculation
    cert_expiration_timestamp = datetime.fromisoformat(app.cert_expiration).timestamp()
    cert_expiration_timestamp_render = render.datetime(int(cert_expiration_timestamp))
    cert_expiration_timespan = cert_expiration_timestamp - datetime.now().timestamp()

    # This content will be used to display the application details in the check result details with
    # the available SAML certificate.
    app_details_list = [
        f"App name: {app.app_name}",
        f"App ID: {app.app_appid}",
        f"Object ID: {app.app_id}",
        "",
        f"Description: {app.app_notes or '(Not available)'}",
        "",
        "Certificate",
        f" - Thumbprint: {app.cert_thumbprint}",
        f" - Expiration time: {cert_expiration_timestamp_render}",
    ]
    result_details = "\n".join(app_details_list)

    # This content will be used as the check result summary.
    result_summary = f"Expiration time: {cert_expiration_timestamp_render}"

    # For state calculation, check_levels is used.
    # It will take the expiration time of the SAML certificate.
    if cert_expiration_timespan > 0:
        yield from check_levels(
            cert_expiration_timespan,
            levels_lower=(params_levels_cert_expiration),
            label="Remaining",
            render_func=render.timespan,
        )
    else:
        yield from check_levels(
            cert_expiration_timespan,
            levels_lower=(params_levels_cert_expiration),
            label="Expired",
            render_func=lambda x: "%s ago" % render.timespan(abs(x)),
        )

    # To display custom summary and details we need to yield Result.
    # The real state is calculated by check_levels.
    yield Result(
        state=State.OK,
        summary=result_summary,
        details=f"\n{result_details}",
    )


agent_section_ms_entra_saml_certs = AgentSection(
    name="ms_entra_saml_certs",
    parse_function=parse_ms_entra_saml_certs,
)


check_plugin_ms_entra_saml_certs = CheckPlugin(
    name="ms_entra_saml_certs",
    service_name="Entra SAML certificate %s",
    discovery_function=discover_ms_entra_saml_certs,
    check_function=check_ms_entra_saml_certs,
    check_ruleset_name="ms_entra_saml_certs",
    check_default_parameters={"cert_expiration": ("fixed", (1209600.0, 432000.0))},
)
