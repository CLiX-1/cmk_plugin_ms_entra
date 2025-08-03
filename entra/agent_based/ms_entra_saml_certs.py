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
# CHECKMK CHECK PLUG-IN: Microsoft Entra SAML App Certificates
#
# This plug-in generates the Checkmk services and determines their status.
# This file is part of the Microsoft Entra special agent (ms_entra).
####################################################################################################

# Example data from special agent (formatted):
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
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    check_levels,
    CheckPlugin,
    CheckResult,
    DiscoveryResult,
    Metric,
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
    app_notes: str | None
    cert_expiration: str | None
    cert_thumbprint: str | None


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


def format_result_details(app: SamlInfo, cert_expiration_timestamp_render: str) -> str:
    # This content will be used to display the application details in the check result details with
    # the available SAML certificate.
    app_details_list = [
        f"App name: {app.app_name}",
        f"App ID: {app.app_appid}",
        f"Object ID: {app.app_id}",
        "",
        f"Description: {app.app_notes or '(Not available)'}",
        "",
        "Certificate details",
        f" - Thumbprint: {app.cert_thumbprint or '(Not available)'}",
        f" - Expiration time: {cert_expiration_timestamp_render}",
    ]
    return "\n".join(app_details_list)


def check_ms_entra_saml_certs(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    app = section.get(item)
    if not app:
        return

    params_levels_cert_expiration = params["cert_expiration"]

    if app.cert_expiration:
        # Cert expiration time and timespan calculation
        cert_expiration_timestamp = datetime.fromisoformat(app.cert_expiration).timestamp()
        cert_expiration_timestamp_render = render.datetime(cert_expiration_timestamp)
        cert_expiration_timespan = cert_expiration_timestamp - datetime.now().timestamp()
    else:
        # In case the certificate expiration time is not available, the check will return
        # UNKNOWN. It prevents a service crash while time cannot be calculated for an None value.
        # The reason for this scenario could be the Microsoft Graph beta API.
        yield Result(
            state=State.UNKNOWN,
            summary=(
                "No certificate expiration time found. The value of "
                "preferredTokenSigningKeyEndDateTime is empty."
            ),
            details=format_result_details(app, "(Not available)"),
        )
        return

    # For state calculation, check_levels is used.
    # It will take the expiration timespan of the SAML certificate.
    if cert_expiration_timespan > 0:
        yield from check_levels(
            cert_expiration_timespan,
            levels_lower=(params_levels_cert_expiration),
            metric_name="ms_entra_saml_certs_remaining_validity",
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

        # To prevent a negative value for the metric.
        yield Metric(
            name="ms_entra_saml_certs_remaining_validity",
            value=0.0,
            levels=params_levels_cert_expiration[1],
        )

    # To display custom summary and details we need to yield Result.
    # The real state is calculated using the worst state of Result and check_levels.
    yield Result(
        state=State.OK,
        summary=f"Expiration time: {cert_expiration_timestamp_render}",
        details=f"\n{format_result_details(app, cert_expiration_timestamp_render)}",
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
