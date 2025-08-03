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
# CHECKMK CHECK PLUG-IN: Microsoft Entra CA VPN Certificate
#
# This plug-in generates the Checkmk services and determines their status.
# This file is part of the Microsoft Entra special agent (ms_entra).
####################################################################################################

# Example data from special agent (formatted):
# <<<ms_entra_ca_vpn_cert:sep(0)>>>
# [
#     {
#         "app_appid": "00000000-0000-0000-0000-000000000000",
#         "app_id": "00000000-0000-0000-0000-000000000000",
#         "app_name": "VPN Server",
#         "app_certs": [
#             {
#                 "cert_id": "00000000-0000-0000-0000-000000000000",
#                 "cert_name": "CN=Microsoft VPN root CA gen 1",
#                 "cert_identifier": "Q1dBUF9BdXRoU2VjcmV0",
#                 "cert_expiration": "1970-01-01T01:00:00Z"
#             }
#             ...
#         ]
#     }
#     ...
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
class VpnAppCert:
    cert_id: str
    cert_name: str
    cert_identifier: str
    cert_expiration: str


@dataclass(frozen=True)
class VpnApp:
    app_name: str
    app_appid: str
    app_id: str
    app_certs: list[VpnAppCert]


Section = list[VpnApp]


def parse_ms_entra_ca_vpn_cert(string_table: StringTable) -> Section:
    parsed = []
    for item in json.loads("".join(string_table[0])):
        app_certs = [VpnAppCert(**cert) for cert in item["app_certs"]]
        parsed.append(
            VpnApp(
                app_name=item["app_name"],
                app_appid=item["app_appid"],
                app_id=item["app_id"],
                app_certs=app_certs,
            )
        )
    return parsed


def discover_ms_entra_ca_vpn_cert(section: Section) -> DiscoveryResult:
    yield Service()


def check_ms_entra_ca_vpn_cert(params: Mapping[str, Any], section: Section) -> CheckResult:
    if not section:
        return

    # If there is more than one service principal with the name "VPN Server," the check will return
    # UNKNOWN because it is not clear which one is used for the Entra Conditional Access VPN.
    if len(section) > 1:
        yield Result(
            state=State.UNKNOWN,
            summary=(
                "Multiple Entra service principals with the same name found (VPN Server). "
                "Cannot decide which one is for the Conditional Access VPN. Please keep the name "
                "of the service principal unique."
            ),
        )
        return

    app = section[0]

    cert_earliest_expiration: dict[str, Any] = {}
    result_details_cert_list = []

    for cert in app.app_certs:
        cert_description = cert.cert_name

        cert_expiration_timestamp = datetime.fromisoformat(cert.cert_expiration).timestamp()

        cert_id = cert.cert_id

        # This is used to find the certificate with the earliest expiration time.
        # The expiration time of this certificate will be used for the check result.
        if (
            not cert_earliest_expiration
            or cert_expiration_timestamp < cert_earliest_expiration["cert_expiration_timestamp"]
        ):
            cert_earliest_expiration = {
                "cert_expiration_timestamp": cert_expiration_timestamp,
                "cert_id": cert_id,
                "cert_description": cert_description,
            }

        # Build a list of certificate details to be displayed in the check result details.
        cert_details_list = [
            f"ID: {cert_id}",
            f" - Description: {cert_description}",
            f" - Expiration time: {render.datetime(cert_expiration_timestamp)}",
        ]
        result_details_cert_list.append("\n".join(cert_details_list))

    # This content will be used to display the application details in the check result details with
    # all available certificates.
    app_details_list = [
        f"App name: {app.app_name}",
        f"App ID: {app.app_appid}",
        f"Object ID: {app.app_id}",
    ]
    result_details = "\n".join(app_details_list) + "\n\n" + "\n\n".join(result_details_cert_list)

    cert_earliest_expiration_timestamp = cert_earliest_expiration["cert_expiration_timestamp"]

    # Calculate the timespan until the earliest certificate expires or has expired.
    cert_expiration_timespan = cert_earliest_expiration_timestamp - datetime.now().timestamp()

    params_cert_expiration_levels = params["cert_expiration"]

    # For state calculation, check_levels is used.
    # It will take the expiration time of the certificate with the earliest expiration time.
    if cert_expiration_timespan > 0:
        yield from check_levels(
            cert_expiration_timespan,
            levels_lower=(params_cert_expiration_levels),
            metric_name="ms_entra_ca_vpn_cert_remaining_validity",
            label="Remaining",
            render_func=render.timespan,
        )
    else:
        yield from check_levels(
            cert_expiration_timespan,
            levels_lower=(params_cert_expiration_levels),
            label="Expired",
            render_func=lambda x: f"{render.timespan(abs(x))} ago",
        )

        # To prevent a negative value for the metric.
        yield Metric(
            name="ms_entra_ca_vpn_cert_remaining_validity",
            value=0.0,
            levels=params_cert_expiration_levels[1],
        )

    # To display custom summary and details we need to yield Result.
    # The real state is calculated using the worst state of Result and check_levels.
    yield Result(
        state=State.OK,
        summary=f"Expiration time: {render.datetime(cert_earliest_expiration_timestamp)}",
        details=f"\n{result_details}",
    )


agent_section_ms_entra_ca_vpn_cert = AgentSection(
    name="ms_entra_ca_vpn_cert",
    parse_function=parse_ms_entra_ca_vpn_cert,
)


check_plugin_ms_entra_ca_vpn_cert = CheckPlugin(
    name="ms_entra_ca_vpn_cert",
    service_name="Entra CA VPN certificate",
    discovery_function=discover_ms_entra_ca_vpn_cert,
    check_function=check_ms_entra_ca_vpn_cert,
    check_ruleset_name="ms_entra_ca_vpn_cert",
    check_default_parameters={"cert_expiration": ("fixed", (1209600.0, 432000.0))},
)
