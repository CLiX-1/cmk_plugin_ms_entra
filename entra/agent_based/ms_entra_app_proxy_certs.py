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
# CHECKMK CHECK PLUG-IN: Microsoft Entra App Proxy Certificates
#
# This plug-in generates the Checkmk services and determines their status.
# This file is part of the Microsoft Entra special agent (ms_entra).
####################################################################################################

# Example data from special agent (formatted):
# <<<ms_entra_app_proxy_certs:sep(0)>>>
# [
#     {
#         "app_name": "App 1",
#         "app_appid": "00000000-0000-0000-0000-000000000000",
#         "app_id": "00000000-0000-0000-0000-000000000000",
#         "app_notes": "App 1 description",
#         "internal_url": "https://app1.internal.tld/",
#         "external_url": "https://app1.external.tld/",
#         "cert_thumbprint": "0000000000000000000000000000000000000000",
#         "cert_subject_name": "app1.external.tld",
#         "cert_expiration": "1970-01-01T01:00:00Z"
#     },
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
class AppProxyInfo:
    app_appid: str
    app_id: str
    app_name: str
    app_notes: str | None
    cert_expiration: str
    cert_subject_name: str
    cert_thumbprint: str
    external_url: str
    internal_url: str


Section = Mapping[str, AppProxyInfo]


def parse_ms_entra_app_proxy_certs(string_table: StringTable) -> Section:
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

        parsed[app_name_unique] = AppProxyInfo(**item)

    return parsed


def discover_ms_entra_app_proxy_certs(section: Section) -> DiscoveryResult:
    for group in section:
        yield Service(item=group)


def check_ms_entra_app_proxy_certs(
    item: str, params: Mapping[str, Any], section: Section
) -> CheckResult:
    app = section.get(item)
    if not app:
        return

    params_levels_cert_expiration = params["cert_expiration"]

    # Cert expiration time and timespan calculation
    cert_expiration_timestamp = datetime.fromisoformat(app.cert_expiration).timestamp()
    cert_expiration_timestamp_render = render.datetime(cert_expiration_timestamp)
    cert_expiration_timespan = cert_expiration_timestamp - datetime.now().timestamp()

    # For state calculation, check_levels is used.
    # It will take the expiration timespan of the app proxy certificate.
    if cert_expiration_timespan > 0:
        yield from check_levels(
            cert_expiration_timespan,
            levels_lower=(params_levels_cert_expiration),
            metric_name="ms_entra_app_proxy_cert_remaining_validity",
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
            name="ms_entra_app_proxy_cert_remaining_validity",
            value=0.0,
            levels=params_levels_cert_expiration[1],
        )

    app_details_list = "\n".join(
        [
            f"App name: {app.app_name}",
            f"App ID: {app.app_appid}",
            f"Object ID: {app.app_id}",
            "",
            f"Description: {app.app_notes or '(Not available)'}",
            "",
            f"Internal URL: {app.internal_url}",
            f"External URL: {app.external_url}",
            "",
            "Certificate details",
            f" - Subject name: {app.cert_subject_name}",
            f" - Thumbprint: {app.cert_thumbprint}",
            f" - Expiration time: {cert_expiration_timestamp_render}",
        ]
    )

    # To display custom summary and details we need to yield Result.
    # The real state is calculated using the worst state of Result and check_levels.
    yield Result(
        state=State.OK,
        summary=f"Expiration time: {cert_expiration_timestamp_render}",
        details=f"\n{app_details_list}",
    )


agent_section_ms_entra_app_proxy_certs = AgentSection(
    name="ms_entra_app_proxy_certs",
    parse_function=parse_ms_entra_app_proxy_certs,
)


check_plugin_ms_entra_app_proxy_certs = CheckPlugin(
    name="ms_entra_app_proxy_certs",
    service_name="Entra app proxy certificate %s",
    discovery_function=discover_ms_entra_app_proxy_certs,
    check_function=check_ms_entra_app_proxy_certs,
    check_ruleset_name="ms_entra_app_proxy_certs",
    check_default_parameters={"cert_expiration": ("fixed", (1209600.0, 432000.0))},
)
