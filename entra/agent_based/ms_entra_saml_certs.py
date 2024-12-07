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
class EntraSamlApps:
    app_id: str
    app_appid: str
    app_name: str
    app_notes: str
    app_cert_expiration: str
    app_cert_thumbprint: str


# Example data from special agent:
# <<<ms_entra_saml_certs:sep(0)>>>
# [
#  {
#    "app_id": "00000000-0000-0000-0000-000000000000",
#    "app_appid": "00000000-0000-0000-0000-000000000000",
#    "app_name": "SAML App 1,
#    "app_notes": "SAML App 1 description",
#    "app_cert_expiration": "2025-01-01T01:00:00Z",
#    "app_cert_thumbprint": "0000000000000000000000000000000000000000"
#  },
#  {
#    "app_id": "00000000-0000-0000-0000-000000000000",
#    "app_appid": "00000000-0000-0000-0000-000000000000",
#    "app_name": "SAML App 2",
#    "app_notes": "SAML App 2 description",
#    "app_cert_expiration": "2026-06-06T13:00:00Z",
#    "app_cert_thumbprint": "0000000000000000000000000000000000000000"
#  },
#  ...
# ]

Section = Mapping[str, Sequence[EntraSamlApps]]


def parse_ms_entra_saml_certs(string_table: StringTable) -> Section:
    parsed = {}
    app_names = set()
    for item in json.loads("".join(string_table[0])):
        app_name = item["app_name"]
        # generate unique names, because entra app name is not unique
        if app_name in app_names:
            app_name_unique = f"{app_name} {item["app_id"][-4:]}"
        else:
            app_name_unique = app_name
            app_names.add(app_name)

        parsed[app_name_unique] = item

    return parsed


def discover_ms_entra_saml_certs(section: Section) -> DiscoveryResult:
    for group in section:
        yield Service(item=group)


def check_ms_entra_saml_certs(item: str, params: Mapping[str, Any], section: Section) -> CheckResult:
    app = section.get(item)
    if not app:
        return

    params_levels_cert_expiration = params.get("cert_expiration")

    app_id = app["app_id"]
    app_appid = app["app_appid"]
    app_name = app["app_name"]
    app_notes = app["app_notes"]
    app_cert_expiration = app["app_cert_expiration"]
    app_cert_thumbprint = app["app_cert_thumbprint"]

    app_cert_expiration_datetime = datetime.fromisoformat(app_cert_expiration)
    app_cert_expiration_timestamp = app_cert_expiration_datetime.timestamp()
    app_cert_expiration_timestamp_render = render.datetime(int(app_cert_expiration_timestamp))

    app_cert_expiration_timespan = app_cert_expiration_timestamp - datetime.now().timestamp()

    result_details = f"App name: {app_name}\\nApp ID: {app_appid}\\nObject ID: {app_id}\\n\\nDescription: "
    result_details += f"{app_notes}" if app_notes else "---"
    result_details += (
        f"\\n\\nCertificate\\n - Thumbprint: {app_cert_thumbprint}\\n"
        f" - Expiration time: {app_cert_expiration_timestamp_render}"
    )

    result_summary = f"Expiration time: {app_cert_expiration_timestamp_render}"

    if app_cert_expiration_timespan > 0:
        yield from check_levels(
            app_cert_expiration_timespan,
            levels_lower=(params_levels_cert_expiration),
            label="Remaining",
            render_func=render.timespan,
        )
    else:
        yield from check_levels(
            app_cert_expiration_timespan,
            levels_lower=(params_levels_cert_expiration),
            label="Expired",
            render_func=lambda x: "%s ago" % render.timespan(abs(x)),
        )

    yield Result(
        state=State.OK,
        summary=result_summary,
        details=f"\\n{result_details}",
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
