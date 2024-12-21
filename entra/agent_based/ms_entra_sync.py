#!/usr/bin/env python3
# -*- coding: utf-8; py-indent-offset: 4; max-line-length: 100 -*-

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


####################################################################################################
# Checkmk check plugin for monitoring the sync status of Entra connect/cloud sync.
# The plugin works with data from the Microsoft Entra Special Agent (ms_entra).

# Example data from special agent:
# <<<ms_entra_sync:sep(0)>>>
# {
#     "sync_enabled": true,
#     "sync_last": "1970-01-01T01:00:00Z"
# }


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
class EntraSyncStatus:
    sync_enabled: Optional[bool]
    sync_last: Optional[str]


Section = EntraSyncStatus


def parse_ms_entra_sync(string_table: StringTable) -> Section:
    parsed = json.loads(string_table[0][0])
    return EntraSyncStatus(**parsed)


def discover_ms_entra_sync(section: Section) -> DiscoveryResult:
    yield Service()


def check_ms_entra_sync(params: Mapping[str, Any], section: Section) -> CheckResult:
    if section.sync_enabled is not True:
        yield Result(
            state=State.UNKNOWN,
            summary="Entra connect/cloud sync not active",
        )
        return

    params_levels_sync_period = params.get("sync_period")

    # Last sync time and timespan calculation
    sync_last_datetime = datetime.fromisoformat(section.sync_last)
    sync_last_timestamp = sync_last_datetime.timestamp()
    sync_last_timestamp_render = render.datetime(int(sync_last_timestamp))
    sync_last_timespan = datetime.now().timestamp() - sync_last_timestamp

    result_summary = f"Sync time: {sync_last_timestamp_render}"

    yield from check_levels(
        sync_last_timespan,
        levels_upper=(params_levels_sync_period),
        label="Last sync",
        render_func=lambda x: f"{render.timespan(abs(x))} ago",
    )

    yield Result(
        state=State.OK,
        summary=result_summary,
    )


agent_section_ms_entra_sync = AgentSection(
    name="ms_entra_sync",
    parse_function=parse_ms_entra_sync,
)


check_plugin_ms_entra_sync = CheckPlugin(
    name="ms_entra_sync",
    service_name="Entra connect sync",
    discovery_function=discover_ms_entra_sync,
    check_function=check_ms_entra_sync,
    check_ruleset_name="ms_entra_sync",
    check_default_parameters={"sync_period": ("fixed", (3600.0, 10800.0))},
)
