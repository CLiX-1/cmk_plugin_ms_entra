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
# Checkmk check plugin for monitoring the sync status of Entra Connect/Cloud Sync.
# The plugin works with data from the Microsoft Entra special agent (ms_entra).

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
    # If sync is not enabled, the check will return UNKNOWN.
    if section.sync_enabled is not True:
        yield Result(
            state=State.UNKNOWN,
            summary="Entra Connect/Cloud Sync not active",
        )
        return

    # Calculation of the timespan since the last sync.
    sync_last_timestamp = datetime.fromisoformat(section.sync_last).timestamp()
    sync_last_timespan = datetime.now().timestamp() - sync_last_timestamp

    # For state calculation, check_levels is used.
    # It will take the last sync timespan of the Entra Connect/Cloud Sync.
    yield from check_levels(
        sync_last_timespan,
        levels_upper=params.get("sync_period"),
        label="Last sync",
        render_func=lambda x: f"{render.timespan(abs(x))} ago",
    )

    # To display custom summary we need to yield Result.
    # The real state is calculated using the worst state of Result and check_levels.
    yield Result(
        state=State.CRIT,
        summary=f"Sync time: {render.datetime(sync_last_timestamp)}",
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
