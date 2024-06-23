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
from datetime import datetime, timezone
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
class LastSync:
    sync_enabled: bool
    sync_last: str


Section = Sequence[LastSync]

# Example data from special agent:
# <<<ms_entra_sync:sep(0)>>>
# {
#     "sync_enabled": true,
#     "sync_last": "2024-06-20T13:01:52Z"
# }


def parse_ms_entra_sync(string_table: StringTable) -> Section:
    parsed = json.loads(string_table[0][0])
    return parsed


def discover_ms_entra_sync(section: Section) -> DiscoveryResult:
    yield Service()


def check_ms_entra_sync(params: Mapping[str, Any], section: Section) -> CheckResult:
    sync_enabled = section["sync_enabled"]

    if sync_enabled is True:
        sync_last = section["sync_last"]

        params_levels_sync_period = params.get("sync_period")

        sync_last_datetime = datetime.fromisoformat(sync_last).replace(tzinfo=timezone.utc)
        sync_last_timestamp = sync_last_datetime.timestamp()

        sync_last_timespan = datetime.now().timestamp() - sync_last_timestamp

        yield from check_levels(
            sync_last_timespan,
            levels_upper=(params_levels_sync_period),
            label="Last sync",
            notice_only=False,
            render_func=lambda x: "%s ago" % render.timespan(abs(x)),
        )

    else:
        yield Result(
            state=State.UNKNOWN,
            summary="Entra connect/cloud sync not active",
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
