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
# CHECKMK RULESET: Microsoft Entra Connect/Cloud Sync (check plug-in)
#
# This file defines the check plug-in parameters for the "Microsoft Entra Connect/Cloud Sync" check.
# The check is part of the Microsoft Entra special agent (ms_entra).
####################################################################################################

from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    LevelDirection,
    SimpleLevels,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostCondition, Topic
from cmk.rulesets.v1.form_specs.validators import NumberInRange


def _parameter_form_ms_entra_sync() -> Dictionary:
    return Dictionary(
        title=Title("Check parameters"),
        help_text=Help(
            "Parameters for the last sync time thresholds from the Microsoft Entra Connect/Cloud "
            "Sync.<br>To use this service, you need to set up the <b>Microsoft Entra</b> special "
            "agent."
        ),
        elements={
            "sync_period": DictElement(
                parameter_form=SimpleLevels[float](
                    title=Title("Time since last sync"),
                    help_text=Help(
                        "Specify the upper levels for the last sync time from Microsoft Entra "
                        "Connect/Cloud Sync.<br>The default values are 1 hour (WARN) and 3 hours "
                        "(CRIT). To ignore the last sync time, select 'No levels'."
                    ),
                    form_spec_template=TimeSpan(
                        custom_validate=(NumberInRange(min_value=0),),
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                            TimeMagnitude.HOUR,
                            TimeMagnitude.MINUTE,
                        ],
                    ),
                    level_direction=LevelDirection.UPPER,
                    prefill_fixed_levels=DefaultValue(value=(3600.0, 10800.0)),
                ),
                required=True,
            ),
        },
    )


rule_spec_ms_entra_sync = CheckParameters(
    name="ms_entra_sync",
    title=Title("Microsoft Entra Connect/Cloud Sync"),
    parameter_form=_parameter_form_ms_entra_sync,
    topic=Topic.CLOUD,
    condition=HostCondition(),
)
