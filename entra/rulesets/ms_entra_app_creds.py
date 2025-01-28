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
# Checkmk ruleset to set the expiration time thresholds for Microsoft Entra app registration
# credentials or/and exclude specific credentials. This ruleset is part of the Microsoft Entra
# special agent (ms_entra).


from cmk.rulesets.v1 import Help, Title
from cmk.rulesets.v1.form_specs import (
    DefaultValue,
    DictElement,
    Dictionary,
    LevelDirection,
    List,
    MatchingScope,
    RegularExpression,
    SimpleLevels,
    TimeMagnitude,
    TimeSpan,
)
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic
from cmk.rulesets.v1.form_specs.validators import LengthInRange


def _parameter_form_ms_entra_app_creds() -> Dictionary:
    return Dictionary(
        title=Title("Microsoft Entra App Credentials"),
        help_text=Help(
            "Parameters for Microsoft Entra app registration credentials like secrets and "
            "certificates.<br>To use this service, you need to set up the <b>Microsoft Entra</b> "
            "special agent."
        ),
        elements={
            "cred_expiration": DictElement(
                parameter_form=SimpleLevels[float](
                    title=Title("Credential expiration"),
                    help_text=Help(
                        "Specify the lower levels for the Microsoft Entra app credential "
                        "expiration time.<br>The default values are 14 days (WARN) and 5 days "
                        "(CRIT).<br>To ignore the credential expiration, select 'No levels'."
                    ),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                        ],
                    ),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=DefaultValue(value=(1209600.0, 432000.0)),
                ),
            ),
            "cred_exclude": DictElement(
                parameter_form=List[str](
                    title=Title("Exclude credentials"),
                    help_text=Help(
                        "Specify a list of credential descriptions that you do not want to monitor."
                        '<br>For example, "CWAP_AuthSecret$" to ignore Microsoft Entra Application '
                        'Proxy secrets or "CN=service.prod.powerva.microsoft.com$" to ignore '
                        "Microsoft Power Virtual Agents certificates. Keep in mind that Microsoft "
                        "can change these descriptions over time.<br><br>"
                    ),
                    element_template=RegularExpression(
                        title=Title("Credential description"),
                        predefined_help_text=MatchingScope.PREFIX,
                        custom_validate=(LengthInRange(min_value=1),),
                    ),
                    editable_order=False,
                ),
            ),
        },
    )


rule_spec_ms_entra_app_creds = CheckParameters(
    name="ms_entra_app_creds",
    title=Title("Microsoft Entra App Credentials"),
    parameter_form=_parameter_form_ms_entra_app_creds,
    topic=Topic.CLOUD,
    condition=HostAndItemCondition(item_title=Title("App")),
)
