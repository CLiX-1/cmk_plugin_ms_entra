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
from cmk.rulesets.v1.rule_specs import CheckParameters, HostAndItemCondition, Topic


def _parameter_form_ms_entra_saml_certs() -> Dictionary:
    return Dictionary(
        title=Title("Microsoft Entra SAML App Certificates"),
        help_text=Help(
            "Parameters for the expiration time thresholds from Microsoft Entra SAML app certificates. "
            "To use this service, you need to set up the <b>Microsoft Entra</b> special agent."
        ),
        elements={
            "cert_expiration": DictElement(
                parameter_form=SimpleLevels[float](
                    title=Title("Certificate expiration"),
                    help_text=Help(
                        "Specify the lower levels for the Microsoft Entra SAML app certificate expiration time. "
                        "The default values are 14 days (WARN) and 5 days (CRIT). "
                        "To ignore the certificate expiration, select 'No levels'."
                    ),
                    form_spec_template=TimeSpan(
                        displayed_magnitudes=[
                            TimeMagnitude.DAY,
                        ],
                    ),
                    level_direction=LevelDirection.LOWER,
                    prefill_fixed_levels=DefaultValue(value=(1209600.0, 432000.0)),
                ),
                required=True,
            ),
        },
    )


rule_spec_ms_entra_saml_certs = CheckParameters(
    name="ms_entra_saml_certs",
    title=Title("Microsoft Entra SAML App Certificates"),
    parameter_form=_parameter_form_ms_entra_saml_certs,
    topic=Topic.CLOUD,
    condition=HostAndItemCondition(item_title=Title("App")),
)
