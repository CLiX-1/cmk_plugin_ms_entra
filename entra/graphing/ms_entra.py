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
# CHECKMK METRICS & GRAPHS: Microsoft Entra
#
# This file defines the Checkmk metrics and graphs for the check plug-ins.
# It is part of the Microsoft Entra special agent (ms_entra).
####################################################################################################

from cmk.graphing.v1 import Title
from cmk.graphing.v1.metrics import (
    Color,
    Unit,
    Metric,
    TimeNotation,
)
from cmk.graphing.v1.perfometers import Closed, FocusRange, Open, Perfometer

UNIT_TIME = Unit(TimeNotation())

# --------------------------------------------------------------------------------------------------
# Microsoft Entra App Credentials
# --------------------------------------------------------------------------------------------------

metric_ms_entra_app_creds_remaining_validity = Metric(
    name="ms_entra_app_creds_remaining_validity",
    title=Title("Remaining credential validity time"),
    unit=UNIT_TIME,
    color=Color.YELLOW,
)

perfometer_ms_entra_app_creds_remaining_validity = Perfometer(
    name="ms_entra_app_creds_remaining_validity",
    focus_range=FocusRange(Closed(0), Open(15552000)),
    segments=["ms_entra_app_creds_remaining_validity"],
)

# --------------------------------------------------------------------------------------------------
# Microsoft Entra CA VPN Certificate
# --------------------------------------------------------------------------------------------------

metric_ms_entra_ca_vpn_cert_remaining_validity = Metric(
    name="ms_entra_ca_vpn_cert_remaining_validity",
    title=Title("Remaining CA VPN cert validity time"),
    unit=UNIT_TIME,
    color=Color.YELLOW,
)

perfometer_ms_entra_ca_vpn_cert_remaining_validity = Perfometer(
    name="ms_entra_ca_vpn_cert_remaining_validity",
    focus_range=FocusRange(Closed(0), Open(15552000)),
    segments=["ms_entra_ca_vpn_cert_remaining_validity"],
)

# --------------------------------------------------------------------------------------------------
# Microsoft Entra SAML Certificate
# --------------------------------------------------------------------------------------------------
metric_ms_entra_saml_certs_remaining_validity = Metric(
    name="ms_entra_saml_certs_remaining_validity",
    title=Title("Remaining SAML cert validity time"),
    unit=UNIT_TIME,
    color=Color.YELLOW,
)

perfometer_ms_entra_saml_certs_remaining_validity = Perfometer(
    name="ms_entra_saml_certs_remaining_validity",
    focus_range=FocusRange(Closed(0), Open(15552000)),
    segments=["ms_entra_saml_certs_remaining_validity"],
)

# --------------------------------------------------------------------------------------------------
# # Microsoft Entra Sync
# --------------------------------------------------------------------------------------------------

metric_ms_entra_sync_elapsed_time = Metric(
    name="ms_entra_sync_elapsed_time",
    title=Title("Elapsed time since last sync"),
    unit=UNIT_TIME,
    color=Color.DARK_YELLOW,
)

perfometer_ms_entra_sync_elapsed_time = Perfometer(
    name="ms_entra_sync_elapsed_time",
    focus_range=FocusRange(Closed(0), Open(3600)),
    segments=["ms_entra_sync_elapsed_time"],
)
