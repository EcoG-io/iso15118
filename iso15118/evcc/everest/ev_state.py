# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 - 2023 Pionix GmbH and Contributors to EVerest
from dataclasses import dataclass, field

@dataclass
class EVState:
    # Common
    PaymentOption: str = ''
    EnergyTransferMode: str = ''
    StopCharging = False

    def reset(self):
        self.StopCharging = False