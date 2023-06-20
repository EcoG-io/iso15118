# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 - 2023 Pionix GmbH and Contributors to EVerest
from typing import Callable

from .ev_state import EVState

PublisherCallback = Callable[[str, any], None]

class Context:
    def __init__(self):
        self._es = EVState()
        self._pub_callback: PublisherCallback = None

    def set_publish_callback(self, callback: PublisherCallback):
        self._pub_callback = callback

    def publish(self, variable_name: str, value: any):
        self._pub_callback(variable_name, value)

    @property
    def ev_state(self) -> EVState:
        return self._es
