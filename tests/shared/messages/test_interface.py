import pytest

from iso15118.secc.controller.evse_data import (
    CurrentType,
    EVSEACCLLimits,
    EVSEDataContext,
    EVSEDCCLLimits,
    EVSESessionLimits,
)
from iso15118.secc.controller.interface import EVSEControllerInterface
from iso15118.shared.messages.datatypes import (
    PVEVSEMaxCurrent,
    PVEVSEMaxCurrentLimit,
    PVEVSEMaxVoltageLimit,
    UnitSymbol,
)


class DummyEVSEControllerInterface(EVSEControllerInterface):
    def __init__(self, evse_data_context):
        EVSEControllerInterface.__init__(self)
        self.evse_data_context = evse_data_context

    async def set_status(self, _):
        pass

    async def get_evse_id(self, _):
        pass

    async def get_supported_energy_transfer_modes(self, _):
        pass

    async def get_schedule_exchange_params(self, _):
        pass

    async def get_energy_service_list(self):
        pass

    def is_eim_authorized(self):
        pass

    async def is_authorized(self, _):
        pass

    async def get_sa_schedule_list(self):
        pass

    async def get_sa_schedule_list_dinspec(self, _):
        pass

    async def get_meter_info_v2(self):
        pass

    async def get_meter_info_v20(self):
        pass

    async def get_supported_providers(self):
        pass

    async def set_hlc_charging(self, _):
        pass

    async def get_cp_state(self):
        pass

    async def service_renegotiation_supported(self):
        pass

    async def get_service_parameter_list(self, _):
        pass

    async def stop_charger(self):
        pass

    async def is_contactor_opened(self):
        pass

    async def is_contactor_closed(self):
        pass

    async def get_evse_status(self):
        pass

    async def set_present_protocol_state(self, _):
        pass

    # ============================================================================
    # |                          AC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_ac_evse_status(self):
        pass

    async def get_ac_charge_params_v2(self):
        pass

    async def get_ac_charge_params_v20(self, _):
        pass

    # ============================================================================
    # |                          DC-SPECIFIC FUNCTIONS                           |
    # ============================================================================

    async def get_dc_evse_status(self):
        pass

    async def get_dc_charge_parameters(self):
        pass

    async def start_cable_check(self):
        pass

    async def get_cable_check_status(self):
        pass

    async def send_charging_command(self, _):
        pass

    async def is_evse_current_limit_achieved(self):
        pass

    async def is_evse_voltage_limit_achieved(self):
        pass

    async def is_evse_power_limit_achieved(self) -> bool:
        return False

    async def get_dc_charge_params_v20(self, _):
        pass

    def get_15118_ev_certificate(self, *args, **kwargs):
        pass

    async def update_data_link(self, _):
        pass

    def ready_to_charge(self):
        pass

    async def session_ended(self, _):
        pass

    async def send_display_params(self):
        pass

    async def send_rated_limits(self):
        pass


@pytest.fixture
def evse_controller_interface():
    session_limits = EVSESessionLimits(
        ac_limits=EVSEACCLLimits(max_charge_power=23000),
        dc_limits=EVSEDCCLLimits(max_charge_current=200),
    )
    evse_data_context = EVSEDataContext(
        session_limits=session_limits,
        present_voltage=230,
        nominal_voltage=230,
    )
    return DummyEVSEControllerInterface(evse_data_context)


@pytest.mark.asyncio
class TestEVSEControllerInterface:
    async def test_get_evse_max_current_limit_ac(self, evse_controller_interface):
        evse_controller_interface.evse_data_context.current_type = CurrentType.AC
        expected_limit = PVEVSEMaxCurrent(
            multiplier=0,
            value=100,
            unit=UnitSymbol.AMPERE,
        )
        limit = await evse_controller_interface.get_evse_max_current_limit()
        assert isinstance(limit, PVEVSEMaxCurrent)
        assert limit == expected_limit

    async def test_get_evse_max_current_limit_dc(self, evse_controller_interface):
        evse_controller_interface.evse_data_context.current_type = CurrentType.DC
        expected_limit = PVEVSEMaxCurrentLimit(
            multiplier=0,
            value=200,
            unit=UnitSymbol.AMPERE,
        )
        limit = await evse_controller_interface.get_evse_max_current_limit()
        assert isinstance(limit, PVEVSEMaxCurrentLimit)
        assert limit == expected_limit

    async def test_get_evse_present_voltage_is_0(self, evse_controller_interface):
        evse_controller_interface.evse_data_context.current_type = CurrentType.AC
        evse_controller_interface.evse_data_context.present_voltage = 0
        evse_controller_interface.evse_data_context.nominal_voltage = 230
        expected_limit = PVEVSEMaxCurrent(
            multiplier=0,
            value=100,
            unit=UnitSymbol.AMPERE,
        )
        limit = await evse_controller_interface.get_evse_max_current_limit()
        assert isinstance(limit, PVEVSEMaxCurrent)
        assert limit == expected_limit

    async def test_get_evse_present_and_nominal_voltage_are_0(
        self, evse_controller_interface
    ):
        """Test that max current is calculated correctly
        when present and nominal voltage are 0."""
        evse_controller_interface.evse_data_context.current_type = CurrentType.AC
        evse_controller_interface.evse_data_context.present_voltage = 0
        evse_controller_interface.evse_data_context.nominal_voltage = 0
        expected_limit = PVEVSEMaxCurrent(
            multiplier=0,
            value=100,
            unit=UnitSymbol.AMPERE,
        )
        limit = await evse_controller_interface.get_evse_max_current_limit()
        assert isinstance(limit, PVEVSEMaxCurrent)
        assert limit == expected_limit

    async def test_get_evse_max_voltage_limit_ac(self, evse_controller_interface):
        evse_controller_interface.evse_data_context.current_type = CurrentType.AC
        evse_controller_interface.evse_data_context.nominal_voltage = 230
        expected_limit = PVEVSEMaxVoltageLimit(
            multiplier=0,
            value=230,
            unit=UnitSymbol.VOLTAGE,
        )
        limit = await evse_controller_interface.get_evse_max_voltage_limit()
        assert isinstance(limit, PVEVSEMaxVoltageLimit)
        assert limit == expected_limit

    async def test_get_evse_max_voltage_limit_dc(self, evse_controller_interface):
        evse_controller_interface.evse_data_context.current_type = CurrentType.DC
        evse_controller_interface.evse_data_context.session_limits.dc_limits.max_voltage = (  # noqa: E501
            1000
        )
        expected_limit = PVEVSEMaxVoltageLimit(
            multiplier=0,
            value=1000,
            unit=UnitSymbol.VOLTAGE,
        )
        limit = await evse_controller_interface.get_evse_max_voltage_limit()
        assert isinstance(limit, PVEVSEMaxVoltageLimit)
        assert limit == expected_limit
