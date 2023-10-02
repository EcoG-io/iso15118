import asyncio
import logging

from iso15118.secc import SECCHandler
from iso15118.secc.controller.evse_data import (
    ACBPTLimits,
    ACCLLimits,
    ACLimits,
    DCBPTLimits,
    DCCLLimits,
    DCLimits,
    EVSEDataContext,
    EVSERatedLimits,
    EVSESessionContext,
)
from iso15118.secc.controller.interface import ServiceStatus
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.secc_settings import Config
from iso15118.shared.exificient_exi_codec import ExificientEXICodec

logger = logging.getLogger(__name__)


def get_evse_context():
    ac_limits = ACLimits(
        # 15118-2 AC CPD
        evse_nominal_voltage=10,
        evse_max_current=10,
        evse_max_charge_power=10,
        evse_min_charge_power=10,
        evse_max_charge_power_l2=10,
        evse_max_charge_power_l3=10,
        evse_min_charge_power_l2=10,
        evse_min_charge_power_l3=10,
        evse_nominal_frequency=10,
        max_power_asymmetry=10,
        evse_power_ramp_limit=10,
        evse_present_active_power=10,
        evse_present_active_power_l2=10,
        evse_present_active_power_l3=10,
    )
    ac_bpt_limits = ACBPTLimits(
        evse_max_discharge_power=10,
        evse_min_discharge_power=10,
        evse_max_discharge_power_l2=10,
        evse_max_discharge_power_l3=10,
        evse_min_discharge_power_l2=10,
        evse_min_discharge_power_l3=10,
    )
    dc_limits = DCLimits(
        evse_max_charge_power=10,
        evse_min_charge_power=10,
        evse_max_charge_current=10,
        evse_min_charge_current=10,
        evse_max_voltage=10,
        evse_min_voltage=10,
        evse_power_ramp_limit=10,
        # 15118-2 DC, DINSPEC
        evse_current_regulation_tolerance=10,
        evse_peak_current_ripple=10,
        evse_energy_to_be_delivered=10,
        evse_maximum_current_limit=10,
        evse_maximum_power_limit=10,
        evse_maximum_voltage_limit=10,
        evse_minimum_current_limit=10,
        evse_minimum_voltage_limit=10,
    )
    dc_bpt_limits = DCBPTLimits(
        # 15118-20 DC BPT
        evse_max_discharge_power=10,
        evse_min_discharge_power=10,
        evse_max_discharge_current=10,
        evse_min_discharge_current=10,
    )
    ac_cl_limits = ACCLLimits(
        evse_target_active_power=10,
        evse_target_active_power_l2=10,
        evse_target_active_power_l3=10,
        evse_target_reactive_power=10,
        evse_target_reactive_power_l2=10,
        evse_target_reactive_power_l3=10,
        evse_present_active_power=10,
        evse_present_active_power_l2=10,
        evse_present_active_power_l3=10,
    )
    dc_cl_limits = DCCLLimits(
        # Optional in 15118-20 DC CL (Scheduled)
        evse_max_charge_power=10,
        evse_min_charge_power=10,
        evse_max_charge_current=10,
        evse_max_voltage=10,
        # Optional and present in 15118-20 DC BPT CL (Scheduled)
        evse_max_discharge_power=10,
        evse_min_discharge_power=10,
        evse_max_discharge_current=10,
        evse_min_voltage=10,
    )
    rated_limits: EVSERatedLimits = EVSERatedLimits(
        ac_limits=ac_limits,
        ac_bpt_limits=ac_bpt_limits,
        dc_limits=dc_limits,
        dc_bpt_limits=dc_bpt_limits,
    )

    session_context: EVSESessionContext = EVSESessionContext(
        evse_present_voltage=1,
        evse_present_current=1,
        ac_limits=ac_cl_limits,
        dc_limits=dc_cl_limits,
    )

    return EVSEDataContext(rated_limits=rated_limits, session_context=session_context)


async def main():
    """
    Entrypoint function that starts the ISO 15118 code running on
    the SECC (Supply Equipment Communication Controller)
    """
    config = Config()
    config.load_envs()
    config.log_settings()

    sim_evse_controller = await SimEVSEController.create()
    sim_evse_controller.set_evse_data_context(get_evse_context())
    await sim_evse_controller.set_status(ServiceStatus.STARTING)
    await SECCHandler(
        exi_codec=ExificientEXICodec(),
        evse_controller=sim_evse_controller,
        config=config,
    ).start(config.iface)


def run():
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.debug("SECC program terminated manually")


if __name__ == "__main__":
    run()
