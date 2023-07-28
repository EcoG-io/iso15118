import asyncio
import logging

from iso15118.secc import SECCHandler
from iso15118.secc.controller.evse_data import EVSEDataContext
from iso15118.secc.controller.interface import ServiceStatus
from iso15118.secc.controller.simulator import SimEVSEController
from iso15118.secc.secc_settings import Config
from iso15118.shared.exificient_exi_codec import ExificientEXICodec

logger = logging.getLogger(__name__)


def get_evse_context():
    return EVSEDataContext(
        evse_max_charge_power=3000,
        evse_min_charge_power=3000,
        evse_max_charge_current=3000,
        evse_min_charge_current=3000,
        evse_max_voltage=3000,
        evse_min_voltage=3000,
        evse_power_ramp_limit=10,
        # EVSE -20 AC and DC BPT
        evse_max_discharge_power=3000,
        evse_min_discharge_power=3000,
        evse_max_discharge_current=3000,
        evse_min_discharge_current=3000,
        # EVSE -20 AC
        evse_max_charge_power_l2=3000,
        evse_max_charge_power_l3=3000,
        evse_min_charge_power_l2=3000,
        evse_min_charge_power_l3=3000,
        evse_nominal_frequency=3000,
        max_power_asymmetry=3000,
        evse_present_active_power=3000,
        evse_present_active_power_l2=3000,
        evse_present_active_power_l3=3000,
        # EVSE
        evse_max_discharge_power_l2=3000,
        evse_max_discharge_power_l3=3000,
        evse_min_discharge_power_l2=3000,
        evse_min_discharge_power_l3=3000,
        # EVSE
        evse_target_active_power=10,
    )


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
