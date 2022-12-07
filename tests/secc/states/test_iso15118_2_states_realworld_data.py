import json

import pytest
from unittest.mock import Mock, patch

from iso15118.secc import Config
from iso15118.secc.states.iso15118_2_states import CurrentDemand
from iso15118.shared.exi_codec import CustomJSONDecoder
from iso15118.shared.messages.iso15118_2.msgdef import V2GMessage


@patch("iso15118.shared.states.EXI.to_exi", new=Mock(return_value=b"01"))
@pytest.mark.asyncio
class TestIso15118_2_StatesRealworldData:

    @pytest.fixture(autouse=True)
    def _comm_session(self, comm_secc_session_mock):
        self.comm_session = comm_secc_session_mock
        self.comm_session.config = Config()
        self.comm_session.is_tls = False
        self.comm_session.writer = Mock()
        self.comm_session.writer.get_extra_info = Mock()

    async def test_current_demand_state_data_extraction(self):
        json_str = '{"V2G_Message": {"Header": {"SessionID": "AC1DECE39DBE831A"},' \
                   '"Body": {"CurrentDemandReq": {"DC_EVStatus":{"EVReady":' \
                   'true,"EVErrorCode":"NO_ERROR","EVRESSSOC":76},"EVTargetCurrent":' \
                   '{"Multiplier":-1,"Unit":"A","Value":0},"EVMaximumVoltageLimit":' \
                   '{"Multiplier":-1,"Unit":"V","Value":8490},"EVMaximumCurrentLimit":' \
                   '{"Multiplier":-1,"Unit":"A","Value":4000},"BulkChargingComplete":' \
                   'false,"ChargingComplete":false,"RemainingTimeToFullSoC":' \
                   '{"Multiplier":0,"Unit":"s","Value":10680},"EVTargetVoltage":' \
                   '{"Multiplier":-1,"Unit":"V","Value":8390}}}}}'
        decoded_dict = json.loads(json_str, cls=CustomJSONDecoder)
        parsed_message = V2GMessage.parse_obj(decoded_dict["V2G_Message"])
        self.comm_session.session_id = decoded_dict["V2G_Message"]["Header"]["SessionID"]

        current_demand = CurrentDemand(self.comm_session)
        await current_demand.process_message(message=parsed_message)

        assert self.comm_session.evse_controller.ev_data_context.remaining_time_to_full_soc_s == 10680
