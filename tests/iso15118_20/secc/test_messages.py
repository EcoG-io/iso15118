import time

from iso15118.shared.messages.iso15118_20.common_messages import ServiceDetailReq
from iso15118.shared.messages.iso15118_20.common_types import MessageHeader
from tests.tools import MOCK_SESSION_ID


def get_v2g_message_service_detail_req(service_list: int) -> ServiceDetailReq:
    return ServiceDetailReq(
        header=MessageHeader(
            session_id=MOCK_SESSION_ID,
            timestamp=time.time(),
        ),
        service_id=service_list,
    )
