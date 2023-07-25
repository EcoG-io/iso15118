from dataclasses import dataclass


@dataclass
class ExiMessageContainer:
    message_name: str
    json_str: str
    description: str = ""
