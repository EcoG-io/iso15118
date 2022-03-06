from abc import ABCMeta, abstractmethod


class IEXICodec(metaclass=ABCMeta):
    @abstractmethod
    def encode(self, message: str, namespace: str) -> bytes:
        """
        Encodes passed message to EXI
        Message: Message payload to be encoded.
        Namespace: String indicating the schema to be used while encoding
        """
        raise NotImplementedError

    @abstractmethod
    def decode(self, stream: bytes, namespace: str) -> str:
        """
        Decodes EXI stream to message payload
        Stream: EXI bytes stream
        Namespace: String indicating the schema to be used while decoding
        """
        raise NotImplementedError

    @abstractmethod
    def get_version(self) -> str:
        pass
