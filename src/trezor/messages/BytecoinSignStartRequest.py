# Automatically generated by pb2py
# fmt: off
import protobuf as p


class BytecoinSignStartRequest(p.MessageType):
    MESSAGE_WIRE_TYPE = 811

    def __init__(
        self,
        version: int = None,
        ut: int = None,
        inputs_size: int = None,
        outputs_size: int = None,
        extra_size: int = None,
    ) -> None:
        self.version = version
        self.ut = ut
        self.inputs_size = inputs_size
        self.outputs_size = outputs_size
        self.extra_size = extra_size

    @classmethod
    def get_fields(cls):
        return {
            1: ('version', p.UVarintType, 0),
            2: ('ut', p.UVarintType, 0),
            3: ('inputs_size', p.UVarintType, 0),
            4: ('outputs_size', p.UVarintType, 0),
            5: ('extra_size', p.UVarintType, 0),
        }
