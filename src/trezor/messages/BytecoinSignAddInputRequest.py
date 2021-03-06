# Automatically generated by pb2py
# fmt: off
import protobuf as p

if __debug__:
    try:
        from typing import List
    except ImportError:
        List = None  # type: ignore


class BytecoinSignAddInputRequest(p.MessageType):
    MESSAGE_WIRE_TYPE = 813

    def __init__(
        self,
        amount: int = None,
        output_indexes: List[int] = None,
        output_secret_hash_arg: bytes = None,
        address_index: int = None,
    ) -> None:
        self.amount = amount
        self.output_indexes = output_indexes if output_indexes is not None else []
        self.output_secret_hash_arg = output_secret_hash_arg
        self.address_index = address_index

    @classmethod
    def get_fields(cls):
        return {
            1: ('amount', p.UVarintType, 0),
            2: ('output_indexes', p.UVarintType, p.FLAG_REPEATED),
            3: ('output_secret_hash_arg', p.BytesType, 0),
            4: ('address_index', p.UVarintType, 0),
        }
