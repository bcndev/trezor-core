from trezor import wire
from trezor.messages import MessageType

from apps.common import HARDENED



def boot():
    ns = [
        ["secp256k1", HARDENED | 44, HARDENED | 0xCC],
    ]
    wire.add(MessageType.BytecoinStartRequest, __name__, "start_request", ns)
    wire.add(MessageType.BytecoinScanOutputsRequest, __name__, "scan_outputs", ns)
    wire.add(MessageType.BytecoinGenerateKeyimageRequest, __name__, "generate_keyimage", ns)
    wire.add(MessageType.BytecoinGenerateOutputSeedRequest, __name__, "generate_output_seed", ns)
    wire.add(MessageType.BytecoinExportViewWalletRequest, __name__, "export_view_wallet", ns)
    wire.add(MessageType.BytecoinSignStartRequest, __name__, "sign_start", ns)
    wire.add(MessageType.BytecoinStartProofRequest, __name__, "start_proof", ns)
