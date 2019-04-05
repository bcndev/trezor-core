from trezor.messages.BytecoinScanOutputsRequest import BytecoinScanOutputsRequest
from trezor.messages.BytecoinScanOutputsResponse import BytecoinScanOutputsResponse

from apps.bytecoin import misc
from apps.bytecoin import bcncrypto

async def scan_outputs(ctx, msg: BytecoinScanOutputsRequest, keychain):
    key_seed, view_seed, view_secret_key = misc.get_basic_secrets(keychain)

    pvs = [view_secret_key.scalarmult(bcncrypto.BcnPoint(pk)).to_bytes() for pk in msg.output_public_key]
    return BytecoinScanOutputsResponse(Pv=pvs)
