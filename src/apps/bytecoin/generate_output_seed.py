from trezor.messages.BytecoinGenerateOutputSeedRequest import BytecoinGenerateOutputSeedRequest
from trezor.messages.BytecoinGenerateOutputSeedResponse import BytecoinGenerateOutputSeedResponse

from apps.bytecoin import misc

async def generate_output_seed(ctx, msg: BytecoinGenerateOutputSeedRequest, keychain):
    if msg.out_index is None:
        msg.out_index = 0
    creds = misc.get_creds(keychain)
    output_seed = creds.generate_output_seed(msg.tx_inputs_hash, msg.out_index)
    return BytecoinGenerateOutputSeedResponse(output_seed=output_seed)

