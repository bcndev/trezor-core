from trezor.messages.BytecoinStartProofRequest import BytecoinStartProofRequest

from apps.bytecoin.sign_start import sign_transaction_or_proof_start

async def start_proof(ctx, msg: BytecoinStartProofRequest, keychain):
    if msg.data_size is None:
        msg.data_size = 0
    return await sign_transaction_or_proof_start(ctx, None, msg, keychain)
