from trezor.messages.BytecoinStartRequest import BytecoinStartRequest
from trezor.messages.BytecoinStartResponse import BytecoinStartResponse

from apps.bytecoin import misc

async def start_request(ctx, msg: BytecoinStartRequest, keychain):

    creds = misc.get_creds(keychain)

    v_mul_A_plus_sH = creds.view_secret_key.scalarmult(creds.A_plus_sH)

    # bcncrypto.test_crypto()

    # await paths.validate_path(ctx, misc.validate_full_path, path=address_n)

    return BytecoinStartResponse(version=b"4.0", wallet_key=creds.wallet_key, A_plus_sH=creds.A_plus_sH.to_bytes(), v_mul_A_plus_sH=v_mul_A_plus_sH.to_bytes(), view_public_key=creds.view_public_key.to_bytes())
