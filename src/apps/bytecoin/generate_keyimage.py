from trezor.messages.BytecoinGenerateKeyimageRequest import BytecoinGenerateKeyimageRequest
from trezor.messages.BytecoinGenerateKeyimageResponse import BytecoinGenerateKeyimageResponse

from apps.bytecoin import misc

async def generate_keyimage(ctx, msg: BytecoinGenerateKeyimageRequest, keychain):
    if msg.address_index is None:
        msg.address_index = 0

    creds = misc.get_creds(keychain)

    inv_output_secret_hash = misc.invert_arg_to_inv_hash(msg.output_secret_hash_arg)

    address_audit_secret_key = creds.generate_address_secret_key(msg.address_index)

    output_secret_key_a = inv_output_secret_hash.mul(address_audit_secret_key)
    output_secret_key_s = inv_output_secret_hash.mul(creds.spend_secret_key)
    output_public_key = misc.secret_keys_to_public_key(output_secret_key_a, output_secret_key_s)

    keyimage_b = misc.generate_key_image_b(output_public_key, output_secret_key_a)
    return BytecoinGenerateKeyimageResponse(keyimage=keyimage_b)
