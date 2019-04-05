from trezor.messages.BytecoinExportViewWalletRequest import BytecoinExportViewWalletRequest
from trezor.messages.BytecoinExportViewWalletResponse import BytecoinExportViewWalletResponse

from apps.bytecoin import misc
from apps.bytecoin import bcncrypto

from apps.bytecoin.layout import confirms


async def export_view_wallet(ctx, msg: BytecoinExportViewWalletRequest, keychain):
    await confirms.require_confirm_watchkey(ctx)
    creds = misc.get_creds(keychain)

    view_seed = bytearray(32)
    confirmed = await confirms.confirm_tx_derivation(ctx)
    if confirmed:
        view_seed = creds.view_seed

    k = bcncrypto.random_scalar()
    sig_c = bcncrypto.hash_to_scalar(creds.sH.to_bytes() + k.scalarmult_h().to_bytes())
    sig_r = k.sub(sig_c.mul(creds.spend_secret_key))
    sig_b = sig_c.to_bytes() + sig_r.to_bytes()
    return BytecoinExportViewWalletResponse(view_secret_key=creds.view_secret_key.to_bytes(), audit_key_base_secret_key=creds.audit_key_base_secret_key.to_bytes(), view_seed=view_seed, view_secrets_signature=sig_b)
