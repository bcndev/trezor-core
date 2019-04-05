from trezor import ui, wire
from trezor.ui.text import Text
from trezor.messages import ButtonRequestType

from apps.common.confirm import confirm, require_confirm, require_hold_to_confirm
from apps.bytecoin.layout import common

async def require_confirm_watchkey(ctx):
    content = Text("Confirm export", ui.ICON_SEND, icon_color=ui.GREEN)
    content.normal("Do you really want to", "export view-only", "credentials?")
    return await require_confirm(ctx, content, ButtonRequestType.SignTx)

async def confirm_tx_derivation(ctx):
    content = Text("Confirm export", ui.ICON_SEND, icon_color=ui.GREEN)
    content.normal("Allow exported view-only wallet", "to see destination", "addresses?")
    return await confirm(ctx, content, ButtonRequestType.SignTx)

async def require_confirm_fee(ctx, fee:int):
    content = Text("Confirm fee", ui.ICON_SEND, icon_color=ui.GREEN)
    content.bold(common.format_amount(fee))
    await require_hold_to_confirm(ctx, content, ButtonRequestType.ConfirmOutput)

async def require_confirm_output(ctx, address:str, amount:int):
    text_addr = common.split_address(address)
    text_amount = common.format_amount(amount)

    if not await common.naive_pagination(
        ctx,
        [ui.BOLD, text_amount, ui.MONO] + list(text_addr),
        "Confirm send",
        ui.ICON_SEND,
        ui.GREEN,
        4,
    ):
        raise wire.ActionCancelled("Cancelled")

