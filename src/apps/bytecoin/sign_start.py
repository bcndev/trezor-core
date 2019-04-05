from trezor.messages import MessageType
from trezor.messages.BytecoinSignStartRequest import BytecoinSignStartRequest
from trezor.messages.BytecoinStartProofRequest import BytecoinStartProofRequest
from trezor.messages.BytecoinEmptyResponse import BytecoinEmptyResponse

from trezor.messages.BytecoinSignAddInputRequest import BytecoinSignAddInputRequest
from trezor.messages.BytecoinSignAddOutputRequest import BytecoinSignAddOutputRequest
from trezor.messages.BytecoinSignAddOutputResponse import BytecoinSignAddOutputResponse
from trezor.messages.BytecoinSignAddExtraRequest import BytecoinSignAddExtraRequest
from trezor.messages.BytecoinSignStepARequest import BytecoinSignStepARequest
from trezor.messages.BytecoinSignStepAResponse import BytecoinSignStepAResponse
from trezor.messages.BytecoinSignStepAMoreDataRequest import BytecoinSignStepAMoreDataRequest
from trezor.messages.BytecoinSignGetC0Request import BytecoinSignGetC0Request
from trezor.messages.BytecoinSignGetC0Response import BytecoinSignGetC0Response
from trezor.messages.BytecoinSignStepBRequest import BytecoinSignStepBRequest
from trezor.messages.BytecoinSignStepBResponse import BytecoinSignStepBResponse

import gc

from apps.bytecoin.layout import confirms
from trezor.crypto import random
from trezor import wire

from apps.bytecoin import misc
from apps.bytecoin import bcncrypto

class State:
    FINISHED = 0
    EXPECT_ADD_INPUT = 1
    EXPECT_ADD_OUTPUT = 2
    EXPECT_ADD_EXTRA_CHUNK = 3
    EXPECT_STEP_A = 4
    EXPECT_STEP_A_MORE_DATA = 5
    EXPECT_STEP_B = 6
    EXPECT_PROOF_CHUNK = 7

class SignState:
    def __init__(self, creds: misc.AccountCreds):
        self.state = State.FINISHED
        self.creds = creds
        self.inputs_size = 0
        self.outputs_size = 0
        self.extra_size = 0
        self.dst_amounts = {}
        self.inputs_counter = 0
        self.outputs_counter = 0
        self.extra_counter = 0
        self.random_seed = random.bytes(32) # bcncrypto.cn_fast_hash(b"bcn") #
        self.tx_inputs_stream = bcncrypto.get_keccak()
        self.tx_inputs_hash = None
        self.tx_prefix_stream = bcncrypto.get_keccak()
        self.inputs_amount = 0
        self.dst_amount = 0
        self.change_amount = 0
        self.c0 = None
        self.encryption_key = random.bytes(32) # bcncrypto.cn_fast_hash(b"bcn") #
        self.step_args_hash = None
        self.change_amount = 0
    def generate_sign_secret(self, input_index:int, suffix:bytes):
        add = bcncrypto.get_varint_data(input_index)
        sec = bcncrypto.hash_to_scalar64(self.random_seed + self.creds.spend_secret_key.to_bytes() + suffix + add)
        return sec
    def encrypt_result(self, input:bytes, input_index:int, suffix:bytes):
        add = bcncrypto.get_varint_data(input_index)
        k = bcncrypto.cn_fast_hash(self.encryption_key + suffix + add)
        enc = bytes(a ^ b for a, b in zip(k, input))
        return enc

async def sign_start(ctx, msg:BytecoinSignStartRequest, keychain):
    if msg.version is None:
        msg.version = 0
    if msg.ut is None:
        msg.ut = 0
    if msg.inputs_size is None:
        msg.inputs_size = 0
    if msg.outputs_size is None:
        msg.outputs_size = 0
    if msg.extra_size is None:
        msg.extra_size = 0
    return await sign_transaction_or_proof_start(ctx, msg, None, keychain)

async def sign_transaction_or_proof_start(ctx, msg_tx: BytecoinSignStartRequest, msg_proof: BytecoinStartProofRequest, keychain):
    creds = misc.get_creds(keychain)
    state = SignState(creds)
    if msg_tx is not None:
        if msg_tx.inputs_size == 0:
            raise wire.DataError("Invalid number of inputs")
        if msg_tx.outputs_size == 0:
            raise wire.DataError("Invalid number of outputs")
        state.state = State.EXPECT_ADD_INPUT
        state.inputs_size = msg_tx.inputs_size
        state.outputs_size = msg_tx.outputs_size
        state.extra_size = msg_tx.extra_size
        state.tx_prefix_stream.update(bcncrypto.get_varint_data(msg_tx.version))
        state.tx_prefix_stream.update(bcncrypto.get_varint_data(msg_tx.ut))
        state.tx_prefix_stream.update(bcncrypto.get_varint_data(msg_tx.inputs_size))
        state.tx_inputs_stream.update(bcncrypto.get_varint_data(msg_tx.inputs_size))
    else:
        state.state = State.EXPECT_ADD_EXTRA_CHUNK
        state.inputs_size = 1
        state.extra_size = msg_proof.data_size
        state.tx_prefix_stream.update(b'\x00')

    res = BytecoinEmptyResponse()
    while True:
        msg = await ctx.call(
            res,
            MessageType.BytecoinSignAddInputRequest,
            MessageType.BytecoinSignAddOutputRequest,
            MessageType.BytecoinSignAddExtraRequest,
            MessageType.BytecoinSignStepARequest,
            MessageType.BytecoinSignStepAMoreDataRequest,
            MessageType.BytecoinSignGetC0Request,
            MessageType.BytecoinSignStepBRequest,
        )
        del res
        if msg.MESSAGE_WIRE_TYPE == MessageType.BytecoinSignAddInputRequest:
            res = await _sign_add_input(state, ctx, msg)
        elif msg.MESSAGE_WIRE_TYPE == MessageType.BytecoinSignAddOutputRequest:
            res = await _sign_add_output(state, ctx, msg)
        elif msg.MESSAGE_WIRE_TYPE == MessageType.BytecoinSignAddExtraRequest:
            res = await _sign_add_extra_chunkt(state, ctx, msg)
        elif msg.MESSAGE_WIRE_TYPE == MessageType.BytecoinSignStepARequest:
            res = await _sign_step_a(state, ctx, msg)
        elif msg.MESSAGE_WIRE_TYPE == MessageType.BytecoinSignStepAMoreDataRequest:
            res = await _sign_step_a_more_data(state, ctx, msg)
        elif msg.MESSAGE_WIRE_TYPE == MessageType.BytecoinSignGetC0Request:
            res = await _sign_get_c0(state, ctx, msg)
        elif msg.MESSAGE_WIRE_TYPE == MessageType.BytecoinSignStepBRequest:
            res = await _sign_step_b(state, ctx, msg)
        else:
            raise wire.DataError("Invalid message")
        if state.state == State.FINISHED:
            break
        gc.collect()
    return res

async def _sign_add_input(state, ctx, msg: BytecoinSignAddInputRequest):
    if msg.address_index is None:
        msg.address_index = 0
    if msg.amount is None:
        msg.amount = 0
    if state.state != State.EXPECT_ADD_INPUT or state.inputs_counter >= state.inputs_size:
        raise wire.DataError("Unexpected add_input")
    state.inputs_amount = misc.add_amount(state.inputs_amount, msg.amount)
    state.tx_prefix_stream.update(b'\x02') # cn::InputKey::type_tag
    state.tx_inputs_stream.update(b'\x02') # cn::InputKey::type_tag
    state.tx_prefix_stream.update(bcncrypto.get_varint_data(msg.amount))
    state.tx_inputs_stream.update(bcncrypto.get_varint_data(msg.amount))
    state.tx_prefix_stream.update(bcncrypto.get_varint_data(len(msg.output_indexes)))
    state.tx_inputs_stream.update(bcncrypto.get_varint_data(len(msg.output_indexes)))
    for index in msg.output_indexes:
        state.tx_prefix_stream.update(bcncrypto.get_varint_data(index))
        state.tx_inputs_stream.update(bcncrypto.get_varint_data(index))
    address_audit_secret_key = state.creds.generate_address_secret_key(msg.address_index)
    inv_output_secret_hash = misc.invert_arg_to_inv_hash(msg.output_secret_hash_arg)
    output_secret_key_a = inv_output_secret_hash.mul(address_audit_secret_key)
    output_secret_key_s = inv_output_secret_hash.mul(state.creds.spend_secret_key)
    output_public_key = misc.secret_keys_to_public_key(output_secret_key_a, output_secret_key_s)
    keyimage_b = misc.generate_key_image_b(output_public_key, output_secret_key_a)
    state.tx_prefix_stream.update(keyimage_b)
    state.tx_inputs_stream.update(keyimage_b)

    state.inputs_counter += 1
    if state.inputs_counter >= state.inputs_size:
        state.state = State.EXPECT_ADD_OUTPUT
        state.tx_inputs_hash = state.tx_inputs_stream.digest()
        state.tx_prefix_stream.update(bcncrypto.get_varint_data(state.outputs_size))
    return BytecoinEmptyResponse()

async def _sign_add_output_or_change(state, ctx, amount: int, tag:int, S:bcncrypto.BcnPoint, Sv:bcncrypto.BcnPoint):
    output_seed = state.creds.generate_output_seed(state.tx_inputs_hash, state.outputs_counter)
    sca, poi, at = misc.generate_output_secrets(output_seed)
    output_public_key = None
    encrypted_secret = None
    if tag == 0:
        output_public_key, encrypted_secret = misc.linkable_derive_output_public_key(sca, state.tx_inputs_hash, state.outputs_counter, S, Sv)
    elif tag == 1:
        output_public_key, encrypted_secret = misc.unlinkable_derive_output_public_key(poi, state.tx_inputs_hash, state.outputs_counter, S, Sv)
    else:
        raise wire.DataError("Unknonw address type")
    print("ga7")
    encrypted_address_type = tag ^ at
    output_public_key_b = output_public_key.to_bytes()
    encrypted_secret_b = encrypted_secret.to_bytes()

    state.tx_prefix_stream.update(b'\x02') # cn::OutputKey::type_tag
    state.tx_prefix_stream.update(bcncrypto.get_varint_data(amount))
    state.tx_prefix_stream.update(output_public_key_b)
    state.tx_prefix_stream.update(encrypted_secret_b)
    add = bytes([encrypted_address_type])
    state.tx_prefix_stream.update(add)

    state.outputs_counter += 1
    if state.outputs_counter >= state.outputs_size:
        outputs_amount = state.dst_amount
        outputs_amount = misc.add_amount(outputs_amount, state.change_amount)
        if outputs_amount > state.inputs_amount:
            raise wire.DataError("Outputs amount > inputs amount")
        fee = state.inputs_amount - outputs_amount
        for key, value in state.dst_amounts.items():
            await confirms.require_confirm_output(ctx, key, value)
        await confirms.require_confirm_fee(ctx, fee)
        state.state = State.EXPECT_ADD_EXTRA_CHUNK
        state.tx_prefix_stream.update(bcncrypto.get_varint_data(state.extra_size))

    return BytecoinSignAddOutputResponse(public_key=output_public_key_b, encrypted_secret=encrypted_secret_b, encrypted_address_type=encrypted_address_type)

async def _sign_add_output(state, ctx, msg: BytecoinSignAddOutputRequest):
    if msg.amount is None:
        msg.amount = 0
    if msg.dst_address_tag is None:
        msg.dst_address_tag = 0
    if msg.change_address_index is None:
        msg.change_address_index = 0
    if state.state != State.EXPECT_ADD_OUTPUT or state.outputs_counter >= state.outputs_size:
        raise wire.DataError("Unexpected add_output")
    if msg.change:
        state.change_amount = misc.add_amount(state.change_amount, msg.amount)
        _, change_address_S, change_address_Sv = state.creds.generate_address(msg.change_address_index)
        return await _sign_add_output_or_change(state, ctx, msg.amount, 1, change_address_S, change_address_Sv)
    state.dst_amount = misc.add_amount(state.dst_amount, msg.amount)
    dst_address_S = bcncrypto.BcnPoint(msg.dst_address_S)
    dst_address_Sv = bcncrypto.BcnPoint(msg.dst_address_Sv)
    str = misc.encode_address(msg.dst_address_tag, dst_address_S, dst_address_Sv)
    if not str in state.dst_amounts:
        state.dst_amounts[str] = 0
    state.dst_amounts[str] = misc.add_amount(state.dst_amounts[str], msg.amount)
    return await _sign_add_output_or_change(state, ctx, msg.amount, msg.dst_address_tag, dst_address_S, dst_address_Sv)

async def _sign_add_extra_chunkt(state, ctx, msg: BytecoinSignAddExtraRequest):
    if msg.extra_chunk is None:
        msg.extra_chunk = bytes()
    if state.state != State.EXPECT_ADD_EXTRA_CHUNK or state.extra_counter + len(msg.extra_chunk) > state.extra_size:
        raise wire.DataError("Unexpected extra chunk")
    state.tx_prefix_stream.update(msg.extra_chunk)
    state.extra_counter += len(msg.extra_chunk)
    if state.extra_counter >= state.extra_size:
        state.state = State.EXPECT_STEP_A
        tx_prefix_hash = state.tx_prefix_stream.digest()
        state.tx_prefix_stream = bcncrypto.get_keccak()
        state.inputs_counter = 0
        state.tx_inputs_stream = bcncrypto.get_keccak()
        state.tx_inputs_stream.update(tx_prefix_hash)

    return BytecoinEmptyResponse()

async def _sign_step_a(state, ctx, msg: BytecoinSignStepARequest):
    if msg.address_index is None:
        msg.address_index = 0
    if state.state == State.EXPECT_STEP_A_MORE_DATA and state.inputs_counter + 1 < state.inputs_size:
        state.inputs_counter += 1
        state.state = State.EXPECT_STEP_A

    if state.state != State.EXPECT_STEP_A or state.inputs_counter >= state.inputs_size:
        raise wire.DataError("Unexpected sign step a")
    state.tx_prefix_stream.update(msg.output_secret_hash_arg)
    state.tx_prefix_stream.update(bcncrypto.get_varint_data(msg.address_index))

    address_audit_secret_key = state.creds.generate_address_secret_key(msg.address_index)
    inv_output_secret_hash = misc.invert_arg_to_inv_hash(msg.output_secret_hash_arg)
    output_secret_key_a = inv_output_secret_hash.mul(address_audit_secret_key)
    output_secret_key_s = inv_output_secret_hash.mul(state.creds.spend_secret_key)
    output_public_key = misc.secret_keys_to_public_key(output_secret_key_a, output_secret_key_s)
    keyimage_b = misc.generate_key_image_b(output_public_key, output_secret_key_a)
    b_coin = bcncrypto.hash_to_ec(keyimage_b)
    hash_my_pub = bcncrypto.hash_to_ec(output_public_key.to_bytes())
    sig_p = output_secret_key_s.scalarmult_h().sub(output_secret_key_a.scalarmult(b_coin))
    state.tx_inputs_stream.update(sig_p.to_bytes())

    kr = state.generate_sign_secret(state.inputs_counter, b"kr")
    ks = state.generate_sign_secret(state.inputs_counter, b"ks")
    ka = state.generate_sign_secret(state.inputs_counter, b"ka")
    x = ks.scalarmult_h().add(ka.scalarmult(b_coin))
    state.tx_inputs_stream.update(x.to_bytes())
    y = kr.scalarmult_base().add(kr.scalarmult(b_coin))
    z = kr.scalarmult(hash_my_pub)

    state.state = State.EXPECT_STEP_A_MORE_DATA
    return BytecoinSignStepAResponse(sig_p=sig_p.to_bytes(),y=y.to_bytes(),z=z.to_bytes())

async def _sign_step_a_more_data(state, ctx, msg: BytecoinSignStepAMoreDataRequest):
    if state.state != State.EXPECT_STEP_A_MORE_DATA:
        raise wire.DataError("Unexpected sign step a more data")
    state.tx_inputs_stream.update(msg.data_chunk)
    return BytecoinEmptyResponse()

async def _sign_get_c0(state, ctx, msg: BytecoinSignGetC0Request):

    if state.state != State.EXPECT_STEP_A_MORE_DATA or state.inputs_counter + 1 != state.inputs_size:
        raise wire.DataError("Unexpected sign get c0")

    state.c0 = bcncrypto.BcnScalar(state.tx_inputs_stream.digest())

    state.step_args_hash = state.tx_prefix_stream.digest()
    state.tx_prefix_stream = bcncrypto.get_keccak()

    state.state = State.EXPECT_STEP_B
    state.inputs_counter = 0
    return BytecoinSignGetC0Response(c0=state.c0.to_bytes())

async def _sign_step_b(state, ctx, msg: BytecoinSignStepBRequest):
    if msg.address_index is None:
        msg.address_index = 0
    if state.state != State.EXPECT_STEP_B or state.inputs_counter >= state.inputs_size:
        raise wire.DataError("Unexpected sign step b")
    state.tx_prefix_stream.update(msg.output_secret_hash_arg)
    state.tx_prefix_stream.update(bcncrypto.get_varint_data(msg.address_index))

    address_audit_secret_key = state.creds.generate_address_secret_key(msg.address_index)
    inv_output_secret_hash = misc.invert_arg_to_inv_hash(msg.output_secret_hash_arg)
    output_secret_key_a = inv_output_secret_hash.mul(address_audit_secret_key)
    output_secret_key_s = inv_output_secret_hash.mul(state.creds.spend_secret_key)
    kr = state.generate_sign_secret(state.inputs_counter, b"kr")
    ks = state.generate_sign_secret(state.inputs_counter, b"ks")
    ka = state.generate_sign_secret(state.inputs_counter, b"ka")
    sig_rs = ks.sub(state.c0.mul(output_secret_key_s))
    sig_ra = ka.add(state.c0.mul(output_secret_key_a))
    my_c = bcncrypto.BcnScalar(msg.my_c)
    sig_rr = kr.sub(my_c.mul(output_secret_key_a))
    esig_rs = state.encrypt_result(sig_rs.to_bytes(), state.inputs_counter, b"rs")
    esig_ra = state.encrypt_result(sig_ra.to_bytes(), state.inputs_counter, b"ra")
    esig_rr = state.encrypt_result(sig_rr.to_bytes(), state.inputs_counter, b"rr")
    state.inputs_counter += 1
    e_key = bytes(32)
    if state.inputs_counter >= state.inputs_size:
        state.state = State.FINISHED
        step_args_hash2 = state.tx_prefix_stream.digest()
        if step_args_hash2 == state.step_args_hash:
            e_key = state.encryption_key
    return BytecoinSignStepBResponse(my_rr=esig_rr, ra=esig_ra, rs=esig_rs, encryption_key=e_key)
