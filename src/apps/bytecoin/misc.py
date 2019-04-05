from apps.common import HARDENED
from trezor import wire

from apps.bytecoin import bcncrypto

def get_basic_secrets(keychain):
    address_n = [HARDENED | 44, HARDENED | 0xCC, HARDENED | 1, 0, 0]
    node = keychain.derive(address_n, "secp256k1")
    key_seed = bcncrypto.cn_fast_hash(node.private_key())

    view_seed = bcncrypto.cn_fast_hash(key_seed + b"view_seed")

    view_secret_key = bcncrypto.hash_to_scalar(view_seed + b"view_key")
    return key_seed, view_seed, view_secret_key


class AccountCreds:
    def __init__(self, keychain):
        self.key_seed, self.view_seed, self.view_secret_key = get_basic_secrets(keychain)

        self.wallet_key = bcncrypto.cn_fast_hash(self.key_seed + b"wallet_key")

        self.audit_key_base_secret_key = bcncrypto.hash_to_scalar(self.view_seed + b"view_key_audit")
        self.spend_secret_key = bcncrypto.hash_to_scalar(self.key_seed + b"spend_key")

        self.sH = self.spend_secret_key.scalarmult_h()

        self.view_public_key = self.view_secret_key.scalarmult_base()
        A = self.audit_key_base_secret_key.scalarmult_base()
        self.A_plus_sH = A.add(self.sH)
        self.last_address_index = -1
        self.last_address_audit_secret_key = bcncrypto.BcnScalar()

    def generate_address_secret_key(self, address_index: int)->bcncrypto.BcnScalar:
        if address_index != self.last_address_index:
            self.last_address_index = address_index
            sec = bcncrypto.hash_to_scalar(self.A_plus_sH.to_bytes() + b"address" + bcncrypto.get_varint_data(address_index))
            self.last_address_audit_secret_key = sec.add(self.audit_key_base_secret_key)
        return self.last_address_audit_secret_key
    def generate_address(self, address_index: int):
        self.generate_address_secret_key(address_index)
        last_address_audit_public_key = self.last_address_audit_secret_key.scalarmult_base()
        S = last_address_audit_public_key.add(self.sH)
        Sv = self.view_secret_key.scalarmult(S)
        str = encode_address(1, S, Sv)
        return last_address_audit_public_key, S, Sv
    def generate_output_seed(self, tx_inputs_hash: bytes, out_index: int)->bytes:
        add = bcncrypto.get_varint_data(out_index)
        kck = bcncrypto.get_keccak()
        kck.update(self.view_seed)
        kck.update(tx_inputs_hash)
        kck.update(add)
        return kck.digest()

def invert_arg_to_inv_hash(arg:bytes)->bcncrypto.BcnScalar:
    output_secret_hash_s = bcncrypto.hash_to_scalar(arg)
    inv_output_secret_hash = output_secret_hash_s.invert()
    return inv_output_secret_hash

def get_creds(keychain)->AccountCreds:
    return AccountCreds(keychain)

def generate_output_secrets(output_seed:bytes):
    sca = bcncrypto.BcnScalar(output_seed)
    poi = bcncrypto.bytes_to_ec(output_seed)
    at = bcncrypto.cn_fast_hash(output_seed)
    return sca, poi, at[0]

def linkable_derive_output_public_key(output_secret_scalar:bcncrypto.BcnScalar, tx_inputs_hash:bytes, output_index:int, address_S:bcncrypto.BcnPoint, address_V:bcncrypto.BcnPoint):
    encrypted_secret = output_secret_scalar.scalarmult(address_V)
    derivation_b = output_secret_scalar.scalarmult_base().to_bytes()
    add = bcncrypto.get_varint_data(output_index)
    derivation_hash_scalar = bcncrypto.hash_to_scalar(derivation_b + tx_inputs_hash + add)

    output_public_key = address_S.add(derivation_hash_scalar.scalarmult_base())

    return output_public_key, encrypted_secret

def unlinkable_derive_output_public_key(output_secret_point:bcncrypto.BcnPoint, tx_inputs_hash:bytes, output_index:int, address_S:bcncrypto.BcnPoint, address_Sv:bcncrypto.BcnPoint):
    add = bcncrypto.get_varint_data(output_index)
    output_secret_hash_s = bcncrypto.hash_to_scalar(output_secret_point.to_bytes() + tx_inputs_hash + add)
    inv_output_secret_hash_s = output_secret_hash_s.invert()

    output_public_key = inv_output_secret_hash_s.scalarmult(address_S)
    encrypted_secret = output_secret_point.add(inv_output_secret_hash_s.scalarmult(address_Sv))
    return output_public_key, encrypted_secret

def encode_address(tag:int, S:bcncrypto.BcnPoint, Sv:bcncrypto.BcnPoint):
    if tag == 0:
        return bcncrypto.encode_address(6, S, Sv)
    if tag == 1:
        return bcncrypto.encode_address(572238, S, Sv)
    raise wire.DataError("Unknown address type")


def generate_key_image_b(output_public_key:bcncrypto.BcnPoint, output_secret_key_a:bcncrypto.BcnScalar)->bytes:
    P = bcncrypto.hash_to_ec(output_public_key.to_bytes())
    return output_secret_key_a.scalarmult(P).to_bytes()

def secret_keys_to_public_key(a:bcncrypto.BcnScalar, s:bcncrypto.BcnScalar)->bcncrypto.BcnPoint:
    return a.scalarmult_base().add(s.scalarmult_h())

def add_amount(sum: int, amount:int):
    if amount > 0xFFFFFFFFFFFFFFFF - sum: # sum is safe, amount itself can be > 2^64-1
        raise wire.DataError("Amount overflow")
    sum += amount
    return sum

def validate_full_path(path: list) -> bool:
    return True
