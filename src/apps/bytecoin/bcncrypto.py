from trezor.crypto.hashlib import sha3_256
from trezor.crypto import bytecoin
from trezor.crypto import random

def get_keccak():
    return sha3_256(data=None, keccak=True)

BcnScalar = bytecoin.BcnScalar
BcnPoint = bytecoin.BcnPoint

cn_fast_hash = bytecoin.cn_fast_hash
hash_to_ec = bytecoin.hash_to_ec
bytes_to_ec = bytecoin.bytes_to_ec
hash_to_scalar = bytecoin.hash_to_scalar

def random_scalar()->BcnScalar:
    return BcnScalar(random.bytes(32))

def bytes_to_scalar64(b:bytes)->BcnScalar:
    sc_2_256 = BcnScalar(bytes(
        [0x1d, 0x95, 0x98, 0x8d, 0x74, 0x31, 0xec, 0xd6, 0x70, 0xcf, 0x7d, 0x73, 0xf4, 0x5b, 0xef, 0xc6, 0xfe, 0xff,
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f]))
    left = BcnScalar(b)
    right = hash_to_scalar(b)
    return right.mul(sc_2_256).add(left)

def hash_to_scalar64(b:bytes)->BcnScalar:
    return bytes_to_scalar64(cn_fast_hash(b))

def get_varint_size(n)->int:
    if n < 0:
        raise ValueError("get_varint_size(n), n < 0")
    bts = 0 if n != 0 else 1
    while n:
        n >>= 7
        bts += 1
    return bts

def get_varint_data(n)->bytearray:
    buffer = bytearray(get_varint_size(n))
    return get_varint_data_into(n, buffer, 0)

def get_varint_data_into(n:int, buffer:bytearray, offset:int=0)->bytearray:
    if n < 0:
        raise ValueError("get_varint_data_into(n), n < 0")
    shifted = True
    while shifted:
        shifted = n >> 7
        buffer[offset] = (n & 0x7F) | (0x80 if shifted else 0x00)
        offset += 1
        n = shifted
    return buffer

encoded_block_sizes = [0, 2, 3, 5, 6, 7, 9, 10, 11]
alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def from_bytes_big(b)->int:
    n = 0
    for x in b:
        n <<= 8
        n |= x
    return n

def encode_block(b:bytes, res:bytearray, offset:int):
    size = encoded_block_sizes[len(b)]
    num = from_bytes_big(b)
    for i in range(size - 1, -1, -1):
        remainder = num % len(alphabet)
        num //= len(alphabet)
        res[offset + i] = alphabet[remainder]

def encode(b:bytes) -> str:
    full_block_size = 8
    full_encoded_block_size = 11
    full_block_count = len(b) // full_block_size
    last_block_size = len(b) % full_block_size
    res_size = full_block_count * full_encoded_block_size + encoded_block_sizes[last_block_size]
    buffer = bytearray(res_size)
    i = 0
    while i != full_block_count:
        encode_block(b[i*full_block_size:(i+1)*full_block_size], buffer, i * full_encoded_block_size)
        i += 1
    pass
    if last_block_size != 0:
        encode_block(b[full_block_count*full_block_size:], buffer, i * full_encoded_block_size)
    return bytes(buffer).decode()

def encode_address(tag:int, S:BcnPoint, Sv:BcnPoint) -> str:
    addr_checksum_size = 4
    buf = get_varint_data(tag) + S.to_bytes() + Sv.to_bytes()
    hash = cn_fast_hash(buf)
    buf += hash[0:addr_checksum_size]
    enc = encode(buf)
    return enc

def test_crypto():
    print("sta0")
    sca_6_b = bytes([6,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
    sca_2_b = bytes([2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
    print("sta1", len(sca_6_b))
    sca_6 = BcnScalar(sca_6_b)
    print("sta1.5", sca_6.to_bytes())
    sca_2 = BcnScalar(sca_2_b)
    print("sta11")
    sca_inv_2 = sca_2.invert()
    print("sca_inv_2", sca_inv_2.to_bytes())
    sca_inv_2 = sca_2.invert(None)
    print("sca_inv_2", sca_inv_2.to_bytes())
    sca_2_plus_6 = sca_6.add(sca_2)
    print("sca_2_plus_6", sca_2_plus_6.to_bytes())
    sca_2_plus_6 = sca_6.add(sca_2)
    print("sca_2_plus_6", sca_2_plus_6.to_bytes())
    sca_6_minus_2 = sca_6.sub(sca_2)
    print("sca_6_minus_2", sca_6_minus_2.to_bytes())
    sca_6_minus_2 = sca_6.sub(sca_2)
    print("sca_6_minus_2", sca_6_minus_2.to_bytes())
    sca_6_mul_2 = sca_6.mul(sca_2)
    print("sca_6_mul_2", sca_6_mul_2.to_bytes())
    sca_6_mul_2 = sca_6.mul(sca_2)
    print("sca_6_mul_2", sca_6_mul_2.to_bytes())

    poi1 = sca_2.scalarmult_base()
    print("poi1", poi1.to_bytes())
    poi2 = sca_2.scalarmult_h()
    print("poi2", poi2.to_bytes())
    poi3 = sca_2.scalarmult(poi1)
    print("poi3", poi3.to_bytes())
    poi3 = poi1.scalarmult(sca_2)
    print("poi3", poi3.to_bytes())
    poi4 = poi1.add(poi2)
    print("poi4", poi4.to_bytes())
    poi5 = poi1.sub(poi2)
    print("poi5", poi5.to_bytes())
    byby = poi1.to_bytes()
    poi6 = BcnPoint(byby)
    print("poi6", poi6.to_bytes())

    ha = cn_fast_hash(b"bcn")
    print("ha", ha)

    sha = hash_to_scalar(b"bcn")
    print("sha", sha.to_bytes())

    xha = hash_to_scalar64(b"bcn")
    print("xha", xha.to_bytes())
    xha = bytes_to_scalar64(cn_fast_hash(b"bcn"))
    print("xha", xha.to_bytes())

    pha = hash_to_ec(b"bcn")
    print("pha", pha.to_bytes())
    pha = bytes_to_ec(cn_fast_hash(b"bcn"))
    print("pha", pha.to_bytes())

    print("vb(572238)=", get_varint_data(572238))
    print("ea=", encode_address(572238, poi1, poi2))

