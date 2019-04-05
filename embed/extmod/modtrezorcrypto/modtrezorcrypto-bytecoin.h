/*
 * This file is part of the TREZOR project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// We avoid all dirty hacks, providing lean and strict interface

// We provide additional 'r' param for all functions (like sc_invert), where
// they place result (if r == None, return value is allocated)
// math (especially in loops) greatly benefits from reduced # of memoty allocations

// Functions to_bytes will always allocate, so that immutable bytes objects
// will never be overwritten

// We expose OOP-like interface, where you do sc1.add(sc2) instead of module.add(sc1, sc2)
// In MicroPython, overriding __add__, __mul__, etc. does not seem to work.

#include "py/objstr.h"
#include "py/objint.h"
#include "py/mpz.h"

#include "bignum.h"
#include "memzero.h"
#include "ed25519-donna/ed25519-donna.h"
#include "hasher.h"

/// package: trezorcrypto.bytecoin

typedef struct _mp_obj_bcn_point_t {
    mp_obj_base_t base;
    ge25519 p;
} mp_obj_bcn_point_t;

typedef struct _mp_obj_bcn_scalar_t {
    mp_obj_base_t base;
    bignum256modm p;
} mp_obj_bcn_scalar_t;

STATIC const mp_obj_type_t mod_trezorcrypto_bcn_point_type;
STATIC const mp_obj_type_t mod_trezorcrypto_bcn_scalar_type;

#define MP_OBJ_IS_BCN_POINT(o) MP_OBJ_IS_TYPE((o), &mod_trezorcrypto_bcn_point_type)
#define MP_OBJ_IS_BCN_SCALAR(o) MP_OBJ_IS_TYPE((o), &mod_trezorcrypto_bcn_scalar_type)
#define MP_OBJ_PTR_MPC_BCN_POINT(o) ((const mp_obj_bcn_point_t*) (o))
#define MP_OBJ_PTR_MPC_BCN_SCALAR(o) ((const mp_obj_bcn_scalar_t*) (o))
#define MP_OBJ_PTR_MP_BCN_POINT(o) ((mp_obj_bcn_point_t*) (o))
#define MP_OBJ_PTR_MP_BCN_SCALAR(o) ((mp_obj_bcn_scalar_t*) (o))
#define MP_OBJ_C_BCN_POINT(o) (MP_OBJ_PTR_MPC_BCN_POINT(o)->p)
#define MP_OBJ_BCN_POINT(o) (MP_OBJ_PTR_MP_BCN_POINT(o)->p)
#define MP_OBJ_C_BCN_SCALAR(o) (MP_OBJ_PTR_MPC_BCN_SCALAR(o)->p)
#define MP_OBJ_BCN_SCALAR(o) (MP_OBJ_PTR_MP_BCN_SCALAR(o)->p)

STATIC inline void assert_bcn_point(const mp_obj_t o){
    if (!MP_OBJ_IS_BCN_POINT(o)){
        mp_raise_ValueError("bytecoin point expected");
    }
}

STATIC inline void assert_bcn_scalar(const mp_obj_t o){
    if (!MP_OBJ_IS_BCN_SCALAR(o)){
        mp_raise_ValueError("bytecoin scalar expected");
    }
}

STATIC mp_obj_t mp_obj_new_bcn_scalar(){
    mp_obj_bcn_scalar_t *o = m_new_obj(mp_obj_bcn_scalar_t);
    o->base.type = &mod_trezorcrypto_bcn_scalar_type;
    set256_modm(o->p, 0);
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mp_obj_new_bcn_scalar_r(mp_obj_t r){
    if (r == mp_const_none){
        return mp_obj_new_bcn_scalar();
    }
    assert_bcn_scalar(r);
    return r;
}

STATIC void bcn_scalar_unpack(bignum256modm r, const mp_buffer_info_t * buff, mp_int_t offset){
    if (buff->len < 32 + offset){
        mp_raise_ValueError("Invalid length of secret key");
    }
    expand256_modm(r, ((uint8_t*)buff->buf) + offset, 32);
}

STATIC mp_obj_t mp_obj_new_bcn_point(){
    mp_obj_bcn_point_t *o = m_new_obj(mp_obj_bcn_point_t);
    o->base.type = &mod_trezorcrypto_bcn_point_type;
    ge25519_set_neutral(&o->p);
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mp_obj_new_bcn_point_r(mp_obj_t r){
    if (r == mp_const_none){
        return mp_obj_new_bcn_point();
    }
    assert_bcn_point(r);
    return r;
}

STATIC void bcn_point_unpack(ge25519 * r, const mp_buffer_info_t * buff, mp_int_t offset){
    if (buff->len < 32 + offset){
        mp_raise_ValueError("Invalid length of the EC point");
    }
    const int res = ge25519_unpack_vartime(r, ((uint8_t*)buff->buf) + offset);
    if (res != 1){
        mp_raise_ValueError("Point decoding error");
    }
}

/// class BcnScalar:
///     '''
///     EC scalar on SC25519
///     '''
///
///     def __init__(x: Optional[Union[BcnScalar, bytes]] = None):
///         '''
///         Constructor
///         '''
STATIC mp_obj_t mod_trezorcrypto_bcn_scalar_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args){
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_bcn_scalar_t *o = m_new_obj(mp_obj_bcn_scalar_t);
    o->base.type = type;

    mp_buffer_info_t buff;
    if (n_args == 0 || args[0] == mp_const_none){
        set256_modm(o->p, 0);
    } else if (n_args == 1 && MP_OBJ_IS_BCN_SCALAR(args[0])){
        copy256_modm(o->p, MP_OBJ_C_BCN_SCALAR(args[0]));
    } else if (n_args == 1 && mp_get_buffer(args[0], &buff, MP_BUFFER_READ)){
        bcn_scalar_unpack(o->p, &buff, 0);
    } else {
        mp_raise_ValueError("Invalid bcn_scalar constructor");
    }
    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t mod_trezorcrypto_bcn_scalar___del__(mp_obj_t self){
    mp_obj_bcn_scalar_t *o = MP_OBJ_TO_PTR(self);
    memzero(o->p, sizeof(bignum256modm));
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_bcn_scalar___del___obj, mod_trezorcrypto_bcn_scalar___del__);

/// def to_bytes(self: BcnScalar) -> bytes:
///     '''
///     Scalar decompression
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_scalar_to_bytes(mp_obj_t self){
    uint8_t buff[32];
    contract256_modm(buff, MP_OBJ_C_BCN_SCALAR(self));
    return mp_obj_new_bytes(buff, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_bcn_scalar_to_bytes_obj, mod_trezorcrypto_bcn_scalar_to_bytes);

/// def invert(self: BcnScalar, r:Optional[BcnScalar] = None) -> BcnScalar:
///     '''
///     Scalar modular inversion
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_scalar_invert(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_scalar_r(n_args > 1 ? args[1] : mp_const_none);
    assert_bcn_scalar(args[0]);
    // bn_prime = curve order, little endian encoded
    bignum256 bn_prime = {.val={0x1cf5d3ed, 0x20498c69, 0x2f79cd65, 0x37be77a8, 0x14, 0x0, 0x0, 0x0, 0x1000}};
    bignum256 bn_x;

    memcpy(&bn_x.val, MP_OBJ_C_BCN_SCALAR(args[0]), sizeof(bignum256modm));
    bn_inverse(&bn_x, &bn_prime);
    memcpy(MP_OBJ_BCN_SCALAR(res), bn_x.val, sizeof(bignum256modm));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_scalar_invert_obj, 1, 2, mod_trezorcrypto_bcn_scalar_invert);

/// def add(self: BcnScalar, a: BcnScalar, r: Optional[BcnScalar] = None) -> BcnScalar:
///     '''
///     Scalar addition
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_scalar_add(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_scalar_r(n_args > 2 ? args[2] : mp_const_none);
    assert_bcn_scalar(args[0]);
    assert_bcn_scalar(args[1]);

    add256_modm(MP_OBJ_BCN_SCALAR(res), MP_OBJ_C_BCN_SCALAR(args[0]), MP_OBJ_C_BCN_SCALAR(args[1]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_scalar_add_obj, 2, 3, mod_trezorcrypto_bcn_scalar_add);

/// def sub(self: BcnScalar, a: BcnScalar, r: Optional[BcnScalar] = None) -> BcnScalar:
///     '''
///     Scalar subtraction
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_scalar_sub(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_scalar_r(n_args > 2 ? args[2] : mp_const_none);
    assert_bcn_scalar(args[0]);
    assert_bcn_scalar(args[1]);

    sub256_modm(MP_OBJ_BCN_SCALAR(res), MP_OBJ_C_BCN_SCALAR(args[0]), MP_OBJ_C_BCN_SCALAR(args[1]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_scalar_sub_obj, 2, 3, mod_trezorcrypto_bcn_scalar_sub);

/// def mul(self: BcnScalar, a: BcnScalar, r: Optional[BcnScalar] = None) -> BcnScalar:
///     '''
///     Scalar multiplication
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_scalar_mul(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_scalar_r(n_args > 2 ? args[2] : mp_const_none);
    assert_bcn_scalar(args[0]);
    assert_bcn_scalar(args[1]);

    mul256_modm(MP_OBJ_BCN_SCALAR(res), MP_OBJ_C_BCN_SCALAR(args[0]), MP_OBJ_C_BCN_SCALAR(args[1]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_scalar_mul_obj, 2, 3, mod_trezorcrypto_bcn_scalar_mul);

/// def scalarmult_base(self: BcnScalar, r: Optional[BcnPoint] = None) -> BcnPoint:
///     '''
///     s * G
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_scalar_scalarmult_base(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_point_r(n_args > 1 ? args[1] : mp_const_none);
    assert_bcn_scalar(args[0]);
    ge25519_scalarmult_base_wrapper(&MP_OBJ_BCN_POINT(res), MP_OBJ_C_BCN_SCALAR(args[0]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_scalar_scalarmult_base_obj, 1, 2, mod_trezorcrypto_bcn_scalar_scalarmult_base);

const ge25519 ALIGN(16) bytecoin_h = {
        {0x1861ec7, 0x1ceac77, 0x2f11626, 0x1f261d3, 0x346107c, 0x06d8c4a, 0x254201d, 0x1675c09, 0x1301c3f, 0x0211d73},
        {0x326feb4, 0x12e30cc, 0x0cf54b4, 0x1117305, 0x318f5d5, 0x06cf754, 0x2e578a1, 0x1daf058, 0x34430a1, 0x04410e9},
        {0x0fde4d2, 0x0774049, 0x22ca951, 0x05aec2b, 0x07a36a5, 0x1394f13, 0x3c5385c, 0x1adb924, 0x2b6c581, 0x0a55fa4},
        {0x24517f7, 0x05ee936, 0x3acf5d9, 0x14b08aa, 0x3363738, 0x1051745, 0x360601e, 0x0f3f2c9, 0x1ead2cd, 0x1d3e3df}
};

/// def scalarmult_h(self: BcnScalar, r: Optional[BcnPoint] = None) -> BcnPoint:
///     '''
///     s * H
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_scalar_scalarmult_h(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_point_r(n_args > 1 ? args[1] : mp_const_none);
    assert_bcn_scalar(args[0]);
    ge25519_scalarmult(&MP_OBJ_BCN_POINT(res), &bytecoin_h, MP_OBJ_C_BCN_SCALAR(args[0]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_scalar_scalarmult_h_obj, 1, 2, mod_trezorcrypto_bcn_scalar_scalarmult_h);

/// def scalarmult(self: BcnScalar, p:BcnPoint, r: Optional[BcnPoint] = None) -> BcnPoint:
///     '''
///     s * p
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_scalar_scalarmult(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_point_r(n_args > 2 ? args[2] : mp_const_none);
    assert_bcn_scalar(args[0]);
    assert_bcn_point(args[1]);
    ge25519_scalarmult(&MP_OBJ_BCN_POINT(res), &MP_OBJ_C_BCN_POINT(args[1]), MP_OBJ_C_BCN_SCALAR(args[0]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_scalar_scalarmult_obj, 2, 3, mod_trezorcrypto_bcn_scalar_scalarmult);


/// class BcnPoint:
///     '''
///     EC point on ED25519
///     '''
///
///     def __init__(x: Optional[Union[BcnPoint, bytes]] = None):
///         '''
///         Constructor
///         '''
STATIC mp_obj_t mod_trezorcrypto_bcn_point_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args){
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_bcn_point_t *o = m_new_obj(mp_obj_bcn_point_t);
    o->base.type = type;

    mp_buffer_info_t buff;
    if (n_args == 0 || args[0] == mp_const_none){
        ge25519_set_neutral(&o->p);
    } else if (n_args == 1 && MP_OBJ_IS_BCN_POINT(args[0])){
        ge25519_copy(&o->p, &MP_OBJ_C_BCN_POINT(args[0]));
    } else if (n_args == 1 && mp_get_buffer(args[0], &buff, MP_BUFFER_READ)){
        bcn_point_unpack(&o->p, &buff, 0);
    } else {
        mp_raise_ValueError("Invalid bcn_point constructor");
    }
    return MP_OBJ_FROM_PTR(o);
}


STATIC mp_obj_t mod_trezorcrypto_bcn_point___del__(mp_obj_t self){
    mp_obj_bcn_point_t *o = MP_OBJ_TO_PTR(self);
    memzero(&(o->p), sizeof(ge25519));
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_bcn_point___del___obj, mod_trezorcrypto_bcn_point___del__);

/// def ge_tobytes(p: BcnPoint) -> bytes:
///     '''
///     Point compression
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_point_to_bytes(mp_obj_t p){
    assert_bcn_point(p);
    uint8_t buff[32];
    ge25519_pack(buff, &MP_OBJ_C_BCN_POINT(p));
    return mp_obj_new_bytes(buff, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_bcn_point_to_bytes_obj, mod_trezorcrypto_bcn_point_to_bytes);

/// def add(self: BcnPoint, a: BcnPoint, r: Optional[BcnPoint] = None) -> BcnPoint:
///     '''
///     Scalar addition
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_point_add(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_point_r(n_args > 2 ? args[2] : mp_const_none);
    assert_bcn_point(args[0]);
    assert_bcn_point(args[1]);

    ge25519_add(&MP_OBJ_BCN_POINT(res), &MP_OBJ_C_BCN_POINT(args[0]), &MP_OBJ_C_BCN_POINT(args[1]), 0);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_point_add_obj, 2, 3, mod_trezorcrypto_bcn_point_add);


/// def dub(self: BcnPoint, a: BcnPoint, r: Optional[BcnPoint] = None) -> BcnPoint:
///     '''
///     Scalar addition
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_point_sub(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_point_r(n_args > 2 ? args[2] : mp_const_none);
    assert_bcn_point(args[0]);
    assert_bcn_point(args[1]);

    ge25519_add(&MP_OBJ_BCN_POINT(res), &MP_OBJ_C_BCN_POINT(args[0]), &MP_OBJ_C_BCN_POINT(args[1]), 1);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_point_sub_obj, 2, 3, mod_trezorcrypto_bcn_point_sub);


/// def scalarmult(self: BcnPoint, s:BcnScalar, r: Optional[BcnPoint] = None) -> BcnPoint:
///     '''
///     s * p
///     '''
STATIC mp_obj_t mod_trezorcrypto_bcn_point_scalarmult(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_point_r(n_args > 2 ? args[2] : mp_const_none);
    assert_bcn_point(args[0]);
    assert_bcn_scalar(args[1]);
    ge25519_scalarmult(&MP_OBJ_BCN_POINT(res), &MP_OBJ_C_BCN_POINT(args[0]), MP_OBJ_C_BCN_SCALAR(args[1]));
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bcn_point_scalarmult_obj, 2, 3, mod_trezorcrypto_bcn_point_scalarmult);

/// def cn_fast_hash(b: bytes) -> bytes:
///     '''
///     CN fast hash
///     '''
STATIC mp_obj_t mod_trezorcrypto_bytecoin_cn_fast_hash(mp_obj_t b){
    uint8_t buff[32];
    mp_buffer_info_t data;
    mp_get_buffer_raise(b, &data, MP_BUFFER_READ);
    hasher_Raw(HASHER_SHA3K, data.buf, data.len, buff);
    return mp_obj_new_bytes(buff, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(mod_trezorcrypto_bytecoin_cn_fast_hash_obj, mod_trezorcrypto_bytecoin_cn_fast_hash);

/// def hash_to_ec(buff: bytes, r: Optional[BcnPoint] = None) -> BcnPoint:
///     '''
///     hashing to EC point in main subgroup
///     '''
STATIC mp_obj_t mod_trezorcrypto_bytecoin_hash_to_ec(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_point_r(n_args > 1 ? args[1] : mp_const_none);
    mp_buffer_info_t data;
    mp_get_buffer_raise(args[0], &data, MP_BUFFER_READ);
    ge25519 point2;
    uint8_t hash[32];
    hasher_Raw(HASHER_SHA3K, data.buf, data.len, hash);

    ge25519_fromfe_frombytes_vartime(&point2, hash);
    ge25519_mul8(&MP_OBJ_BCN_POINT(res), &point2);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bytecoin_hash_to_ec_obj, 1, 2, mod_trezorcrypto_bytecoin_hash_to_ec);

/// def bytes_to_ec(buff: bytes, r: Optional[BcnPoint] = None) -> BcnPoint:
///     '''
///     any 32 bytes to EC point in main subgroup (hash_to_ec without hashing)
///     '''
STATIC mp_obj_t mod_trezorcrypto_bytecoin_bytes_to_ec(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_point_r(n_args > 1 ? args[1] : mp_const_none);
    mp_buffer_info_t data;
    mp_get_buffer_raise(args[0], &data, MP_BUFFER_READ);
    if (data.len != 32){
        mp_raise_ValueError("Invalid length of bytes to the EC point");
    }
    ge25519 point2;

    ge25519_fromfe_frombytes_vartime(&point2, data.buf);
    ge25519_mul8(&MP_OBJ_BCN_POINT(res), &point2);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bytecoin_bytes_to_ec_obj, 1, 2, mod_trezorcrypto_bytecoin_bytes_to_ec);

/// def hash_to_scalar(buff: bytes, r: Optional[BcnScalar] = None) -> BcnScalar:
///     '''
///     return BcnScalar(cn_fast_hash(bytes)) without allocating temporary object
///     '''
STATIC mp_obj_t mod_trezorcrypto_bytecoin_hash_to_scalar(size_t n_args, const mp_obj_t *args){
    mp_obj_t res = mp_obj_new_bcn_scalar_r(n_args > 1 ? args[1] : mp_const_none);
    mp_buffer_info_t data;
    mp_get_buffer_raise(args[0], &data, MP_BUFFER_READ);
    uint8_t hash[32];
    hasher_Raw(HASHER_SHA3K, data.buf, data.len, hash);
    expand256_modm(MP_OBJ_BCN_SCALAR(res), hash, 32);
    return res;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(mod_trezorcrypto_bytecoin_hash_to_scalar_obj, 1, 2, mod_trezorcrypto_bytecoin_hash_to_scalar);

STATIC const mp_rom_map_elem_t mod_trezorcrypto_bcn_point_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&mod_trezorcrypto_bcn_point___del___obj) },
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&mod_trezorcrypto_bcn_point_to_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_add), MP_ROM_PTR(&mod_trezorcrypto_bcn_point_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_sub), MP_ROM_PTR(&mod_trezorcrypto_bcn_point_sub_obj) },
    { MP_ROM_QSTR(MP_QSTR_scalarmult), MP_ROM_PTR(&mod_trezorcrypto_bcn_point_scalarmult_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_bcn_point_locals_dict, mod_trezorcrypto_bcn_point_locals_dict_table);

STATIC const mp_obj_type_t mod_trezorcrypto_bcn_point_type = {
    { &mp_type_type },
    .name = MP_QSTR_BcnPoint,
    .make_new = mod_trezorcrypto_bcn_point_make_new,
    .locals_dict = (void*)&mod_trezorcrypto_bcn_point_locals_dict,
};

STATIC const mp_rom_map_elem_t mod_trezorcrypto_bcn_scalar_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar___del___obj) },
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar_to_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_invert), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar_invert_obj) },
    { MP_ROM_QSTR(MP_QSTR_add), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_sub), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar_sub_obj) },
    { MP_ROM_QSTR(MP_QSTR_mul), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar_mul_obj) },
    { MP_ROM_QSTR(MP_QSTR_scalarmult), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar_scalarmult_obj) },
    { MP_ROM_QSTR(MP_QSTR_scalarmult_base), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar_scalarmult_base_obj) },
    { MP_ROM_QSTR(MP_QSTR_scalarmult_h), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar_scalarmult_h_obj) },
};


STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_bcn_scalar_locals_dict, mod_trezorcrypto_bcn_scalar_locals_dict_table);

STATIC const mp_obj_type_t mod_trezorcrypto_bcn_scalar_type = {
    { &mp_type_type },
    .name = MP_QSTR_BcnScalar,
    .make_new = mod_trezorcrypto_bcn_scalar_make_new,
    .locals_dict = (void*)&mod_trezorcrypto_bcn_scalar_locals_dict,
};

STATIC const mp_rom_map_elem_t mod_trezorcrypto_bytecoin_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_bytecoin) },
    { MP_ROM_QSTR(MP_QSTR_BcnScalar), MP_ROM_PTR(&mod_trezorcrypto_bcn_scalar_type) },
    { MP_ROM_QSTR(MP_QSTR_BcnPoint), MP_ROM_PTR(&mod_trezorcrypto_bcn_point_type) },

    { MP_ROM_QSTR(MP_QSTR_cn_fast_hash), MP_ROM_PTR(&mod_trezorcrypto_bytecoin_cn_fast_hash_obj) },
    { MP_ROM_QSTR(MP_QSTR_bytes_to_ec), MP_ROM_PTR(&mod_trezorcrypto_bytecoin_bytes_to_ec_obj) },
    { MP_ROM_QSTR(MP_QSTR_hash_to_ec), MP_ROM_PTR(&mod_trezorcrypto_bytecoin_hash_to_ec_obj) },
    { MP_ROM_QSTR(MP_QSTR_hash_to_scalar), MP_ROM_PTR(&mod_trezorcrypto_bytecoin_hash_to_scalar_obj) },
};
STATIC MP_DEFINE_CONST_DICT(mod_trezorcrypto_bytecoin_globals, mod_trezorcrypto_bytecoin_globals_table);

STATIC const mp_obj_module_t mod_trezorcrypto_bytecoin_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mod_trezorcrypto_bytecoin_globals,
};
