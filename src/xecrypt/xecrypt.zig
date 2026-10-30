// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of the XeCrypt routines XexTool uses. The original stores RSA numbers as
// an array of big-endian u64 limbs in least-significant-limb-first order. The
// helpers at the bottom convert that representation to the conventional
// big-endian byte string used by std.crypto.ff.

const std = @import("std");
const endian = @import("../core/endian.zig");

pub const Sha1 = std.crypto.hash.Sha1;
pub const Sha1DigestSize = 20;
pub const HmacBlockSize = 64;
pub const AesBlockSize = 16;

pub const AesState = struct {
    key: [16]u8,
};

pub const ShaState = Sha1;

pub const HmacShaState = struct {
    inner: Sha1,
    outer: Sha1,
};

pub const Signature = [256]u8;
pub const Rsa = extern struct {
    cqw: u32,
    dw_pub_exp: u32,
    qw_reserved: u64,
};

pub fn XeCryptAesKey(state: *AesState, key: []const u8) void {
    std.debug.assert(key.len == 16);
    @memcpy(&state.key, key[0..16]);
}

pub fn XeCryptAesEcb(state: *const AesState, input: *const [16]u8, output: *[16]u8, encrypt: bool) void {
    if (encrypt) {
        const ctx = std.crypto.core.aes.Aes128.initEnc(state.key);
        ctx.encrypt(output, input);
    } else {
        const ctx = std.crypto.core.aes.Aes128.initDec(state.key);
        ctx.decrypt(output, input);
    }
}

pub fn XeCryptAesCbc(state: *const AesState, input: []const u8, output: []u8, feed: *[16]u8, encrypt: bool) void {
    std.debug.assert(input.len % AesBlockSize == 0);
    std.debug.assert(output.len >= input.len);
    if (encrypt) {
        const ctx = std.crypto.core.aes.Aes128.initEnc(state.key);
        var iv = feed.*;
        var offset: usize = 0;
        while (offset < input.len) : (offset += AesBlockSize) {
            var block: [16]u8 = undefined;
            for (0..16) |i| block[i] = input[offset + i] ^ iv[i];
            ctx.encrypt(output[offset..][0..16], &block);
            @memcpy(&iv, output[offset..][0..16]);
        }
        feed.* = iv;
    } else {
        const ctx = std.crypto.core.aes.Aes128.initDec(state.key);
        var iv = feed.*;
        var offset: usize = 0;
        while (offset < input.len) : (offset += AesBlockSize) {
            var ciphertext: [16]u8 = undefined;
            @memcpy(&ciphertext, input[offset..][0..16]);
            var plaintext: [16]u8 = undefined;
            ctx.decrypt(&plaintext, &ciphertext);
            for (0..16) |i| output[offset + i] = plaintext[i] ^ iv[i];
            @memcpy(&iv, &ciphertext);
        }
        feed.* = iv;
    }
}

pub fn XeCryptShaInit(state: *ShaState) void {
    state.* = Sha1.init(.{});
}

pub fn XeCryptShaUpdate(state: *ShaState, input: []const u8) void {
    if (input.len != 0) state.update(input);
}

pub fn XeCryptShaFinal(state: *ShaState, output: []u8, output_len: u32) void {
    var digest: [Sha1DigestSize]u8 = undefined;
    state.final(&digest);
    const count = @min(output.len, @min(output_len, Sha1DigestSize));
    @memcpy(output[0..count], digest[0..count]);
}

pub fn XeCryptSha(input1: []const u8, input2: []const u8, input3: []const u8, output: []u8, output_len: u32) void {
    var state: ShaState = undefined;
    XeCryptShaInit(&state);
    XeCryptShaUpdate(&state, input1);
    XeCryptShaUpdate(&state, input2);
    XeCryptShaUpdate(&state, input3);
    XeCryptShaFinal(&state, output, output_len);
}

pub fn XeCryptHmacShaInit(state: *HmacShaState, key: []const u8) void {
    var k: [HmacBlockSize]u8 = @splat(0);
    @memcpy(k[0..@min(key.len, HmacBlockSize)], key[0..@min(key.len, HmacBlockSize)]);

    var pad: [HmacBlockSize]u8 = undefined;
    for (0..HmacBlockSize) |i| pad[i] = k[i] ^ 0x36;
    XeCryptShaInit(&state.inner);
    XeCryptShaUpdate(&state.inner, &pad);

    for (0..HmacBlockSize) |i| pad[i] = k[i] ^ 0x5C;
    XeCryptShaInit(&state.outer);
    XeCryptShaUpdate(&state.outer, &pad);
}

pub fn XeCryptHmacShaUpdate(state: *HmacShaState, input: []const u8) void {
    XeCryptShaUpdate(&state.inner, input);
}

pub fn XeCryptHmacShaFinal(state: *HmacShaState, output: []u8, output_len: u32) void {
    var digest: [Sha1DigestSize]u8 = undefined;
    XeCryptShaFinal(&state.inner, &digest, Sha1DigestSize);
    XeCryptShaUpdate(&state.outer, &digest);
    XeCryptShaFinal(&state.outer, output, output_len);
}

pub fn XeCryptHmacSha(key: []const u8, input1: []const u8, input2: []const u8, input3: []const u8, output: []u8, output_len: u32) void {
    var state: HmacShaState = undefined;
    XeCryptHmacShaInit(&state, key);
    XeCryptHmacShaUpdate(&state, input1);
    XeCryptHmacShaUpdate(&state, input2);
    XeCryptHmacShaUpdate(&state, input3);
    XeCryptHmacShaFinal(&state, output, output_len);
}

pub fn XeCryptRotSum(output: *[32]u8, input: []const u8, cqw: u32) void {
    if (cqw == 0) return;
    std.debug.assert(input.len >= @as(usize, cqw) * 8);
    std.debug.assert(output.len == 32);

    var qw1 = endian.get64be(output, 0);
    var qw2 = endian.get64be(output, 8);
    var qw3 = endian.get64be(output, 16);
    var qw4 = endian.get64be(output, 24);

    var i: u32 = 0;
    while (i < cqw) : (i += 1) {
        const tqw1 = endian.get64be(input, @as(usize, i) * 8);
        const tqw2 = tqw1 +% qw2;
        qw2 = if (tqw2 < tqw1) 1 else 0;
        qw4 = (~tqw1) +% qw4 +% 1;
        qw1 = qw2 +% qw1;
        qw2 = std.math.rotl(u64, tqw2, 29);
        const borrow: u64 = if (qw4 > tqw1) 1 else 0;
        qw3 = (~borrow) +% qw3 +% 1;
        qw4 = std.math.rotl(u64, qw4, 31);
    }

    endian.set64be(output, 0, qw1);
    endian.set64be(output, 8, qw2);
    endian.set64be(output, 16, qw3);
    endian.set64be(output, 24, qw4);
}

pub fn XeCryptRotSumSha(input1: []const u8, input2: []const u8, output: []u8, output_len: u32) void {
    var rotsum: [32]u8 = @splat(0);
    XeCryptRotSum(&rotsum, input1, @intCast(input1.len / 8));
    XeCryptRotSum(&rotsum, input2, @intCast(input2.len / 8));

    var state: ShaState = undefined;
    XeCryptShaInit(&state);
    XeCryptShaUpdate(&state, &rotsum);
    XeCryptShaUpdate(&state, &rotsum);
    XeCryptShaUpdate(&state, input1);
    XeCryptShaUpdate(&state, input2);
    for (0..rotsum.len) |i| rotsum[i] = ~rotsum[i];
    XeCryptShaUpdate(&state, &rotsum);
    XeCryptShaUpdate(&state, &rotsum);
    XeCryptShaFinal(&state, output, output_len);
}

pub fn XeCryptRc4(key: []const u8, data: []u8) void {
    var s: [256]u8 = undefined;
    for (0..256) |i| s[i] = @intCast(i);
    var j: u8 = 0;
    for (0..256) |i| {
        j = j +% s[i] +% key[i % key.len];
        std.mem.swap(u8, &s[i], &s[j]);
    }
    var i: u8 = 0;
    j = 0;
    for (data) |*byte| {
        i = i +% 1;
        j = j +% s[i];
        std.mem.swap(u8, &s[i], &s[j]);
        byte.* ^= s[s[i] +% s[j]];
    }
}

pub fn XeCryptBnQwBeSigFormat(signature: *Signature, hash: []const u8, salt: []const u8) void {
    std.debug.assert(hash.len == 20);
    std.debug.assert(salt.len == 10);

    @memset(signature[0..0xE0], 0);
    @memcpy(signature[0xE1..0xEB], salt[0..10]);
    signature[0xE0] = 1;
    signature[0xFF] = 0xBC;

    var state: ShaState = undefined;
    XeCryptShaInit(&state);
    XeCryptShaUpdate(&state, signature[0..8]);
    XeCryptShaUpdate(&state, hash[0..20]);
    XeCryptShaUpdate(&state, salt[0..10]);
    XeCryptShaFinal(&state, signature[0xEB..0xFF], 20);

    XeCryptRc4(signature[0xEB..0xFF], signature[0..0xEB]);
    signature[0] &= 0x7F;
    bnQwBeBufSwap(signature[0..256]);
}

pub fn XeCryptBnQwBeSigCreate(signature: *Signature, hash: []const u8, salt: []const u8, key: []const u8) bool {
    var public_key: Rsa = undefined;
    @memcpy(std.mem.asBytes(&public_key), key[0..@sizeOf(Rsa)]);
    const count = @byteSwap(public_key.cqw);
    if (count != 0x20) return false;
    const exp = @byteSwap(public_key.dw_pub_exp);
    if (exp != 3 and exp != 0x00010001) return false;

    XeCryptBnQwBeSigFormat(signature, hash, salt);

    const modulus = key[0x10..][0 .. @as(usize, count) * 8];
    if (!lessThanQwArray(signature, modulus)) return false;

    var two_qw: [256]u8 = @splat(0);
    endian.set64be(&two_qw, 0, 2);

    var exponent_qw: [256]u8 = @splat(0);
    const blinding: u64 = (@as(u64, exp) - 1) << 11;
    endian.set64be(&exponent_qw, 0, blinding);

    var pow_result: [256]u8 = @splat(0);
    if (!XeCryptBnQwNeModExp(&pow_result, &two_qw, &exponent_qw, modulus, count)) return false;

    const M = std.crypto.ff.Modulus(4096);
    const modulus_be = qwArrayToBeBytes(modulus);
    const m = M.fromBytes(&modulus_be, .big) catch return false;
    const a = M.Fe.fromBytes(m, &qwArrayToBeBytes(&pow_result), .big) catch return false;
    const b = M.Fe.fromBytes(m, &qwArrayToBeBytes(signature), .big) catch return false;
    const product = m.mul(a, b);

    var tmp: [M.Fe.encoded_bytes]u8 = undefined;
    product.toBytes(&tmp, .big) catch return false;
    beBytesToQwArray(&tmp, signature);
    return true;
}

pub fn XeCryptBnQwBeSigVerify(signature: []const u8, hash: []const u8, salt: []const u8, key: []const u8) bool {
    std.debug.assert(signature.len == 256);
    var public_key: Rsa = undefined;
    @memcpy(std.mem.asBytes(&public_key), key[0..@sizeOf(Rsa)]);
    const count = @byteSwap(public_key.cqw);
    if (count != 0x20) return false;
    const exp = @byteSwap(public_key.dw_pub_exp);
    if (exp != 3 and exp != 0x00010001) return false;

    var expected: Signature = undefined;
    XeCryptBnQwBeSigFormat(&expected, hash, salt);

    const modulus = key[0x10..][0 .. @as(usize, count) * 8];
    var decrypted: [256]u8 = @splat(0);
    var exponent_qw: [256]u8 = @splat(0);
    endian.set32be(&exponent_qw, 0, exp);
    if (!XeCryptBnQwNeModExp(&decrypted, signature[0..256], &exponent_qw, modulus, count)) return false;
    return std.mem.eql(u8, &decrypted, &expected);
}

pub fn XeCryptBnQwNeModExp(output: []u8, input: []const u8, exponent: []const u8, modulus: []const u8, cqw: u32) bool {
    std.debug.assert(cqw > 0);
    const byte_count: usize = @as(usize, cqw) * 8;
    if (input.len < byte_count or exponent.len < byte_count or modulus.len < byte_count or output.len < byte_count) return false;

    const M = std.crypto.ff.Modulus(4096);
    const modulus_be = qwArrayToBeBytes(modulus[0..byte_count]);
    const input_be = qwArrayToBeBytes(input[0..byte_count]);
    const exponent_be = qwArrayToBeBytes(exponent[0..byte_count]);

    const m = M.fromBytes(&modulus_be, .big) catch return false;
    const x = M.Fe.fromBytes(m, &input_be, .big) catch return false;
    const result = m.powWithEncodedExponent(x, &exponent_be, .big) catch return false;

    var tmp: [M.Fe.encoded_bytes]u8 = undefined;
    result.toBytes(&tmp, .big) catch return false;
    beBytesToQwArray(&tmp, output[0..byte_count]);
    return true;
}

fn bnQwBeBufSwap(data: []u8) void {
    std.debug.assert(data.len == 256);
    var left: usize = 0;
    var right: usize = 31;
    while (left < 16) : ({
        left += 1;
        right -= 1;
    }) {
        const a = endian.get64be(data, left * 8);
        const b = endian.get64be(data, right * 8);
        endian.set64be(data, left * 8, b);
        endian.set64be(data, right * 8, a);
    }
}

fn lessThanQwArray(a: *const [256]u8, b: []const u8) bool {
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        const av = endian.get64be(a, i * 8);
        const bv = endian.get64be(b, i * 8);
        if (av < bv) return true;
        if (av > bv) return false;
    }
    return false;
}

fn qwArrayToBeBytes(input: []const u8) [512]u8 {
    std.debug.assert(input.len <= 512);
    var out: [512]u8 = @splat(0);
    const count = input.len / 8;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        @memcpy(out[512 - (i + 1) * 8 ..][0..8], input[i * 8 ..][0..8]);
    }
    return out;
}

fn beBytesToQwArray(input: []const u8, output: []u8) void {
    std.debug.assert(input.len == 512);
    const count = output.len / 8;
    var i: usize = 0;
    while (i < count) : (i += 1) {
        @memcpy(output[i * 8 ..][0..8], input[512 - (i + 1) * 8 ..][0..8]);
    }
}

test "XeCrypt SHA-1 matches NIST vector" {
    var out: [20]u8 = undefined;
    XeCryptSha("abc", "", "", &out, 20);
    try std.testing.expectEqualSlices(u8, &.{
        0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E,
        0x25, 0x71, 0x78, 0x50, 0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D,
    }, &out);
}

test "XeCrypt HMAC-SHA1 matches RFC 2202 vector 1" {
    const key: [20]u8 = @splat(0x0B);
    var out: [20]u8 = undefined;
    XeCryptHmacSha(&key, "Hi There", "", "", &out, 20);
    try std.testing.expectEqualSlices(u8, &.{
        0xB6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xE2, 0x8B,
        0xC0, 0xB6, 0xFB, 0x37, 0x8C, 0x8E, 0xF1, 0x46, 0xBE, 0x00,
    }, &out);
}

test "XeCrypt AES-128 ECB matches FIPS-197 vector" {
    var state: AesState = undefined;
    XeCryptAesKey(&state, &.{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F });
    var out: [16]u8 = undefined;
    XeCryptAesEcb(&state, &.{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, &out, true);
    try std.testing.expectEqualSlices(u8, &.{ 0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A }, &out);
}

test "XeCrypt AES-128 CBC round-trips and updates the IV" {
    var state: AesState = undefined;
    XeCryptAesKey(&state, &.{ 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C });
    const plain: [32]u8 = @splat(0);
    var cipher: [32]u8 = undefined;
    var iv_enc: [16]u8 = @splat(0);
    XeCryptAesCbc(&state, &plain, &cipher, &iv_enc, true);
    var iv_dec: [16]u8 = @splat(0);
    var roundtrip: [32]u8 = undefined;
    XeCryptAesCbc(&state, &cipher, &roundtrip, &iv_dec, false);
    try std.testing.expectEqualSlices(u8, &plain, &roundtrip);
    try std.testing.expectEqualSlices(u8, cipher[16..32], &iv_enc);
    try std.testing.expectEqualSlices(u8, cipher[16..32], &iv_dec);
}

test "XeCrypt signature format matches reference output" {
    var hash: [20]u8 = undefined;
    for (&hash, 0..) |*byte, i| byte.* = @intCast(i);
    var salt: [10]u8 = undefined;
    for (&salt, 0..) |*byte, i| byte.* = @intCast(0xA0 + i);

    var signature: Signature = undefined;
    XeCryptBnQwBeSigFormat(&signature, &hash, &salt);
    try std.testing.expectEqualSlices(u8, &.{
        0xD9, 0x33, 0x5D, 0xF6, 0x51, 0x21, 0xE2, 0xBC, 0x83, 0x4A, 0xAF, 0x41, 0x0A, 0x8F, 0x50, 0x59,
        0x8E, 0x59, 0xE5, 0x3B, 0x5C, 0xC4, 0x65, 0x23, 0x80, 0x38, 0x85, 0x0F, 0x3B, 0xEF, 0xDC, 0x90,
    }, signature[0..32]);
}

test "XeCrypt modular exponentiation uses least-significant qword first" {
    var base: [8]u8 = @splat(0);
    var exponent: [8]u8 = @splat(0);
    var modulus: [8]u8 = @splat(0);
    var result: [8]u8 = @splat(0);
    endian.set64be(&base, 0, 2);
    endian.set64be(&exponent, 0, 5);
    endian.set64be(&modulus, 0, 13);

    try std.testing.expect(XeCryptBnQwNeModExp(&result, &base, &exponent, &modulus, 1));
    try std.testing.expectEqual(@as(u64, 6), endian.get64be(&result, 0));
}

test "XeCrypt RotSumSha matches reference output" {
    const input = "0123456789ABCDEF0123456789ABCDEF";
    var out: [20]u8 = undefined;
    XeCryptRotSumSha(input, "", &out, 20);
    try std.testing.expectEqualSlices(u8, &.{
        0xD3, 0x6A, 0x5C, 0x8A, 0xA8, 0x01, 0x62, 0x52, 0xA8, 0x8E,
        0xC5, 0x63, 0xED, 0x30, 0x5B, 0x3F, 0x61, 0x25, 0xB5, 0x8A,
    }, &out);
}
