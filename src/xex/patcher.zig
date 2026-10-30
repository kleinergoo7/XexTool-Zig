// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Port of XexTool/src/XexPatcher.cpp: rebuild a target XEX from a source XEX
// and its delta patch module. The patch carries a set of delta blocks; each
// block either zeroes, copies or LZX-decompresses data over a window seeded
// with the region it replaces.

const std = @import("std");
const DataBlock = @import("../core/datablock.zig").DataBlock;
const endian = @import("../core/endian.zig");
const crypto = @import("../xecrypt/xecrypt.zig");
const XexLzx = @import("../lzx/XexLzx.zig");
const header = @import("header.zig");
const model = @import("model.zig");

pub const Error = header.Error || error{
    NotAPatchModule,
    SourceIsPatchModule,
    IncorrectPatch,
    InvalidPatchDescriptor,
    InvalidPatchData,
    InvalidTargetImageSize,
    CorruptedPatchBlock,
    DeltaDecompressFailed,
    TargetSmallerThanSource,
    WriteFailed,
};

/// `offsetof(XexImageHeader, securityInfoOffset)`.
const image_header_security_offset = 0x10;
/// `offsetof(XexSecurityInfo, imageInfo)`.
const security_info_image_info = 0x08;
/// `offsetof(XexHvImageInfo, signature)`; the signature is the first field.
const hv_image_info_signature = 0x00;
const signature_size = 0x100;

/// `DeltaPatchDescriptor`, XexImageEntryTypes.h. The IMAGEKEY_DELTA_PATCH_DESCRIPTOR
/// entry holds these big-endian bytes; XexHeader.cpp converts the s32 fields to
/// host order while header.zig keeps the raw entry, so read them with get32be.
const delta_patch_descriptor = struct {
    const info_size = 0x00;
    const target_version = 0x04;
    const source_version = 0x08;
    const source_hash = 0x0C;
    const image_key_source = 0x20;
    const target_header_size = 0x30;
    const delta_header_source_offset = 0x34;
    const delta_header_source_size = 0x38;
    const delta_header_target_offset = 0x3C;
    const delta_image_source_offset = 0x40;
    const delta_image_source_size = 0x44;
    const delta_image_target_offset = 0x48;
    const patch_data = 0x4C;
};

/// `DeltaBlock`, XexPatcher.cpp: 4+4+2+2 bytes, no padding.
const DeltaBlock = struct {
    const size = 12;
    const src = 0x00;
    const dest = 0x04;
    const decomp_size = 0x08;
    const comp_size = 0x0A;
};

/// `CompBaseFileBlock`, XexImageEntryTypes.h.
const comp_base_file_block = struct {
    const size = 24;
    const data_size = 0x00;
    const hash = 0x04;
};

/// `CompBaseFileInfo`: the fields header.zig already converted to host order.
const comp_base_file_info = struct {
    const enc_type = 0x04;
    const comp_type = 0x06;
    const window_size = 0x08;
    const data_size = 0x0C;
    const hash = 0x10;
};

const headers_window_size: i32 = 0x8000;

/// Checks whether `patch_xex` patches `source`. Mirrors XexPatcher::isCorrectPatch:
/// the descriptor's source hash is SHA-1 over the 0x100-byte signature of the
/// source headers, and the descriptor must be present.
pub fn isCorrectPatch(source: *const model.Xex, patch_xex: *const model.Xex) bool {
    const headers = &source.original_headers;
    // XexSecurityInfo.imageInfo precedes the signature; a short header block
    // zero-fills exactly like DataBlock::get in the reference.
    const sec_offset: i32 = @bitCast(headers.get32be(image_header_security_offset));
    const sig_offset = sec_offset +% (security_info_image_info + hv_image_info_signature);

    var source_sig: [signature_size]u8 = @splat(0);
    headers.get(&source_sig, sig_offset, signature_size) catch |err| switch (err) {
        error.InvalidRange => return false,
        error.OutOfMemory => unreachable, // DataBlock.get does not allocate
    };

    const descriptor = patch_xex.delta_patch_descriptor orelse return false;

    var patch_hash: [20]u8 = undefined;
    descriptor.get(&patch_hash, delta_patch_descriptor.source_hash, 20) catch |err| switch (err) {
        error.InvalidRange => return false,
        error.OutOfMemory => unreachable, // DataBlock.get does not allocate
    };

    var source_hash: [20]u8 = undefined;
    crypto.XeCryptSha(&source_sig, "", "", &source_hash, 20);
    return std.mem.eql(u8, &source_hash, &patch_hash);
}

/// Builds the patched XEX. The caller owns the returned model and must
/// `deinit` it. `out` receives the same messages XexPatcher.cpp prints.
pub fn patch(
    gpa: std.mem.Allocator,
    source: *const model.Xex,
    patch_xex: *const model.Xex,
    out: anytype,
) Error!model.Xex {
    if (!patch_xex.isPatchModule()) return error.NotAPatchModule;
    if (source.isPatchModule()) return error.SourceIsPatchModule;
    if (!isCorrectPatch(source, patch_xex)) return error.IncorrectPatch;

    var output = model.Xex.init(gpa);
    errdefer output.deinit();

    const descriptor = patch_xex.delta_patch_descriptor orelse return error.InvalidPatchDescriptor;

    // Rebuild the headers: seed the target from the source headers, then
    // apply the descriptor's delta blocks.
    var headers_target = DataBlock.init();
    defer headers_target.deinit(gpa);
    try unpackDeltaHeaders(gpa, &headers_target, &source.original_headers, &descriptor);

    const target_image_size = try header.readHeaders(&output, headers_target);
    if (target_image_size < 0) return error.InvalidTargetImageSize;

    // The patch image key is encrypted with the (already decrypted) target key.
    const target_key = output.image_key;
    var patch_key = patch_xex.image_key;
    var aes: crypto.AesState = undefined;
    crypto.XeCryptAesKey(&aes, &target_key.data);
    var decrypted_key: [16]u8 = undefined;
    crypto.XeCryptAesEcb(&aes, &patch_key.data, &decrypted_key, false);
    patch_key.data = decrypted_key;

    var basefile_target = DataBlock.init();
    defer basefile_target.deinit(gpa);
    try unpackDeltaBasefile(
        gpa,
        &basefile_target,
        target_image_size,
        &source.basefile,
        &patch_xex.patch_data,
        &patch_xex.patch_info,
        &patch_key.data,
        out,
    );

    output.basefile.deinit(gpa);
    output.basefile = basefile_target;
    basefile_target = .{};
    return output;
}

/// Applies one delta block stream in place. Returns false for a malformed
/// stream, matching the reference's bool result (the caller reports it).
fn deltaDecompress(
    gpa: std.mem.Allocator,
    window_size: i32,
    output: *DataBlock,
    input: []const u8,
) Error!bool {
    // The reference casts to u32; an invalid window makes XexLzxCreate fail,
    // exactly as lzx_create_decompression_window returns NULL.
    const window: u32 = @bitCast(window_size);
    const output_size = output.size();
    var rest = input;

    while (rest.len != 0) {
        if (rest.len < DeltaBlock.size) return false;

        const src: i32 = @bitCast(endian.get32be(rest, DeltaBlock.src));
        const dest: i32 = @bitCast(endian.get32be(rest, DeltaBlock.dest));
        const decomp_size: i32 = endian.get16be(rest, DeltaBlock.decomp_size);
        const comp_size: i32 = endian.get16be(rest, DeltaBlock.comp_size);
        rest = rest[DeltaBlock.size..];

        // A zero decompressed size terminates the stream.
        if (decomp_size == 0) break;
        // Negative offsets are malformed where the reference would wrap.
        if (src < 0 or dest < 0) return false;
        if (src > output_size or
            decomp_size > output_size - src or
            dest >= output_size or
            decomp_size > output_size - dest)
        {
            return false;
        }

        if (comp_size == 0) {
            try output.fill(gpa, 0, dest, decomp_size);
        } else if (comp_size == 1) {
            if (src != dest) try output.setBlock(gpa, output, src, dest, decomp_size);
        } else {
            // Check the compressed length before decoding so truncated input
            // fails the same way the post-decode check did.
            if (@as(usize, @intCast(comp_size)) > rest.len) return false;
            const chunk = rest[0..@intCast(comp_size)];
            rest = rest[@intCast(comp_size)..];

            const size: usize = @intCast(decomp_size); // decomp_size > 0, bounded above
            const reference = try gpa.alloc(u8, size);
            defer gpa.free(reference);
            try output.get(reference, src, decomp_size);

            const data = try gpa.alloc(u8, size);
            defer gpa.free(data);

            const decoder = XexLzx.XexLzxCreate(gpa, window) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return false,
            };
            defer XexLzx.XexLzxDestroy(decoder);

            XexLzx.XexLzxSeedWindow(decoder, reference) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return false,
            };
            XexLzx.XexLzxDecodeChunk(decoder, chunk, data) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return false,
            };
            try output.set(gpa, data, dest, decomp_size);
        }
    }

    return true;
}

/// Seeds the target headers from the source headers, then applies the
/// descriptor's delta blocks. XexPatcher::unpackDeltaHeaders.
fn unpackDeltaHeaders(
    gpa: std.mem.Allocator,
    headers_target: *DataBlock,
    headers_source: *const DataBlock,
    patch_info: *const DataBlock,
) Error!void {
    const info = patch_info.data();
    if (info.len < delta_patch_descriptor.patch_data) return error.InvalidPatchDescriptor;

    const info_size: i32 = @bitCast(endian.get32be(info, delta_patch_descriptor.info_size));
    const target_header_size: i32 = @bitCast(endian.get32be(info, delta_patch_descriptor.target_header_size));
    const source_offset: i32 = @bitCast(endian.get32be(info, delta_patch_descriptor.delta_header_source_offset));
    const source_size: i32 = @bitCast(endian.get32be(info, delta_patch_descriptor.delta_header_source_size));
    const target_offset: i32 = @bitCast(endian.get32be(info, delta_patch_descriptor.delta_header_target_offset));

    if (target_header_size < 0 or source_offset < 0 or source_size < 0 or target_offset < 0) {
        return error.InvalidPatchDescriptor;
    }

    // `(targetHeaderSize + 0xFFF) & 0xFFFFF000`: the target header block is
    // page aligned and zero filled before the source copy.
    const rounded = (@as(i64, target_header_size) + 0xFFF) & ~@as(i64, 0xFFF);
    if (rounded > std.math.maxInt(i32)) return error.InvalidPatchDescriptor;
    const dest_size: i32 = @intCast(rounded); // rounded <= maxInt(i32) checked above
    const dest_len: usize = @intCast(dest_size); // rounded >= 0

    const source_len: usize = @intCast(source_size); // non-negative checked above
    const target_off: usize = @intCast(target_offset);
    // The reference writes past its allocation here; reject the range instead.
    if (target_off > dest_len or source_len > dest_len - target_off) {
        return error.InvalidPatchDescriptor;
    }

    headers_target.clear(gpa);
    try headers_target.fill(gpa, 0, 0, dest_size);
    // DataBlock::get zero-fills a source read that runs past the header block.
    try headers_target.setBlock(gpa, headers_source, source_offset, target_offset, source_size);

    if (info_size < delta_patch_descriptor.patch_data) return error.InvalidPatchDescriptor;
    const patch_len: usize = @intCast(info_size - delta_patch_descriptor.patch_data); // info_size >= 0x4C
    if (patch_len > info.len - delta_patch_descriptor.patch_data) return error.InvalidPatchDescriptor;

    const patch_blocks = info[delta_patch_descriptor.patch_data..][0..patch_len];
    const decoded = try deltaDecompress(gpa, headers_window_size, headers_target, patch_blocks);
    if (!decoded) return error.DeltaDecompressFailed;
}

/// Builds the target basefile from the source image and the patch blocks.
/// XexPatcher::unpackDeltaBasefile; `out` receives its three printf lines.
fn unpackDeltaBasefile(
    gpa: std.mem.Allocator,
    basefile_target: *DataBlock,
    target_image_size: i32,
    basefile_source: *const DataBlock,
    basefile_patch: *const DataBlock,
    basefile_patch_info: *const DataBlock,
    dec_key: *const [16]u8,
    out: anytype,
) Error!void {
    if (target_image_size < 0) return error.InvalidTargetImageSize;

    // Delta basefiles are AES-CBC encrypted as one stream with a zero IV.
    var decrypted = DataBlock.init();
    defer decrypted.deinit(gpa);
    var patch_bytes = basefile_patch;
    if (basefile_patch_info.get16(comp_base_file_info.enc_type) == 1) {
        const size = basefile_patch.size();
        if (@mod(size, crypto.AesBlockSize) != 0) return error.InvalidPatchData;
        try decrypted.set(gpa, basefile_patch.data(), 0, size);
        var aes: crypto.AesState = undefined;
        crypto.XeCryptAesKey(&aes, dec_key);
        var ivec: [16]u8 = @splat(0);
        crypto.XeCryptAesCbc(&aes, decrypted.data(), decrypted.dataMut(), &ivec, false);
        patch_bytes = &decrypted;
    }

    // Keep the tail of the source image that the target still covers.
    const source_size = basefile_source.size();
    const offset64 = @as(i64, source_size) - target_image_size;
    const offset: i32 = if (offset64 < 0) 0 else @intCast(offset64); // <= source_size
    const copy_size = source_size - offset;
    basefile_target.clear(gpa);
    if (copy_size > 0) {
        try basefile_target.set(gpa, basefile_source.data()[@intCast(offset)..], 0, copy_size);
    }
    // A target taller than the source starts with zeroes.
    if (target_image_size > basefile_target.size()) {
        try basefile_target.fill(gpa, 0, basefile_target.size(), target_image_size - basefile_target.size());
    }

    const window_size: i32 = @bitCast(basefile_patch_info.get32(comp_base_file_info.window_size));
    var unpack_size: i32 = @bitCast(basefile_patch_info.get32(comp_base_file_info.data_size));
    var unpack_hash: [20]u8 = undefined;
    basefile_patch_info.get(&unpack_hash, comp_base_file_info.hash, 20) catch |err| switch (err) {
        error.InvalidRange => return error.InvalidPatchData,
        error.OutOfMemory => unreachable, // DataBlock.get does not allocate
    };

    var input_offset: i32 = 0;
    while (unpack_size != 0) {
        const block_size = unpack_size;
        if (block_size < 0) return error.InvalidPatchData;
        const block_len: usize = @intCast(block_size); // block_size >= 0

        const block_data = try gpa.alloc(u8, block_len);
        defer gpa.free(block_data);
        patch_bytes.get(block_data, input_offset, block_size) catch |err| switch (err) {
            error.InvalidRange => return error.InvalidPatchData,
            error.OutOfMemory => unreachable, // DataBlock.get does not allocate
        };

        const block_start = input_offset;
        input_offset +%= block_size;

        // Each block starts with the next block's size/hash and a SHA-1 over
        // the whole encrypted-or-plain block.
        var block_hash: [20]u8 = undefined;
        crypto.XeCryptSha(block_data, "", "", &block_hash, 20);
        if (!std.mem.eql(u8, &block_hash, &unpack_hash)) {
            out.print("Error patch file is corrupted for block 0x{X} - 0x{X} (0x{X})!\n", .{
                @as(u32, @bitCast(block_start)),
                @as(u32, @bitCast(input_offset)),
                @as(u32, @bitCast(block_size)),
            }) catch return error.WriteFailed;
            return error.CorruptedPatchBlock;
        }

        const comp_size = block_size - comp_base_file_block.size;
        var decoded = comp_size >= 0;
        if (decoded) {
            const blocks = block_data[comp_base_file_block.size..][0..@intCast(comp_size)];
            decoded = try deltaDecompress(gpa, window_size, basefile_target, blocks);
        }
        if (!decoded) {
            out.writeAll("Error doing delta decompress.\n") catch return error.WriteFailed;
            return error.DeltaDecompressFailed;
        }

        unpack_size = @bitCast(endian.get32be(block_data, comp_base_file_block.data_size));
        @memcpy(&unpack_hash, block_data[comp_base_file_block.hash..][0..20]);
    }

    // Unreachable for well-formed input: the delta blocks are bounded by the
    // initial target size. Kept for parity with the reference.
    if (basefile_target.size() > target_image_size) {
        basefile_target.truncate(target_image_size);
        out.writeAll("Patching error due to target file being smaller than the source file\n") catch return error.WriteFailed;
        return error.TargetSmallerThanSource;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const defines = @import("defines.zig");
const lzx = @import("../lzx/lzx.zig");

const test_zeros: [0x10]u8 = @splat(0);

test "delta block header has no padding" {
    try std.testing.expectEqual(@as(usize, 12), DeltaBlock.size);
}

fn setDeltaBlock(bytes: []u8, offset: usize, src: u32, dest: u32, decomp_size: u16, comp_size: u16) void {
    endian.set32be(bytes, offset + DeltaBlock.src, src);
    endian.set32be(bytes, offset + DeltaBlock.dest, dest);
    endian.set16be(bytes, offset + DeltaBlock.decomp_size, decomp_size);
    endian.set16be(bytes, offset + DeltaBlock.comp_size, comp_size);
}

fn buildDescriptor(
    gpa: std.mem.Allocator,
    source_hash: [20]u8,
    target_header_size: i32,
    source_offset: i32,
    source_size: i32,
    target_offset: i32,
    delta_blocks: []const u8,
) !DataBlock {
    var descriptor = DataBlock.init();
    errdefer descriptor.deinit(gpa);

    const total: i32 = delta_patch_descriptor.patch_data + @as(i32, @intCast(delta_blocks.len));
    try descriptor.fill(gpa, 0, 0, total);
    const bytes = descriptor.dataMut();

    endian.set32be(bytes, delta_patch_descriptor.info_size, @bitCast(total));
    @memcpy(bytes[delta_patch_descriptor.source_hash..][0..20], &source_hash);
    endian.set32be(bytes, delta_patch_descriptor.target_header_size, @bitCast(target_header_size));
    endian.set32be(bytes, delta_patch_descriptor.delta_header_source_offset, @bitCast(source_offset));
    endian.set32be(bytes, delta_patch_descriptor.delta_header_source_size, @bitCast(source_size));
    endian.set32be(bytes, delta_patch_descriptor.delta_header_target_offset, @bitCast(target_offset));
    @memcpy(bytes[delta_patch_descriptor.patch_data..][0..delta_blocks.len], delta_blocks);
    return descriptor;
}

test "isCorrectPatch compares the SHA-1 of the source signature" {
    const gpa = std.testing.allocator;

    var headers: [0x300]u8 = @splat(0);
    endian.set32be(&headers, image_header_security_offset, 0x100);
    for (headers[0x108..0x208], 0..) |*byte, index| byte.* = @truncate(index *% 7 + 1);

    var source = model.Xex.init(gpa);
    defer source.deinit();
    try source.original_headers.set(gpa, &headers, 0, headers.len);

    var patch_xex = model.Xex.init(gpa);
    defer patch_xex.deinit();

    var digest: [20]u8 = undefined;
    crypto.XeCryptSha(headers[0x108..0x208], "", "", &digest, 20);
    var descriptor = try buildDescriptor(gpa, digest, 0, 0, 0, 0, "");
    defer descriptor.deinit(gpa);
    patch_xex.delta_patch_descriptor = try descriptor.clone(gpa);

    try std.testing.expect(isCorrectPatch(&source, &patch_xex));

    // One flipped signature byte must invalidate the descriptor.
    headers[0x108] ^= 0xFF;
    try source.original_headers.set(gpa, &headers, 0, headers.len);
    try std.testing.expect(!isCorrectPatch(&source, &patch_xex));

    patch_xex.delta_patch_descriptor.?.deinit(gpa);
    patch_xex.delta_patch_descriptor = null;
    try std.testing.expect(!isCorrectPatch(&source, &patch_xex));
}

test "deltaDecompress fills zeros, copies and rejects out-of-range blocks" {
    const gpa = std.testing.allocator;

    var seed: [0x40]u8 = undefined;
    for (&seed, 0..) |*byte, index| byte.* = @truncate(index *% 3 + 1);

    var output = DataBlock.init();
    defer output.deinit(gpa);
    try output.set(gpa, &seed, 0, seed.len);

    var input: [3 * DeltaBlock.size]u8 = @splat(0);
    setDeltaBlock(&input, 0, 0, 0x10, 8, 1);
    setDeltaBlock(&input, DeltaBlock.size, 0, 0x20, 0x10, 0);
    setDeltaBlock(&input, 2 * DeltaBlock.size, 0, 0, 0, 0);
    try std.testing.expect(try deltaDecompress(gpa, 0x8000, &output, &input));
    try std.testing.expectEqualSlices(u8, seed[0..8], output.data()[0x10..0x18]);
    try std.testing.expectEqualSlices(u8, &test_zeros, output.data()[0x20..0x30]);

    // Overlapping copy reads through a temporary, like the reference.
    var overlap = DataBlock.init();
    defer overlap.deinit(gpa);
    try overlap.set(gpa, &seed, 0, seed.len);
    var copy: [2 * DeltaBlock.size]u8 = @splat(0);
    setDeltaBlock(&copy, 0, 0, 4, 8, 1);
    setDeltaBlock(&copy, DeltaBlock.size, 0, 0, 0, 0);
    try std.testing.expect(try deltaDecompress(gpa, 0x8000, &overlap, &copy));
    // out[4..12] receives the original out[0..8], so the first half is untouched.
    try std.testing.expectEqualSlices(u8, seed[0..4], overlap.data()[0..4]);
    try std.testing.expectEqualSlices(u8, seed[0..8], overlap.data()[4..12]);

    // destination at the end, too much output, source past the end, truncation.
    var bad: [DeltaBlock.size + 1]u8 = @splat(0);
    setDeltaBlock(&bad, 0, 0, 0x40, 1, 0);
    try std.testing.expect(!(try deltaDecompress(gpa, 0x8000, &output, &bad)));
    setDeltaBlock(&bad, 0, 0, 0, 0x41, 0);
    try std.testing.expect(!(try deltaDecompress(gpa, 0x8000, &output, &bad)));
    setDeltaBlock(&bad, 0, 0x41, 0, 1, 0);
    try std.testing.expect(!(try deltaDecompress(gpa, 0x8000, &output, &bad)));
    try std.testing.expect(!(try deltaDecompress(gpa, 0x8000, &output, bad[0..8])));
    setDeltaBlock(&bad, 0, 0, 0, 1, 2);
    try std.testing.expect(!(try deltaDecompress(gpa, 0x8000, &output, bad[0 .. DeltaBlock.size + 1])));
}

test "deltaDecompress decodes an LZX block over the seeded window" {
    const gpa = std.testing.allocator;

    const seed = "seeded window bytes, seeded window bytes";
    const payload = "lzx delta payload, lzx delta payload, lzx delta payload";

    const dest = try gpa.alloc(u8, lzx.worstCaseCompressedSize(payload.len));
    defer gpa.free(dest);
    const framed = try lzx.compress(gpa, dest, payload, 0x8000);
    const compressed = std.mem.readInt(u16, framed[0..2], .little);
    // The payload is shorter than one chunk, so the stream has one frame.
    try std.testing.expectEqual(@as(usize, 4 + compressed), framed.len);

    var output = DataBlock.init();
    defer output.deinit(gpa);
    try output.fill(gpa, 0, 0, 0x100);
    try output.set(gpa, seed, 0, seed.len);

    const block_len = DeltaBlock.size + compressed;
    const block = try gpa.alloc(u8, block_len);
    defer gpa.free(block);
    setDeltaBlock(block, 0, 0, 0x80, @intCast(payload.len), @intCast(compressed));
    @memcpy(block[DeltaBlock.size..], framed[4..][0..compressed]);

    try std.testing.expect(try deltaDecompress(gpa, 0x8000, &output, block));
    try std.testing.expectEqualSlices(u8, payload, output.data()[0x80..][0..payload.len]);
}

test "unpackDeltaHeaders seeds from the source and applies blocks" {
    const gpa = std.testing.allocator;

    var source_bytes: [0x40]u8 = undefined;
    for (&source_bytes, 0..) |*byte, index| byte.* = @truncate(index *% 5 + 0x10);
    var source = DataBlock.init();
    defer source.deinit(gpa);
    try source.set(gpa, &source_bytes, 0, source_bytes.len);

    var blocks: [2 * DeltaBlock.size]u8 = @splat(0);
    setDeltaBlock(&blocks, 0, 0x10, 0, 8, 1);
    setDeltaBlock(&blocks, DeltaBlock.size, 0, 0, 0, 0);

    var descriptor = try buildDescriptor(gpa, @splat(0), 0x100, 0, 0x20, 0x10, &blocks);
    defer descriptor.deinit(gpa);

    var target = DataBlock.init();
    defer target.deinit(gpa);
    try unpackDeltaHeaders(gpa, &target, &source, &descriptor);

    // targetHeaderSize is rounded up to the 0x1000 page boundary.
    try std.testing.expectEqual(@as(i32, 0x1000), target.size());
    try std.testing.expectEqualSlices(u8, source_bytes[0..0x20], target.data()[0x10..0x30]);
    // The delta block copies the seeded region back over the start.
    try std.testing.expectEqualSlices(u8, source_bytes[0..8], target.data()[0..8]);
    try std.testing.expectEqual(@as(u8, 0), target.data()[0x30]);

    // A block outside the target block fails the header decode.
    var bad_blocks: [2 * DeltaBlock.size]u8 = @splat(0);
    setDeltaBlock(&bad_blocks, 0, 0, 0x1000, 1, 0);
    setDeltaBlock(&bad_blocks, DeltaBlock.size, 0, 0, 0, 0);
    var bad_descriptor = try buildDescriptor(gpa, @splat(0), 0x100, 0, 0x20, 0x10, &bad_blocks);
    defer bad_descriptor.deinit(gpa);
    try std.testing.expectError(error.DeltaDecompressFailed, unpackDeltaHeaders(gpa, &target, &source, &bad_descriptor));

    // Short descriptors are rejected instead of reading past the block.
    var truncated = DataBlock.init();
    defer truncated.deinit(gpa);
    try truncated.fill(gpa, 0, 0, 0x20);
    try std.testing.expectError(error.InvalidPatchDescriptor, unpackDeltaHeaders(gpa, &target, &source, &truncated));
}

test "unpackDeltaBasefile reports a corrupted block" {
    const gpa = std.testing.allocator;

    var source = DataBlock.init();
    defer source.deinit(gpa);
    var patch_block = DataBlock.init();
    defer patch_block.deinit(gpa);
    var info = DataBlock.init();
    defer info.deinit(gpa);
    var target = DataBlock.init();
    defer target.deinit(gpa);

    try patch_block.fill(gpa, 0, 0, comp_base_file_block.size);
    try info.fill(gpa, 0, 0, 0x24);
    try info.set32(gpa, comp_base_file_block.size, comp_base_file_info.data_size);
    // The info hash stays zero while the block hash cannot be, so the check fires.

    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    const key: [16]u8 = @splat(0);

    try std.testing.expectError(
        error.CorruptedPatchBlock,
        unpackDeltaBasefile(gpa, &target, 0x100, &source, &patch_block, &info, &key, &buffer.writer),
    );
    try std.testing.expectEqualStrings("Error patch file is corrupted for block 0x0 - 0x18 (0x18)!\n", buffer.written());
}

test "unpackDeltaBasefile reports a failed delta decode" {
    const gpa = std.testing.allocator;

    var source = DataBlock.init();
    defer source.deinit(gpa);
    var target = DataBlock.init();
    defer target.deinit(gpa);
    var info = DataBlock.init();
    defer info.deinit(gpa);

    // One block: 24-byte CompBaseFileBlock plus a block that writes past the end.
    var patch_block = DataBlock.init();
    defer patch_block.deinit(gpa);
    try patch_block.fill(gpa, 0, 0, comp_base_file_block.size + 2 * DeltaBlock.size);
    const bytes = patch_block.dataMut();
    endian.set32be(bytes, comp_base_file_block.data_size, 0);
    setDeltaBlock(bytes, comp_base_file_block.size, 0, 0x100, 1, 0);
    setDeltaBlock(bytes, comp_base_file_block.size + DeltaBlock.size, 0, 0, 0, 0);

    var digest: [20]u8 = undefined;
    crypto.XeCryptSha(bytes, "", "", &digest, 20);

    try info.fill(gpa, 0, 0, 0x24);
    try info.set32(gpa, @bitCast(patch_block.size()), comp_base_file_info.data_size);
    try info.set(gpa, &digest, comp_base_file_info.hash, 20);

    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();
    const key: [16]u8 = @splat(0);

    try std.testing.expectError(
        error.DeltaDecompressFailed,
        unpackDeltaBasefile(gpa, &target, 0x100, &source, &patch_block, &info, &key, &buffer.writer),
    );
    try std.testing.expectEqualStrings("Error doing delta decompress.\n", buffer.written());
}

fn encryptKey(key: [16]u8, plaintext: [16]u8) [16]u8 {
    var aes: crypto.AesState = undefined;
    crypto.XeCryptAesKey(&aes, &key);
    var output: [16]u8 = undefined;
    crypto.XeCryptAesEcb(&aes, &plaintext, &output, true);
    return output;
}

fn buildTestHeaders(stored_image_key: [16]u8) [0x298]u8 {
    var headers: [0x298]u8 = @splat(0);
    @memcpy(headers[0..4], &defines.xex_magic);
    endian.set32be(&headers, 0x04, defines.module_flag_title_module);
    endian.set32be(&headers, 0x08, 0x298);
    endian.set32be(&headers, 0x10, 0x100);
    endian.set32be(&headers, 0x14, 1);
    endian.set32be(&headers, 0x18, defines.image_key_basefile_format);
    endian.set32be(&headers, 0x1C, 0x80);
    endian.set32be(&headers, 0x80, 8);
    endian.set16be(&headers, 0x84, 0);
    endian.set16be(&headers, 0x86, 1);
    endian.set32be(&headers, 0x100, 0x184);
    endian.set32be(&headers, 0x104, 0x10000);
    // Non-zero garbage signature: retail verification fails, so the image key
    // is decrypted with the debug key.
    headers[0x108] = 0x5A;
    endian.set32be(&headers, 0x208, 0x174);
    endian.set32be(&headers, 0x20C, defines.image_flag_title_usermode);
    endian.set32be(&headers, 0x210, 0x82000000);
    @memcpy(headers[0x250..0x260], &stored_image_key);
    endian.set32be(&headers, 0x27C, defines.media_hard_disk);
    endian.set32be(&headers, 0x280, 1);
    endian.set32be(&headers, 0x284, (4 << 4) | defines.section_info_code);
    return headers;
}

test "unpackDeltaBasefile decrypts an AES-CBC patch stream" {
    const gpa = std.testing.allocator;

    const key: [16]u8 = .{ 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6 };
    var source_bytes: [0x20]u8 = undefined;
    for (&source_bytes, 0..) |*byte, index| byte.* = @truncate(index +% 0x40);

    var source = DataBlock.init();
    defer source.deinit(gpa);
    try source.set(gpa, &source_bytes, 0, source_bytes.len);

    var target = DataBlock.init();
    defer target.deinit(gpa);

    // Plaintext: one copy block inside the target and the terminator; the
    // trailing bytes keep the stream a whole number of AES blocks.
    var plain: [0x40]u8 = @splat(0);
    setDeltaBlock(&plain, comp_base_file_block.size, 0, 0x10, 0x10, 1);
    setDeltaBlock(&plain, comp_base_file_block.size + DeltaBlock.size, 0, 0, 0, 0);

    var digest: [20]u8 = undefined;
    crypto.XeCryptSha(&plain, "", "", &digest, 20);

    var aes: crypto.AesState = undefined;
    crypto.XeCryptAesKey(&aes, &key);
    var ivec: [16]u8 = @splat(0);
    var encrypted: [0x40]u8 = undefined;
    crypto.XeCryptAesCbc(&aes, &plain, &encrypted, &ivec, true);

    var patch_block = DataBlock.init();
    defer patch_block.deinit(gpa);
    try patch_block.set(gpa, &encrypted, 0, encrypted.len);

    var info = DataBlock.init();
    defer info.deinit(gpa);
    try info.fill(gpa, 0, 0, 0x24);
    try info.set16(gpa, 1, comp_base_file_info.enc_type);
    try info.set16(gpa, 3, comp_base_file_info.comp_type);
    try info.set32(gpa, 0x8000, comp_base_file_info.window_size);
    try info.set32(gpa, @bitCast(patch_block.size()), comp_base_file_info.data_size);
    try info.set(gpa, &digest, comp_base_file_info.hash, 20);

    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();

    try unpackDeltaBasefile(gpa, &target, 0x20, &source, &patch_block, &info, &key, &buffer.writer);
    try std.testing.expectEqualStrings("", buffer.written());
    try std.testing.expectEqual(@as(i32, 0x20), target.size());
    try std.testing.expectEqualSlices(u8, source_bytes[0..0x10], target.data()[0x10..0x20]);
}

test "patch rebuilds headers and basefile from a delta patch module" {
    const gpa = std.testing.allocator;

    const target_key_plain: [16]u8 = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    const patch_key_plain: [16]u8 = .{ 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

    const headers = buildTestHeaders(encryptKey(@import("data.zig").xex_debug_key, target_key_plain));

    var source = model.Xex.init(gpa);
    defer source.deinit();
    source.module_flags = defines.module_flag_title_module;
    try source.original_headers.set(gpa, &headers, 0, headers.len);

    var source_image: [0x100]u8 = undefined;
    for (&source_image, 0..) |*byte, index| byte.* = @truncate(index *% 11 + 3);
    try source.basefile.set(gpa, &source_image, 0, source_image.len);

    var patch_xex = model.Xex.init(gpa);
    defer patch_xex.deinit();
    patch_xex.module_flags = defines.module_flag_patch_module | defines.module_flag_patch_delta;
    patch_xex.image_key.data = encryptKey(target_key_plain, patch_key_plain);

    // Header patch: one copy inside the target header block.
    var header_blocks: [2 * DeltaBlock.size]u8 = @splat(0);
    setDeltaBlock(&header_blocks, 0, 0, 0x300, 8, 1);
    setDeltaBlock(&header_blocks, DeltaBlock.size, 0, 0, 0, 0);

    var header_digest: [20]u8 = undefined;
    crypto.XeCryptSha(headers[0x108..0x208], "", "", &header_digest, 20);
    var descriptor = try buildDescriptor(gpa, header_digest, 0x298, 0, headers.len, 0, &header_blocks);
    defer descriptor.deinit(gpa);
    patch_xex.delta_patch_descriptor = try descriptor.clone(gpa);

    // Basefile patch: copy source bytes to 0x200, zero 0x300..0x310.
    var basefile_blocks: [3 * DeltaBlock.size]u8 = @splat(0);
    setDeltaBlock(&basefile_blocks, 0, 0, 0x200, 0x20, 1);
    setDeltaBlock(&basefile_blocks, DeltaBlock.size, 0, 0x300, 0x10, 0);
    setDeltaBlock(&basefile_blocks, 2 * DeltaBlock.size, 0, 0, 0, 0);

    var patch_data = DataBlock.init();
    defer patch_data.deinit(gpa);
    try patch_data.fill(gpa, 0, 0, comp_base_file_block.size + basefile_blocks.len);
    const patch_bytes = patch_data.dataMut();
    endian.set32be(patch_bytes, comp_base_file_block.data_size, 0);
    @memcpy(patch_bytes[comp_base_file_block.size..], &basefile_blocks);

    var patch_digest: [20]u8 = undefined;
    crypto.XeCryptSha(patch_bytes, "", "", &patch_digest, 20);
    try patch_xex.patch_info.fill(gpa, 0, 0, 0x24);
    try patch_xex.patch_info.set32(gpa, 0x24, 0);
    try patch_xex.patch_info.set16(gpa, 0, comp_base_file_info.enc_type);
    try patch_xex.patch_info.set16(gpa, 3, comp_base_file_info.comp_type);
    try patch_xex.patch_info.set32(gpa, 0x8000, comp_base_file_info.window_size);
    try patch_xex.patch_info.set32(gpa, @bitCast(patch_data.size()), comp_base_file_info.data_size);
    try patch_xex.patch_info.set(gpa, &patch_digest, comp_base_file_info.hash, 20);
    patch_xex.patch_data = try patch_data.clone(gpa);

    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();

    var output = try patch(gpa, &source, &patch_xex, &buffer.writer);
    defer output.deinit();

    try std.testing.expectEqualStrings("", buffer.written());
    try std.testing.expectEqual(@as(i32, 0x10000), output.basefile.size());
    try std.testing.expectEqualSlices(u8, &source_image, output.basefile.data()[0..0x100]);
    try std.testing.expectEqual(@as(u8, 0), output.basefile.data()[0x100]);
    try std.testing.expectEqualSlices(u8, source_image[0..0x20], output.basefile.data()[0x200..0x220]);
    try std.testing.expectEqualSlices(u8, &test_zeros, output.basefile.data()[0x300..0x310]);

    // readHeaders stores the whole page-aligned block it parsed.
    try std.testing.expectEqual(@as(i32, 0x1000), output.original_headers.size());
    try std.testing.expectEqualSlices(u8, &headers, output.original_headers.data()[0..headers.len]);
    try std.testing.expectEqual(@as(u8, 0), output.original_headers.data()[0x400]);
    try std.testing.expectEqual(defines.module_flag_title_module, output.module_flags);
    try std.testing.expectEqual(@as(usize, 1), output.sections.items.len);
}

test "patch rejects non-patch inputs and a wrong source hash" {
    const gpa = std.testing.allocator;

    var source = model.Xex.init(gpa);
    defer source.deinit();
    var patch_xex = model.Xex.init(gpa);
    defer patch_xex.deinit();

    var buffer: std.Io.Writer.Allocating = .init(gpa);
    defer buffer.deinit();

    try std.testing.expectError(error.NotAPatchModule, patch(gpa, &source, &patch_xex, &buffer.writer));

    patch_xex.module_flags = defines.module_flag_patch_module | defines.module_flag_patch_delta;
    source.module_flags = defines.module_flag_patch_module;
    try std.testing.expectError(error.SourceIsPatchModule, patch(gpa, &source, &patch_xex, &buffer.writer));

    source.module_flags = defines.module_flag_title_module;
    try std.testing.expectError(error.IncorrectPatch, patch(gpa, &source, &patch_xex, &buffer.writer));

    var headers: [0x300]u8 = @splat(0);
    endian.set32be(&headers, image_header_security_offset, 0x100);
    headers[0x108] = 0x11;
    try source.original_headers.set(gpa, &headers, 0, headers.len);
    var descriptor = try buildDescriptor(gpa, @splat(0), 0, 0, 0, 0, "");
    defer descriptor.deinit(gpa);
    patch_xex.delta_patch_descriptor = try descriptor.clone(gpa);
    try std.testing.expectError(error.IncorrectPatch, patch(gpa, &source, &patch_xex, &buffer.writer));
    try std.testing.expectEqualStrings("", buffer.written());
}
