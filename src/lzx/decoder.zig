// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// LZX decoder, transliterated from
// XexTool/third_party/libLZX/lzx/lzx_decoder.c. The bit reader keeps the
// C macros' fill rules: FILL_BUF_NOEOFCHECK reads one 16 bit word when the
// counter drops to zero or below, the checked fill_buf checks the end pointer
// first and sets error_condition instead of reading past the input.

const std = @import("std");
const c = @import("common.zig");

const Error = c.Error;

const dec_state_new_block: u8 = 1;
const dec_state_decoding: u8 = 2;

// Bit positions derived from the C macros: 32 - table bits.
const main_tree_shift: u5 = 32 - 10; // MAIN_TREE_TABLE_BITS
const main_tree_mask_shift: u5 = 32 - 1 - 10;
const small_tree_shift: u5 = 32 - 8; // DS_TABLE_BITS
const small_tree_mask_shift: u5 = 32 - 1 - 8;
const secondary_shift: u5 = 32 - 8; // SECONDARY_LEN_TREE_TABLE_BITS
const secondary_mask_shift: u5 = 32 - 1 - 8;
const aligned_tree_shift: u5 = 32 - 7; // LZX_ALIGNED_TABLE_BITS

const tree_enc_rep_min: u32 = 4;
const tree_enc_rep_first_extra_bits: u5 = 4;
const tree_enc_rep_second_extra_bits: u5 = 5;
const tree_enc_rep_zero_first: u32 = 16;
const tree_enc_rep_same_extra_bits: u5 = 1;

/// Extra bytes kept after the copied input so the unchecked bit fills can
/// read a word past end_input_pos the way the C code reads malloc slack.
const input_slack = 64;

pub const Decoder = struct {
    allocator: std.mem.Allocator,
    /// window_size + LZX_MAX_MATCH + 4 bytes; the tail is the copy the C code
    /// uses for the first 257 bytes of a block (see decode_*_block_special).
    mem_window: []u8,
    input_buffer: []u8,
    window_size: u32,
    window_mask: u32,
    last_matchpos_offset: [c.num_repeated_offsets]u32,
    main_tree_table: [1 << c.main_tree_table_bits]i16,
    secondary_len_tree_table: [1 << c.secondary_len_tree_table_bits]i16,
    main_tree_len: [c.max_main_tree_elements]u8,
    secondary_len_tree_len: [c.num_secondary_len]u8,
    num_position_slots: u32,
    aligned_table: [1 << c.aligned_table_bits]u8,
    aligned_len: [c.aligned_num_elements]u8,
    main_tree_left_right: [c.max_main_tree_elements * 4]i16,
    secondary_len_tree_left_right: [c.num_secondary_len * 4]i16,
    input_curpos: usize,
    end_input_pos: usize,
    output_buffer: ?[]u8,
    position_at_start: i64,
    main_tree_prev_len: [c.max_main_tree_elements]u8,
    secondary_len_tree_prev_len: [c.num_secondary_len]u8,
    bitcount: i8,
    first_time_this_group: bool,
    error_condition: bool,
    bitbuf: u32,
    pos: u32,
    current_file_size: u32,
    instr_pos: u32,
    num_cfdata_frames: u32,
    original_block_size: i64,
    block_size: i64,
    block_type: u32,
    decoder_state: u8,
};

/// lzx_create_decompression_window.
pub fn createDecompressionWindow(allocator: std.mem.Allocator, size: u32) Error!*Decoder {
    if (!c.isValidWindowSize(size)) return error.LzxInvalidData;

    const self = try allocator.create(Decoder);
    errdefer allocator.destroy(self);

    const mem_window = try allocator.alloc(u8, size + c.max_match + 4);
    errdefer allocator.free(mem_window);

    const input_buffer = try allocator.alloc(u8, c.output_size + input_slack);
    errdefer allocator.free(input_buffer);

    self.* = .{
        .allocator = allocator,
        .mem_window = mem_window,
        .input_buffer = input_buffer,
        .window_size = 0,
        .window_mask = 0,
        .last_matchpos_offset = .{ 1, 1, 1 },
        .main_tree_table = @splat(0),
        .secondary_len_tree_table = @splat(0),
        .main_tree_len = @splat(0),
        .secondary_len_tree_len = @splat(0),
        .num_position_slots = 0,
        .aligned_table = @splat(0),
        .aligned_len = @splat(0),
        .main_tree_left_right = @splat(0),
        .secondary_len_tree_left_right = @splat(0),
        .input_curpos = 0,
        .end_input_pos = 0,
        .output_buffer = null,
        .position_at_start = 0,
        .main_tree_prev_len = @splat(0),
        .secondary_len_tree_prev_len = @splat(0),
        .bitcount = 0,
        .first_time_this_group = true,
        .error_condition = false,
        .bitbuf = 0,
        .pos = 0,
        .current_file_size = 0,
        .instr_pos = 0,
        .num_cfdata_frames = 0,
        .original_block_size = 0,
        .block_size = 0,
        .block_type = @backingInt(c.BlockType.invalid),
        .decoder_state = dec_state_new_block,
    };
    initWindow(self, size);
    return self;
}

/// lzx_create_decompression: the default 128 KiB window.
pub fn createDecompression(allocator: std.mem.Allocator) Error!*Decoder {
    return createDecompressionWindow(allocator, c.window_size);
}

/// lzx_destroy_decompression.
pub fn destroyDecompression(self: *Decoder) void {
    const allocator = self.allocator;
    allocator.free(self.mem_window);
    allocator.free(self.input_buffer);
    allocator.destroy(self);
}

/// lzx_set_window_data: place the data at the end of the window so it reads as
/// the output immediately before position zero, and zero everything before it.
pub fn setWindowData(self: *Decoder, data: []const u8) Error!void {
    if (data.len > self.window_size) return error.LzxInvalidData;
    const tail = self.window_size - @as(u32, @intCast(data.len));
    @memcpy(self.mem_window[tail..self.window_size], data);
    @memset(self.mem_window[0..tail], 0);
}

/// lzx_decompress_block. `dest.len` is the expected uncompressed size, the
/// in/out `bytes_decompressed` of the C API. Returns the bytes produced.
pub fn decompressBlock(self: *Decoder, src: []const u8, dest: []u8) Error!u32 {
    if (src.len > c.output_size) return error.LzxBufferOverflow;
    if (dest.len > c.chunk_size) return error.LzxBufferOverflow;

    @memcpy(self.input_buffer[0..src.len], src);
    @memset(self.input_buffer[src.len .. src.len + input_slack], 0);

    self.input_curpos = 0;
    self.end_input_pos = src.len + 4;
    self.output_buffer = dest;

    initBitbuf(
        self,
    );

    const bytes_decoded = try decodeData(self, @intCast(dest.len));

    self.num_cfdata_frames +%= 1;
    self.position_at_start += bytes_decoded;
    return bytes_decoded;
}

/// Cumulative uncompressed bytes handed out by decompressBlock.
pub fn positionAtStart(self: *const Decoder) i64 {
    return self.position_at_start;
}

/// lzx_calc_decompress_size: sum the little-endian block headers.
pub fn calcDecompressSize(src: []const u8) Error!u32 {
    var offset: usize = 0;
    var total: u32 = 0;
    while (offset < src.len) {
        if (offset + 4 > src.len) return error.LzxInvalidData;
        const compressed = std.mem.readInt(u16, src[offset..][0..2], .little);
        const uncompressed = std.mem.readInt(u16, src[offset + 2 ..][0..2], .little);
        total +%= uncompressed;
        offset += 4;
        offset += compressed;
    }
    return total;
}

fn initWindow(self: *Decoder, size: u32) void {
    self.window_size = size;
    self.window_mask = size - 1;
    self.num_position_slots = 4;

    var pos_start: u32 = 4;
    while (true) {
        pos_start +%= @as(u32, 1) << @intCast(c.extra_bits[self.num_position_slots]);
        self.num_position_slots += 1;
        if (pos_start >= self.window_size) break;
    }

    @memset(self.mem_window, 0);
    @memset(self.main_tree_len[0..c.mainTreeElements(self.num_position_slots)], 0);
    @memset(self.main_tree_prev_len[0..c.mainTreeElements(self.num_position_slots)], 0);
    @memset(self.secondary_len_tree_len[0..c.num_secondary_len], 0);
    @memset(self.secondary_len_tree_prev_len[0..c.num_secondary_len], 0);

    self.last_matchpos_offset = .{ 1, 1, 1 };
    self.pos = 0;
    self.position_at_start = 0;
    self.decoder_state = dec_state_new_block;
    self.block_size = 0;
    self.block_type = @backingInt(c.BlockType.invalid);
    self.first_time_this_group = true;
    self.current_file_size = 0;
    self.error_condition = false;
    self.instr_pos = 0;
    self.num_cfdata_frames = 0;
    self.bitcount = 0;
    self.bitbuf = 0;
}

// --- bit input -----------------------------------------------------------

inline fn readWord(self: *Decoder) u32 {
    const i = self.input_curpos;
    // input_buffer has input_slack zero bytes past any valid stream, so the
    // unchecked fills can always read two bytes here.
    std.debug.assert(i + 1 < self.input_buffer.len);
    return @as(u32, self.input_buffer[i]) | (@as(u32, self.input_buffer[i + 1]) << 8);
}

/// FILL_BUF_NOEOFCHECK body: shift in one word when the counter is used up.
inline fn fillRaw(self: *Decoder) void {
    const shift: u5 = @intCast(-self.bitcount);
    self.bitbuf |= readWord(
        self,
    ) << shift;
    self.input_curpos += 2;
    self.bitcount += 16;
}

inline fn fillRaw17(self: *Decoder) void {
    fillRaw(
        self,
    );
    if (self.bitcount <= 0) fillRaw(
        self,
    );
}

inline fn fillBufNoEof(self: *Decoder, n: u5) void {
    self.bitbuf <<= n;
    self.bitcount -= @as(i8, @intCast(n));
    if (self.bitcount <= 0) fillRaw(
        self,
    );
}

inline fn fillBuf17NoEof(self: *Decoder, n: u5) void {
    self.bitbuf <<= n;
    self.bitcount -= @as(i8, @intCast(n));
    if (self.bitcount <= 0) fillRaw17(
        self,
    );
}

/// fill_bitbuf: the checked variant used by getBits and decodeSmall.
fn fillBuf(self: *Decoder, n: u5) void {
    self.bitbuf <<= n;
    self.bitcount -= @as(i8, @intCast(n));
    if (self.bitcount <= 0) {
        if (self.input_curpos >= self.end_input_pos) {
            self.error_condition = true;
            return;
        }
        fillRaw(
            self,
        );
        if (self.bitcount <= 0) {
            if (self.input_curpos >= self.end_input_pos) {
                self.error_condition = true;
                return;
            }
            fillRaw(
                self,
            );
        }
    }
}

/// GET_BITS_NOEOFCHECK.
inline fn getBitsNoEof(self: *Decoder, n: u5) u32 {
    std.debug.assert(n != 0);
    const value = self.bitbuf >> @intCast(32 - @as(u6, n));
    fillBufNoEof(self, n);
    return value;
}

/// GET_BITS17_NOEOFCHECK.
inline fn getBits17NoEof(self: *Decoder, n: u5) u32 {
    std.debug.assert(n != 0);
    const value = self.bitbuf >> @intCast(32 - @as(u6, n));
    fillBuf17NoEof(self, n);
    return value;
}

/// get_bits.
fn getBits(self: *Decoder, n: u5) u32 {
    std.debug.assert(n != 0);
    const value = self.bitbuf >> @intCast(32 - @as(u6, n));
    fillBuf(self, n);
    return value;
}

fn getBitsChecked(self: *Decoder, n: u5) Error!u32 {
    const value = getBits(self, n);
    if (self.error_condition) return error.LzxFailed;
    return value;
}

/// init_bitbuf.
fn initBitbuf(self: *Decoder) void {
    if (self.block_type == @backingInt(c.BlockType.uncompressed)) return;
    if (self.input_curpos + 4 > self.end_input_pos) return;

    const p = self.input_curpos;
    self.bitbuf = (@as(u32, self.input_buffer[p + 2]) | (@as(u32, self.input_buffer[p + 3]) << 8)) |
        ((@as(u32, self.input_buffer[p]) | (@as(u32, self.input_buffer[p + 1]) << 8)) << 16);
    self.bitcount = 16;
    self.input_curpos += 4;
}

// --- canonical Huffman tables -------------------------------------------

/// make_table. A table whose lengths sum to zero is valid and decodes every
/// symbol as 0 with a zero bit length, exactly as the C version's memset path.
fn makeTable(
    nchar: u32,
    bitlen: []const u8,
    tablebits: u5,
    table: []i16,
    leftright: []i16,
) Error!void {
    var count: [17]u32 = @splat(0);
    var weight: [17]u32 = @splat(0);
    var start: [18]u32 = @splat(0);

    var i: u32 = 0;
    while (i < nchar) : (i += 1) {
        const len = bitlen[i];
        if (len > 16) return error.LzxInvalidData;
        count[len] += 1;
    }

    i = 1;
    while (i <= 16) : (i += 1) {
        start[i + 1] = start[i] +% (count[i] << @intCast(16 - i));
    }

    if (start[17] != 65536) {
        if (start[17] == 0) {
            @memset(table, 0);
            return;
        }
        return error.LzxFailed;
    }

    const jutbits: u5 = 16 - tablebits;

    i = 1;
    while (i <= tablebits) : (i += 1) {
        start[i] >>= jutbits;
        weight[i] = @as(u32, 1) << @intCast(@as(u32, tablebits) - i);
    }
    while (i <= 16) : (i += 1) {
        weight[i] = @as(u32, 1) << @intCast(16 - i);
    }

    i = start[tablebits + 1] >> jutbits;
    if (i != 65536) {
        if (i > table.len) return error.LzxFailed;
        @memset(table[i..], 0);
    }

    var avail: i32 = @intCast(nchar);
    var ch: u32 = 0;
    while (ch < nchar) : (ch += 1) {
        const len = bitlen[ch];
        if (len == 0) continue;

        const nextcode = start[len] +% weight[len];

        if (len <= tablebits) {
            if (nextcode > (@as(u32, 1) << tablebits)) return error.LzxFailed;
            var k = start[len];
            while (k < nextcode) : (k += 1) table[k] = @intCast(ch);
            start[len] = nextcode;
        } else {
            var k = start[len];
            start[len] = nextcode;
            var p_in_table = true;
            var p_index: usize = k >> jutbits;
            if (p_index >= table.len) return error.LzxFailed;
            var left: u32 = @as(u32, bitlen[ch]) - tablebits;
            k <<= tablebits;

            while (true) {
                const current: i16 = if (p_in_table) table[p_index] else leftright[p_index];
                if (current == 0) {
                    const a: usize = @intCast(avail * 2);
                    if (a + 1 >= leftright.len) return error.LzxFailed;
                    leftright[a] = 0;
                    leftright[a + 1] = 0;
                    const node: i16 = @intCast(-avail);
                    if (p_in_table) table[p_index] = node else leftright[p_index] = node;
                    avail += 1;
                }

                // Internal nodes are stored negative; the low 16 bits of k
                // select the branch like the C `(short)k < 0` test.
                const next_node: i32 = -(if (p_in_table) table[p_index] else leftright[p_index]);
                const base: usize = 2 * @as(usize, @intCast(next_node));
                if ((k & 0x8000) != 0) {
                    if (base + 1 >= leftright.len) return error.LzxFailed;
                    p_index = base + 1;
                } else {
                    if (base >= leftright.len) return error.LzxFailed;
                    p_index = base;
                }
                p_in_table = false;

                k <<= 1;
                left -= 1;
                if (left == 0) break;
            }

            if (p_in_table) table[p_index] = @intCast(ch) else leftright[p_index] = @intCast(ch);
        }
    }
}

/// make_table_8bit for the aligned offset tree.
fn makeTable8(bitlen: []const u8, table: []u8) Error!void {
    var count: [17]u16 = @splat(0);
    var weight: [17]u16 = @splat(0);
    var start: [18]u16 = @splat(0);

    var i: u32 = 0;
    while (i < c.aligned_num_elements) : (i += 1) {
        const len = bitlen[i];
        if (len > 16) return error.LzxInvalidData;
        count[len] +%= 1;
    }

    i = 1;
    while (i <= 16) : (i += 1) {
        start[i + 1] = start[i] +% (count[i] << @intCast(16 - i));
    }

    if (start[17] != 0) return error.LzxFailed;

    i = 1;
    while (i <= 7) : (i += 1) {
        start[i] >>= 9;
        weight[i] = @as(u16, 1) << @intCast(7 - i);
    }
    while (i <= 16) : (i += 1) {
        weight[i] = @as(u16, 1) << @intCast(16 - i);
    }

    @memset(table, 0);

    var ch: u8 = 0;
    while (ch < 8) : (ch += 1) {
        const len = bitlen[ch];
        if (len == 0) continue;

        const nextcode = start[len] +% weight[len];
        if (nextcode > 128) return error.LzxFailed;

        var k = start[len];
        while (k < nextcode) : (k += 1) table[k] = ch;
        start[len] = nextcode;
    }
}

/// Turn `lastlen - symbol + 17` into a length. C keeps the remainder of a
/// negative value (i.e. a byte >= 128); that only happens on corrupt streams.
fn reducedLen(value: i32) Error!u8 {
    const rem = @rem(value, 17);
    if (rem < 0 or rem > 16) return error.LzxInvalidData;
    return @intCast(rem);
}

/// decode_small.
fn decodeSmall(
    self: *Decoder,
    small_table: []const i16,
    small_bitlen: []const u8,
    leftright_s: []const i16,
) i16 {
    var temp = small_table[self.bitbuf >> small_tree_shift];
    if (temp < 0) {
        var mask: u32 = @as(u32, 1) << small_tree_mask_shift;
        while (true) {
            temp = -temp;
            const idx: usize = @intCast(temp);
            temp = if ((self.bitbuf & mask) != 0) leftright_s[2 * idx + 1] else leftright_s[2 * idx];
            mask >>= 1;
            if (temp >= 0) break;
        }
    }
    fillBuf(self, @intCast(small_bitlen[@intCast(temp)]));
    return temp;
}

/// read_rep_tree.
fn readRepTree(self: *Decoder, num_elements: u32, lastlen: []const u8, len: []u8) Error!void {
    if (len.len < @as(usize, num_elements) or lastlen.len < @as(usize, num_elements)) return error.LzxInvalidData;

    var small_bitlen: [24]u8 = @splat(0);
    var small_table: [1 << c.small_tree_table_bits]i16 = undefined;
    var leftright_s: [2 * (2 * 24 + 241)]i16 = undefined;

    var i: u32 = 0;
    while (i < c.num_decode_small) : (i += 1) {
        small_bitlen[i] = @intCast(try getBitsChecked(self, 4));
    }

    try makeTable(c.num_decode_small, small_bitlen[0..c.num_decode_small], c.small_tree_table_bits, &small_table, &leftright_s);

    i = 0;
    while (i < num_elements) {
        var temp = decodeSmall(self, &small_table, &small_bitlen, &leftright_s);
        if (self.error_condition) return error.LzxFailed;

        if (temp == 17) {
            var consecutive: u32 = try getBitsChecked(self, tree_enc_rep_first_extra_bits);
            consecutive += tree_enc_rep_min;

            if (i + consecutive >= num_elements) consecutive = num_elements - i;
            while (consecutive > 0) : (consecutive -= 1) {
                len[i] = 0;
                i += 1;
            }
        } else if (temp == 18) {
            var consecutive: u32 = try getBitsChecked(self, tree_enc_rep_second_extra_bits);
            consecutive += tree_enc_rep_min + tree_enc_rep_zero_first;

            if (i + consecutive >= num_elements) consecutive = num_elements - i;
            while (consecutive > 0) : (consecutive -= 1) {
                len[i] = 0;
                i += 1;
            }
        } else if (temp == 19) {
            var consecutive: u32 = try getBitsChecked(self, tree_enc_rep_same_extra_bits);
            consecutive += tree_enc_rep_min;

            if (i + consecutive >= num_elements) consecutive = num_elements - i;

            temp = decodeSmall(self, &small_table, &small_bitlen, &leftright_s);
            if (self.error_condition) return error.LzxFailed;

            const value = try reducedLen(@as(i32, lastlen[i]) - @as(i32, temp) + 17);

            while (consecutive > 0) : (consecutive -= 1) {
                len[i] = value;
                i += 1;
            }
        } else {
            len[i] = try reducedLen(@as(i32, lastlen[i]) - @as(i32, temp) + 17);
            i += 1;
        }
    }

    if (self.error_condition) return error.LzxFailed;
}

fn readMainAndSecondaryTrees(self: *Decoder) Error!void {
    try readRepTree(self, 256, self.main_tree_prev_len[0..], self.main_tree_len[0..]);

    const position_elements = self.num_position_slots * (c.num_primary_len + 1);
    try readRepTree(self, position_elements, self.main_tree_prev_len[256..], self.main_tree_len[256..]);

    try makeTable(
        c.mainTreeElements(self.num_position_slots),
        self.main_tree_len[0..],
        c.main_tree_table_bits,
        self.main_tree_table[0..],
        self.main_tree_left_right[0..],
    );

    try readRepTree(self, c.num_secondary_len, self.secondary_len_tree_prev_len[0..], self.secondary_len_tree_len[0..]);

    try makeTable(
        c.num_secondary_len,
        self.secondary_len_tree_len[0..],
        c.secondary_len_tree_table_bits,
        self.secondary_len_tree_table[0..],
        self.secondary_len_tree_left_right[0..],
    );
}

fn readAlignedOffsetTree(self: *Decoder) Error!void {
    var i: u32 = 0;
    while (i < c.aligned_num_elements) : (i += 1) {
        self.aligned_len[i] = @intCast(try getBitsChecked(self, 3));
    }
    if (self.error_condition) return error.LzxFailed;
    try makeTable8(self.aligned_len[0..], self.aligned_table[0..]);
}

// --- symbol decoding -----------------------------------------------------

/// DECODE_MAIN_TREE. Returns -1 (error) when the input pointer reached the end
/// like the C macro; the caller has produced a partial block, which the C API
/// reports as LZX_ERROR_FAILED.
fn decodeMainTree(self: *Decoder) Error!i32 {
    var j: i32 = self.main_tree_table[self.bitbuf >> main_tree_shift];
    if (j < 0) {
        var mask: u32 = @as(u32, 1) << main_tree_mask_shift;
        while (true) {
            j = -j;
            const idx: usize = @intCast(j);
            j = if ((self.bitbuf & mask) != 0)
                self.main_tree_left_right[2 * idx + 1]
            else
                self.main_tree_left_right[2 * idx];
            mask >>= 1;
            if (j >= 0) break;
        }
    }

    if (self.input_curpos >= self.end_input_pos) return error.LzxFailed;

    const bits: u5 = @intCast(self.main_tree_len[@intCast(j)]);
    self.bitbuf <<= bits;
    self.bitcount -= @as(i8, @intCast(bits));
    if (self.bitcount <= 0) fillRaw(
        self,
    );
    return j;
}

/// DECODE_LEN_TREE_NOEOFCHECK, including the +LZX_NUM_PRIMARY_LEN.
inline fn decodeLenTree(self: *Decoder) i32 {
    var matchlen: i32 = self.secondary_len_tree_table[self.bitbuf >> secondary_shift];
    if (matchlen < 0) {
        var mask: u32 = @as(u32, 1) << secondary_mask_shift;
        while (true) {
            matchlen = -matchlen;
            const idx: usize = @intCast(matchlen);
            matchlen = if ((self.bitbuf & mask) != 0)
                self.secondary_len_tree_left_right[2 * idx + 1]
            else
                self.secondary_len_tree_left_right[2 * idx];
            mask >>= 1;
            if (matchlen >= 0) break;
        }
    }
    fillBufNoEof(self, @intCast(self.secondary_len_tree_len[@intCast(matchlen)]));
    return matchlen + @as(i32, @intCast(c.num_primary_len));
}

// --- E8 translation ------------------------------------------------------

/// translate_e8 from lzx_decoder.c.
fn translateE8(self: *Decoder, mem: []u8, bytes: usize) Error!void {
    if (bytes <= 6) {
        self.instr_pos +%= @intCast(bytes);
        return;
    }

    var temp: [6]u8 = undefined;
    @memcpy(&temp, mem[bytes - 6 .. bytes]);
    // The sentinel makes the search below stop before the final six bytes.
    @memset(mem[bytes - 6 .. bytes], 0xE8);

    const end_instr_pos: u32 = self.instr_pos +% @as(u32, @intCast(bytes)) -% 10;

    var i: usize = 0;
    while (true) {
        while (true) {
            if (i >= mem.len) return error.LzxFailed;
            const byte = mem[i];
            i += 1;
            if (byte == 0xE8) break;
            self.instr_pos +%= 1;
        }

        if (self.instr_pos >= end_instr_pos) break;
        if (i + 4 > mem.len) return error.LzxFailed;

        const absolute = std.mem.readInt(u32, mem[i..][0..4], .little);

        if (absolute < self.current_file_size) {
            const offset = absolute -% self.instr_pos;
            std.mem.writeInt(u32, mem[i..][0..4], offset, .little);
        } else if ((0 -% absolute) <= self.instr_pos) {
            const offset = absolute +% self.current_file_size;
            std.mem.writeInt(u32, mem[i..][0..4], offset, .little);
        }

        i += 4;
        self.instr_pos +%= 5;
    }

    self.instr_pos = end_instr_pos +% 10;
    @memcpy(mem[bytes - 6 .. bytes], &temp);
}

fn copyDataToOutput(self: *Decoder, amount: u32, start: usize) Error!void {
    const dest = self.output_buffer orelse return;
    const n: usize = @intCast(amount);
    @memcpy(dest[0..n], self.mem_window[start..][0..n]);
    if (self.current_file_size != 0 and self.num_cfdata_frames < 32768) {
        try translateE8(self, dest[0..n], n);
    }
}

// --- block decoding ------------------------------------------------------

fn decodeAlignedBlockSpecial(self: *Decoder, pos_in: u32, amount_to_decode: u32) Error!u32 {
    var pos = pos_in;
    const pos_end = pos + amount_to_decode;

    while (pos < pos_end) {
        var code = try decodeMainTree(
            self,
        );
        code -= 256;

        if (code < 0) {
            const byte: u8 = @truncate(@as(u32, @bitCast(code)));
            self.mem_window[pos] = byte;
            if (pos < 257) self.mem_window[self.window_size + pos] = byte;
            pos += 1;
            continue;
        }

        var match_length: i32 = code & @as(i32, @intCast(c.num_primary_len));
        if (match_length == @as(i32, @intCast(c.num_primary_len))) match_length = decodeLenTree(
            self,
        );

        const m: i32 = code >> 3;
        var match_pos: u32 = undefined;
        var temp_pos: u32 = 0;

        if (m > 2) {
            const extra = c.extra_bits[@intCast(m)];
            if (extra >= 3) {
                if (extra - 3 != 0) temp_pos = getBitsNoEof(self, @intCast(extra - 3));

                const base: i32 = c.match_pos_minus2[@intCast(m)];
                match_pos = @as(u32, @bitCast(base)) +% (temp_pos << 3);

                const aligned = self.aligned_table[self.bitbuf >> aligned_tree_shift];
                fillBufNoEof(self, @intCast(self.aligned_len[aligned]));
                match_pos +%= aligned;
            } else if (extra != 0) {
                temp_pos = getBitsNoEof(self, @intCast(extra));
                const base: i32 = c.match_pos_minus2[@intCast(m)];
                match_pos = @as(u32, @bitCast(base)) +% temp_pos;
            } else {
                match_pos = 1;
            }

            self.last_matchpos_offset[2] = self.last_matchpos_offset[1];
            self.last_matchpos_offset[1] = self.last_matchpos_offset[0];
            self.last_matchpos_offset[0] = match_pos;
        } else {
            match_pos = self.last_matchpos_offset[@intCast(m)];
            if (m != 0) {
                self.last_matchpos_offset[@intCast(m)] = self.last_matchpos_offset[0];
                self.last_matchpos_offset[0] = match_pos;
            }
        }

        match_length += 2;
        while (match_length > 0) : (match_length -= 1) {
            self.mem_window[pos] = self.mem_window[(pos -% match_pos) & self.window_mask];
            if (pos < 257) self.mem_window[self.window_size + pos] = self.mem_window[pos];
            pos += 1;
        }
    }

    return pos;
}

fn decodeAlignedOffsetBlockFast(self: *Decoder, pos_in: u32, amount_to_decode: u32) Error!i32 {
    var pos = pos_in;
    const pos_end = pos + amount_to_decode;

    while (pos < pos_end) {
        var code = try decodeMainTree(
            self,
        );
        code -= 256;

        if (code < 0) {
            self.mem_window[pos] = @truncate(@as(u32, @bitCast(code)));
            pos += 1;
            continue;
        }

        var match_length: i32 = code & @as(i32, @intCast(c.num_primary_len));
        if (match_length == @as(i32, @intCast(c.num_primary_len))) match_length = decodeLenTree(
            self,
        );

        const m: i32 = code >> 3;
        var match_pos: u32 = undefined;

        if (m > 2) {
            const extra = c.extra_bits[@intCast(m)];
            if (extra >= 3) {
                var temp_pos: u32 = 0;
                if (extra - 3 != 0) temp_pos = getBitsNoEof(self, @intCast(extra - 3));

                const base: i32 = c.match_pos_minus2[@intCast(m)];
                match_pos = @as(u32, @bitCast(base)) +% (temp_pos << 3);

                const aligned = self.aligned_table[self.bitbuf >> aligned_tree_shift];
                fillBufNoEof(self, @intCast(self.aligned_len[aligned]));
                match_pos +%= aligned;
            } else if (extra != 0) {
                const temp_pos = getBitsNoEof(self, @intCast(extra));
                const base: i32 = c.match_pos_minus2[@intCast(m)];
                match_pos = @as(u32, @bitCast(base)) +% temp_pos;
            } else {
                match_pos = @as(u32, @bitCast(c.match_pos_minus2[@intCast(m)]));
            }

            self.last_matchpos_offset[2] = self.last_matchpos_offset[1];
            self.last_matchpos_offset[1] = self.last_matchpos_offset[0];
            self.last_matchpos_offset[0] = match_pos;
        } else {
            match_pos = self.last_matchpos_offset[@intCast(m)];
            if (m != 0) {
                self.last_matchpos_offset[@intCast(m)] = self.last_matchpos_offset[0];
                self.last_matchpos_offset[0] = match_pos;
            }
        }

        match_length += 2;
        var match_ptr: u32 = (pos -% match_pos) & self.window_mask;

        while (match_length > 0) : (match_length -= 1) {
            self.mem_window[pos] = self.mem_window[match_ptr];
            pos += 1;
            match_ptr += 1;
        }
    }

    const decode_residue: i32 = @intCast(pos - pos_end);
    self.pos = pos & self.window_mask;
    return decode_residue;
}

fn decodeAlignedOffsetBlock(self: *Decoder, pos_in: u32, amount_to_decode_in: i32) Error!i32 {
    var pos = pos_in;
    var amount_to_decode = amount_to_decode_in;

    if (pos < 257) {
        const slowly = @min(@as(u32, 257) - pos, @as(u32, @intCast(amount_to_decode)));
        const new_pos = try decodeAlignedBlockSpecial(self, pos, slowly);
        amount_to_decode -= @intCast(new_pos - pos);
        pos = new_pos;
        self.pos = pos;
        if (amount_to_decode <= 0) return amount_to_decode;
    }

    return decodeAlignedOffsetBlockFast(self, pos, @intCast(amount_to_decode));
}

fn decodeVerbatimBlockSpecial(self: *Decoder, pos_in: u32, amount_to_decode: u32) Error!u32 {
    var pos = pos_in;
    const pos_end = pos + amount_to_decode;

    while (pos < pos_end) {
        var code = try decodeMainTree(
            self,
        );
        code -= 256;

        if (code < 0) {
            const byte: u8 = @truncate(@as(u32, @bitCast(code)));
            self.mem_window[pos] = byte;
            if (pos < 257) self.mem_window[self.window_size + pos] = byte;
            pos += 1;
            continue;
        }

        var match_length: i32 = code & @as(i32, @intCast(c.num_primary_len));
        if (match_length == @as(i32, @intCast(c.num_primary_len))) match_length = decodeLenTree(
            self,
        );

        const m: i32 = code >> 3;
        var match_pos: u32 = undefined;

        if (m > 2) {
            if (m > 3) {
                const extra = c.extra_bits[@intCast(m)];
                const temp_pos = getBits17NoEof(self, @intCast(extra));
                const base: i32 = c.match_pos_minus2[@intCast(m)];
                match_pos = @as(u32, @bitCast(base)) +% temp_pos;
            } else {
                match_pos = 1;
            }

            self.last_matchpos_offset[2] = self.last_matchpos_offset[1];
            self.last_matchpos_offset[1] = self.last_matchpos_offset[0];
            self.last_matchpos_offset[0] = match_pos;
        } else {
            match_pos = self.last_matchpos_offset[@intCast(m)];
            if (m != 0) {
                self.last_matchpos_offset[@intCast(m)] = self.last_matchpos_offset[0];
                self.last_matchpos_offset[0] = match_pos;
            }
        }

        match_length += 2;
        while (match_length > 0) : (match_length -= 1) {
            self.mem_window[pos] = self.mem_window[(pos -% match_pos) & self.window_mask];
            if (pos < 257) self.mem_window[self.window_size + pos] = self.mem_window[pos];
            pos += 1;
        }
    }

    return pos;
}

fn decodeVerbatimBlockFast(self: *Decoder, pos_in: u32, amount_to_decode: u32) Error!i32 {
    var pos = pos_in;
    const pos_end = pos + amount_to_decode;

    while (pos < pos_end) {
        var code = try decodeMainTree(
            self,
        );
        code -= 256;

        if (code < 0) {
            self.mem_window[pos] = @truncate(@as(u32, @bitCast(code)));
            pos += 1;
            continue;
        }

        var match_length: i32 = code & @as(i32, @intCast(c.num_primary_len));
        if (match_length == @as(i32, @intCast(c.num_primary_len))) match_length = decodeLenTree(
            self,
        );

        const m: i32 = code >> 3;
        var match_pos: u32 = undefined;

        if (m > 2) {
            if (m > 3) {
                const extra = c.extra_bits[@intCast(m)];
                const temp_pos = getBits17NoEof(self, @intCast(extra));
                const base: i32 = c.match_pos_minus2[@intCast(m)];
                match_pos = @as(u32, @bitCast(base)) +% temp_pos;
            } else {
                match_pos = @as(u32, @bitCast(c.match_pos_minus2[@intCast(m)]));
            }

            self.last_matchpos_offset[2] = self.last_matchpos_offset[1];
            self.last_matchpos_offset[1] = self.last_matchpos_offset[0];
            self.last_matchpos_offset[0] = match_pos;
        } else {
            match_pos = self.last_matchpos_offset[@intCast(m)];
            if (m != 0) {
                self.last_matchpos_offset[@intCast(m)] = self.last_matchpos_offset[0];
                self.last_matchpos_offset[0] = match_pos;
            }
        }

        match_length += 2;
        var match_ptr: u32 = (pos -% match_pos) & self.window_mask;

        while (match_length > 0) : (match_length -= 1) {
            self.mem_window[pos] = self.mem_window[match_ptr];
            pos += 1;
            match_ptr += 1;
        }
    }

    const decode_residue: i32 = @intCast(pos - pos_end);
    self.pos = pos & self.window_mask;
    return decode_residue;
}

fn decodeVerbatimBlock(self: *Decoder, pos_in: u32, amount_to_decode_in: i32) Error!i32 {
    var pos = pos_in;
    var amount_to_decode = amount_to_decode_in;

    if (pos < 257) {
        const slowly = @min(@as(u32, 257) - pos, @as(u32, @intCast(amount_to_decode)));
        const new_pos = try decodeVerbatimBlockSpecial(self, pos, slowly);
        amount_to_decode -= @intCast(new_pos - pos);
        pos = new_pos;
        self.pos = pos;
        if (amount_to_decode <= 0) return amount_to_decode;
    }

    return decodeVerbatimBlockFast(self, pos, @intCast(amount_to_decode));
}

fn decodeUncompressedBlock(self: *Decoder, pos_in: u32, amount_to_decode: u32) Error!i32 {
    const pos_start = pos_in;
    var pos = pos_in;
    const pos_end = pos + amount_to_decode;

    var p = self.input_curpos;
    while (pos < pos_end) {
        if (p >= self.end_input_pos) return error.LzxFailed;
        self.mem_window[pos] = self.input_buffer[p];
        pos += 1;
        p += 1;
    }
    self.input_curpos = p;

    const end_copy_pos = @min(257, pos_end);
    var copy_pos = pos_start;
    while (copy_pos < end_copy_pos) : (copy_pos += 1) {
        self.mem_window[copy_pos + self.window_size] = self.mem_window[copy_pos];
    }

    const decode_residue: i32 = @intCast(pos - pos_end);
    self.pos = pos & self.window_mask;
    return decode_residue;
}

fn decodeData(self: *Decoder, bytes_to_decode_in: i32) Error!u32 {
    var bytes_to_decode = bytes_to_decode_in;
    var total_decoded: u32 = 0;

    while (bytes_to_decode > 0) {
        if (self.decoder_state == dec_state_new_block) {
            if (self.first_time_this_group) {
                self.first_time_this_group = false;

                const do_translation = (try getBitsChecked(self, 1)) != 0;
                if (do_translation) {
                    const high = try getBitsChecked(self, 16);
                    const low = try getBitsChecked(self, 16);
                    self.current_file_size = (high << 16) | low;
                } else {
                    self.current_file_size = 0;
                }
            }

            if (self.block_type == @backingInt(c.BlockType.uncompressed)) {
                if ((self.original_block_size & 1) != 0) {
                    if (self.input_curpos < self.end_input_pos) self.input_curpos += 1;
                }
                self.block_type = @backingInt(c.BlockType.invalid);
                initBitbuf(
                    self,
                );
            }

            self.block_type = try getBitsChecked(self, 3);

            const temp1 = try getBitsChecked(self, 8);
            const temp2 = try getBitsChecked(self, 8);
            const temp3 = try getBitsChecked(self, 8);

            self.original_block_size = (@as(i64, temp1) << 16) + (@as(i64, temp2) << 8) + @as(i64, temp3);
            self.block_size = self.original_block_size;

            switch (self.block_type) {
                @backingInt(c.BlockType.aligned) => {
                    try readAlignedOffsetTree(
                        self,
                    );
                    try copyPreviousTrees(
                        self,
                    );
                    try readMainAndSecondaryTrees(
                        self,
                    );
                },
                @backingInt(c.BlockType.verbatim) => {
                    try copyPreviousTrees(
                        self,
                    );
                    try readMainAndSecondaryTrees(
                        self,
                    );
                },
                @backingInt(c.BlockType.uncompressed) => {
                    if (self.input_curpos < 2) return error.LzxFailed;
                    self.input_curpos -= 2;
                    if (self.input_curpos + 4 >= self.end_input_pos) return error.LzxFailed;
                    var i: u32 = 0;
                    while (i < c.num_repeated_offsets) : (i += 1) {
                        const p = self.input_curpos;
                        self.last_matchpos_offset[i] = @as(u32, self.input_buffer[p]) |
                            (@as(u32, self.input_buffer[p + 1]) << 8) |
                            (@as(u32, self.input_buffer[p + 2]) << 16) |
                            (@as(u32, self.input_buffer[p + 3]) << 24);
                        self.input_curpos += 4;
                    }
                },
                else => return error.LzxFailed,
            }

            self.decoder_state = dec_state_decoding;
        }

        while (self.block_size > 0 and bytes_to_decode > 0) {
            const amount = @min(self.block_size, @as(i64, bytes_to_decode));
            if (amount == 0) return error.LzxFailed;
            const amount_i: i32 = @intCast(amount);

            switch (self.block_type) {
                @backingInt(c.BlockType.aligned) => _ = try decodeAlignedOffsetBlock(self, self.pos, amount_i),
                @backingInt(c.BlockType.verbatim) => _ = try decodeVerbatimBlock(self, self.pos, amount_i),
                @backingInt(c.BlockType.uncompressed) => {
                    const residue = try decodeUncompressedBlock(self, self.pos, @intCast(amount_i));
                    if (residue < 0) return error.LzxFailed;
                },
                else => return error.LzxFailed,
            }

            self.block_size -= amount;
            bytes_to_decode -= amount_i;
            total_decoded += @intCast(amount_i);
        }

        if (self.block_size == 0) self.decoder_state = dec_state_new_block;
        if (bytes_to_decode == 0) initBitbuf(
            self,
        );
    }

    var temp = self.pos;
    if (temp == 0) temp = self.window_size;

    const start: isize = @as(isize, temp) - @as(isize, total_decoded);
    if (start < 0) return error.LzxFailed;
    const start_index: usize = @intCast(start);
    if (start_index + @as(usize, total_decoded) > self.mem_window.len) return error.LzxFailed;

    try copyDataToOutput(self, total_decoded, start_index);

    if (self.error_condition) return error.LzxFailed;
    return total_decoded;
}

fn copyPreviousTrees(self: *Decoder) Error!void {
    const elements = c.mainTreeElements(self.num_position_slots);
    if (elements > self.main_tree_len.len) return error.LzxInvalidData;
    @memcpy(self.main_tree_prev_len[0..elements], self.main_tree_len[0..elements]);
    @memcpy(self.secondary_len_tree_prev_len[0..c.num_secondary_len], self.secondary_len_tree_len[0..c.num_secondary_len]);
}

// --- tests ---------------------------------------------------------------

test "create and destroy a decoder with both supported windows" {
    const allocator = std.testing.allocator;

    const small = try createDecompressionWindow(allocator, 0x8000);
    defer destroyDecompression(small);
    try std.testing.expectEqual(@as(u32, 0x8000), small.window_size);
    try std.testing.expectEqual(@as(u32, 0x7fff), small.window_mask);
    try std.testing.expectEqual(@as(u32, 30), small.num_position_slots);
    try std.testing.expectEqual(@as(usize, 0x8000 + 261), small.mem_window.len);

    const large = try createDecompressionWindow(allocator, 128 * 1024);
    defer destroyDecompression(large);
    try std.testing.expectEqual(@as(u32, 34), large.num_position_slots);
    try std.testing.expectEqual(@as(u32, 528), c.mainTreeElements(large.num_position_slots));
}

test "invalid window sizes are rejected before allocation" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.LzxInvalidData, createDecompressionWindow(allocator, 0x4000));
    try std.testing.expectError(error.LzxInvalidData, createDecompressionWindow(allocator, 0xC000));
    try std.testing.expectError(error.LzxInvalidData, createDecompressionWindow(allocator, 0x400000));
}

test "set window data places the seed before position zero" {
    const allocator = std.testing.allocator;
    const decoder = try createDecompressionWindow(allocator, 0x8000);
    defer destroyDecompression(decoder);

    const seed = [_]u8{ 1, 2, 3, 4, 5 };
    try setWindowData(decoder, &seed);

    try std.testing.expectEqual(@as(u8, 0), decoder.mem_window[0]);
    try std.testing.expectEqual(@as(u8, 0), decoder.mem_window[0x8000 - 6]);
    try std.testing.expectEqualSlices(u8, &seed, decoder.mem_window[0x8000 - 5 .. 0x8000]);

    const too_big = try allocator.alloc(u8, 0x8001);
    defer allocator.free(too_big);
    @memset(too_big, 0);
    try std.testing.expectError(error.LzxInvalidData, setWindowData(decoder, too_big));
}

test "garbage compressed data returns an error instead of decoding" {
    const allocator = std.testing.allocator;
    const decoder = try createDecompressionWindow(allocator, 0x8000);
    defer destroyDecompression(decoder);

    const garbage: [32]u8 = @splat(0xFF);
    var out: [0x8000]u8 = undefined;

    try std.testing.expectError(error.LzxFailed, decompressBlock(decoder, &garbage, &out));
    try std.testing.expectEqual(@as(u32, 0), decoder.pos);
}

test "truncated stream returns an error" {
    const allocator = std.testing.allocator;
    const decoder = try createDecompressionWindow(allocator, 0x8000);
    defer destroyDecompression(decoder);

    const truncated = [_]u8{ 0x00, 0x00, 0x00, 0x00 };
    var out: [16]u8 = undefined;

    try std.testing.expectError(error.LzxFailed, decompressBlock(decoder, &truncated, &out));
}

test "block size and window size are enforced" {
    const allocator = std.testing.allocator;
    const decoder = try createDecompressionWindow(allocator, 0x8000);
    defer destroyDecompression(decoder);

    var out: [0x8000]u8 = undefined;
    const oversized: [38913]u8 = @splat(0);
    try std.testing.expectError(error.LzxBufferOverflow, decompressBlock(decoder, &oversized, out[0..16]));

    var big_out: [0x8001]u8 = undefined;
    const eight: [8]u8 = @splat(0);
    try std.testing.expectError(error.LzxBufferOverflow, decompressBlock(decoder, &eight, &big_out));
}

test "calc decompress size walks the little endian headers" {
    const src = [_]u8{
        0x00, 0x00, 0x00, 0x80, // compressed 0, uncompressed 0x8000
        0x00, 0x00, 0x00, 0x40, // compressed 0, uncompressed 0x4000
    };
    try std.testing.expectEqual(@as(u32, 0x8000 + 0x4000), try calcDecompressSize(&src));

    const short_src = [_]u8{ 0x00, 0x00, 0x00, 0x80, 0x10 };
    try std.testing.expectError(error.LzxInvalidData, calcDecompressSize(&short_src));
}

test "translate e8 rewrites a forward call offset" {
    const allocator = std.testing.allocator;
    const decoder = try createDecompressionWindow(allocator, 0x8000);
    defer destroyDecompression(decoder);

    var mem: [16]u8 = @splat(0);
    mem[0] = 0xE8;
    mem[1] = 0x10;

    decoder.current_file_size = 0x1000;
    decoder.instr_pos = 0;
    try translateE8(decoder, &mem, mem.len);

    // absolute (0x10) < file size: the relative offset replaces the field.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xE8, 0x10, 0, 0, 0 }, mem[0..5]);
    // The last six bytes are restored and the instruction pointer jumps to
    // end_instr_pos + 10.
    const restored: [6]u8 = @splat(0);
    try std.testing.expectEqualSlices(u8, &restored, mem[10..16]);
    try std.testing.expectEqual(@as(u32, 16), decoder.instr_pos);
}

test "translate e8 rewrites a backward call offset" {
    const allocator = std.testing.allocator;
    const decoder = try createDecompressionWindow(allocator, 0x8000);
    defer destroyDecompression(decoder);

    var mem: [32]u8 = @splat(0);
    mem[16] = 0xE8;
    // 0xFFFFFFF0 is -16 as a signed 32 bit relative call.
    mem[17] = 0xF0;
    mem[18] = 0xFF;
    mem[19] = 0xFF;
    mem[20] = 0xFF;

    decoder.current_file_size = 0x1000;
    decoder.instr_pos = 0;
    try translateE8(decoder, &mem, mem.len);

    // absolute is negative and -absolute (16) <= instr_pos (16), so the stored
    // offset becomes absolute + current_file_size = 0xFF0.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xE8, 0xF0, 0x0F, 0, 0 }, mem[16..21]);
    try std.testing.expectEqual(@as(u32, 32), decoder.instr_pos);
}

test "make table decodes a single symbol with a zero length code" {
    var bitlen: [4]u8 = @splat(0);
    var table: [1 << 8]i16 = undefined;
    var leftright: [16]i16 = undefined;
    try makeTable(4, &bitlen, 8, &table, &leftright);
    for (table) |entry| try std.testing.expectEqual(@as(i16, 0), entry);
}

test "make table rejects lengths that do not fill the code space" {
    var bitlen = [_]u8{ 1, 1, 1, 0 };
    var table: [1 << 8]i16 = undefined;
    var leftright: [16]i16 = undefined;
    try std.testing.expectError(error.LzxFailed, makeTable(4, &bitlen, 8, &table, &leftright));
}
