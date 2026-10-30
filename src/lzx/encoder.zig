// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// LZX encoder, transliterated from
// XexTool/third_party/libLZX/lzx/lzx_encoder.c. Positions inside the sliding
// window are kept as isize indices into real_mem_window; C keeps a
// `mem_window` pointer that starts `window_size` bytes into the allocation and
// moves back by the secondary partition size on a slide, which is the same as
// adjusting one base offset.

const std = @import("std");
const c = @import("common.zig");

const Error = c.Error;

const secondary_partition_size: u32 = 64 * 1024;
const max_literal_items: u32 = 65536;
const min_literals_required: u32 = 6144;
const min_literals_in_block: u32 = 4096;
const max_dist_items: u32 = 32768;
const nl_shift: u5 = 3;
const extra_size: u32 = 4096;
const look: u32 = extra_size - c.max_match - 2; // 3837
const output_extra_bytes: u32 = 64;
const max_length_two_offset: u32 = 128 * 1024;
const break_max_length_two_offset: u32 = 2048;
const e8_cfdata_frame_threshold: u32 = 32768;
const break_length: u32 = 50;
const tree_create_interval: u32 = 4096;
const step_size: u32 = 64;
const resolution: u32 = 1024;
const threshold: u32 = 1400;
const early_break_threshold: u32 = 1700;
const max_block_splits: u8 = 4;
const fast_decision_threshold: u32 = 50;
const mpslot3_cutoff: u32 = 16;
const num_search_trees: u32 = 65536;
const num_chars: u32 = 256;

const tree_enc_rep_min: u32 = 4;
const tree_enc_rep_zero_first: u32 = 16;
const tree_enc_rep_zero_second: u32 = 32;
const tree_enc_rep_same_first: u32 = 2;
const tree_enc_repz_first_extra_bits: u5 = 4;
const tree_enc_repz_second_extra_bits: u5 = 5;
const tree_enc_rep_same_extra_bits: u5 = 1;

const DecisionNode = struct {
    link: u32,
    path: u32,
    repeated_offset: [c.num_repeated_offsets]u32,
    numbits: u32,
};

/// A mutable pointer into tree_root, left[] or right[], standing in for the
/// uint32_t* walks in binary_search_remove_node.
const Link = struct {
    kind: enum { root, left, right },
    index: isize,
};

pub const Encoder = struct {
    allocator: std.mem.Allocator,
    destination: []u8,
    dest_pos: usize,

    window_size: u32,
    num_position_slots: u32,
    tree_root: []u32,
    /// real_left[i + mem_base] and real_right[i + mem_base] belong to window
    /// position i, like left[]/right[] after the C pointer offsets.
    real_left: []u32,
    real_right: []u32,
    real_mem_window: []u8,
    mem_base: isize,

    bitbuf: u32,
    bitcount: i8,
    depth: i32,
    output_overflow: bool,
    literals: u32,
    distances: u32,
    dist_data: []u32,
    lit_data: []u8,
    item_type: []u8,
    repeated_offset_at_literal_zero: [c.num_repeated_offsets]u32,
    last_matchpos_offset: [c.num_repeated_offsets]u32,
    matchpos_table: [c.max_match + 1]u32,
    bufpos: u32,
    slot_table: [1024]u8,

    out_buf: []u8,
    out_cur: usize,
    out_end: usize,

    input_running_total: u32,
    bufpos_last_output_block: u32,
    file_size_for_translation: u32,
    num_block_splits: u8,
    first_block: bool,
    need_to_recalc_stats: bool,
    first_time_this_group: bool,
    ones: [256]u8,
    encoder_second_partition_size: u32,
    earliest_window_data_remaining: u32,
    bufpos_at_last_block: u32,

    input_buffer: []u8,
    input_ptr: []const u8,
    input_at: usize,
    input_left: i64,
    instr_pos: u32,

    tree_heap: [c.max_main_tree_elements + 2]i32,
    tree_leftright: [2 * (2 * c.max_main_tree_elements - 1)]u16,
    tree_len_cnt: [17]u16,
    tree_heapsize: i32,
    tree_n: i32,
    tree_sortptr: u32,

    next_tree_create: u32,
    last_literals: u32,
    last_distances: u32,
    decision_node: []DecisionNode,
    dn_base: isize,

    main_tree_len: [c.max_main_tree_elements + 1]u8,
    secondary_tree_len: [c.num_secondary_len + 1]u8,
    main_tree_freq: [c.max_main_tree_elements * 2]u16,
    main_tree_code: [c.max_main_tree_elements]u16,
    main_tree_prev_len: [c.max_main_tree_elements + 1]u8,
    secondary_tree_freq: [c.num_secondary_len * 2]u16,
    secondary_tree_code: [c.num_secondary_len]u16,
    secondary_tree_prev_len: [c.num_secondary_len + 1]u8,
    aligned_tree_freq: [c.aligned_num_elements * 2]u16,
    aligned_tree_code: [c.aligned_num_elements]u16,
    aligned_tree_len: [c.aligned_num_elements]u8,
    aligned_tree_prev_len: [c.aligned_num_elements]u8,

    cfdata_frames: u32,
    output_buffer_size: u32,
    output_buffer_block_count: u32,
};

fn memAllocSize(window_size: u32) u32 {
    return window_size + (c.max_match + extra_size) + secondary_partition_size;
}

/// lzx_create_compression_window. `dest` replaces the raw pointer the C API
/// takes; its length is the only output bound.
pub fn createCompressionWindow(allocator: std.mem.Allocator, dest: []u8, size: u32) Error!*Encoder {
    if (!c.isValidWindowSize(size)) return error.LzxInvalidData;

    const self = try allocator.create(Encoder);
    errdefer allocator.destroy(self);

    const tree_root = try allocator.alloc(u32, num_search_trees);
    errdefer allocator.free(tree_root);
    const real_left = try allocator.alloc(u32, memAllocSize(size));
    errdefer allocator.free(real_left);
    const real_right = try allocator.alloc(u32, memAllocSize(size));
    errdefer allocator.free(real_right);
    const real_mem_window = try allocator.alloc(u8, memAllocSize(size));
    errdefer allocator.free(real_mem_window);
    const lit_data = try allocator.alloc(u8, max_literal_items);
    errdefer allocator.free(lit_data);
    const dist_data = try allocator.alloc(u32, max_dist_items);
    errdefer allocator.free(dist_data);
    const item_type = try allocator.alloc(u8, max_literal_items / 8);
    errdefer allocator.free(item_type);
    const out_buf = try allocator.alloc(u8, c.output_size);
    errdefer allocator.free(out_buf);
    const decision_node = try allocator.alloc(DecisionNode, look + c.max_match + 16);
    errdefer allocator.free(decision_node);
    const input_buffer = try allocator.alloc(u8, c.chunk_size);
    errdefer allocator.free(input_buffer);

    self.* = .{
        .allocator = allocator,
        .destination = dest,
        .dest_pos = 0,
        .window_size = size,
        .num_position_slots = 0,
        .tree_root = tree_root,
        .real_left = real_left,
        .real_right = real_right,
        .real_mem_window = real_mem_window,
        .mem_base = 0,
        .bitbuf = 0,
        .bitcount = 32,
        .depth = 0,
        .output_overflow = false,
        .literals = 0,
        .distances = 0,
        .dist_data = dist_data,
        .lit_data = lit_data,
        .item_type = item_type,
        .repeated_offset_at_literal_zero = .{ 1, 1, 1 },
        .last_matchpos_offset = .{ 1, 1, 1 },
        .matchpos_table = @splat(0),
        .bufpos = 0,
        .slot_table = @splat(0),
        .out_buf = out_buf,
        .out_cur = 0,
        .out_end = c.output_size - output_extra_bytes,
        .input_running_total = 0,
        .bufpos_last_output_block = 0,
        .file_size_for_translation = 0,
        .num_block_splits = 0,
        .first_block = true,
        .need_to_recalc_stats = true,
        .first_time_this_group = true,
        .ones = @splat(0),
        .encoder_second_partition_size = secondary_partition_size,
        .earliest_window_data_remaining = 0,
        .bufpos_at_last_block = 0,
        .input_buffer = input_buffer,
        .input_ptr = input_buffer[0..0],
        .input_at = 0,
        .input_left = 0,
        .instr_pos = 0,
        .tree_heap = @splat(0),
        .tree_leftright = @splat(0),
        .tree_len_cnt = @splat(0),
        .tree_heapsize = 0,
        .tree_n = 0,
        .tree_sortptr = 0,
        .next_tree_create = 0,
        .last_literals = 0,
        .last_distances = 0,
        .decision_node = decision_node,
        .dn_base = 0,
        .main_tree_len = @splat(0),
        .secondary_tree_len = @splat(0),
        .main_tree_freq = @splat(0),
        .main_tree_code = @splat(0),
        .main_tree_prev_len = @splat(0),
        .secondary_tree_freq = @splat(0),
        .secondary_tree_code = @splat(0),
        .secondary_tree_prev_len = @splat(0),
        .aligned_tree_freq = @splat(0),
        .aligned_tree_code = @splat(0),
        .aligned_tree_len = @splat(0),
        .aligned_tree_prev_len = @splat(0),
        .cfdata_frames = 0,
        .output_buffer_size = 0,
        .output_buffer_block_count = 0,
    };

    try initCompressionMemory(
        self,
    );
    return self;
}

/// lzx_create_compression: the default 128 KiB window.
pub fn createCompression(allocator: std.mem.Allocator, dest: []u8) Error!*Encoder {
    return createCompressionWindow(allocator, dest, c.window_size);
}

/// lzx_destroy_compression.
pub fn destroyCompression(self: *Encoder) void {
    const allocator = self.allocator;
    allocator.free(self.tree_root);
    allocator.free(self.real_left);
    allocator.free(self.real_right);
    allocator.free(self.real_mem_window);
    allocator.free(self.lit_data);
    allocator.free(self.dist_data);
    allocator.free(self.item_type);
    allocator.free(self.out_buf);
    allocator.free(self.decision_node);
    allocator.free(self.input_buffer);
    allocator.destroy(self);
}

/// lzx_compress_block. `src.len` is the C bytes_read argument.
pub fn compressBlock(self: *Encoder, src: []const u8) Error!void {
    if (src.len > c.chunk_size) return error.LzxInvalidData;
    @memcpy(self.input_buffer[0..src.len], src);
    self.input_ptr = self.input_buffer[0..src.len];
    self.input_at = 0;
    self.input_left = @intCast(src.len);
    // The E8 translation is off for XEX basefiles; the C wrapper forces this.
    self.file_size_for_translation = 0;
    try encodeStart(
        self,
    );
    if (self.output_overflow) return error.LzxBufferOverflow;
}

/// lzx_compress_next_block. The C API advances *src and decrements
/// *bytes_remaining; here the caller just slices, so this is the same call.
pub fn compressNextBlock(self: *Encoder, src: []const u8) Error!void {
    return compressBlock(self, src);
}

/// lzx_flush_compression. Unlike the C void function, an output overflow is
/// reported instead of silently truncating the stream.
pub fn flushCompression(self: *Encoder) Error!void {
    while (self.literals > 0) try outputBlock(
        self,
    );
    try encodeFlush(
        self,
    );
}

/// The C field output_buffer_size: bytes written to the destination so far.
pub fn compressedSize(self: *const Encoder) u32 {
    return self.output_buffer_size;
}

pub fn blockCount(self: *const Encoder) u32 {
    return self.output_buffer_block_count;
}

// --- window accessors ----------------------------------------------------

inline fn memIndex(self: *const Encoder, i: isize) usize {
    // mem_base + i is a real index into real_mem_window by construction.
    return @intCast(self.mem_base + i);
}

inline fn memGet(self: *const Encoder, i: isize) u8 {
    return self.real_mem_window[memIndex(self, i)];
}

inline fn leftAt(self: *Encoder, i: isize) *u32 {
    return &self.real_left[memIndex(self, i)];
}

inline fn rightAt(self: *Encoder, i: isize) *u32 {
    return &self.real_right[memIndex(self, i)];
}

inline fn memReadU16(self: *const Encoder, i: isize) u16 {
    const index = memIndex(self, i);
    return std.mem.readInt(u16, self.real_mem_window[index..][0..2], .little);
}

inline fn linkGet(self: *Encoder, link: Link) u32 {
    return switch (link.kind) {
        .root => self.tree_root[@intCast(link.index)],
        .left => self.real_left[memIndex(self, link.index)],
        .right => self.real_right[memIndex(self, link.index)],
    };
}

inline fn linkSet(self: *Encoder, link: Link, value: u32) void {
    switch (link.kind) {
        .root => self.tree_root[@intCast(link.index)] = value,
        .left => self.real_left[memIndex(self, link.index)] = value,
        .right => self.real_right[memIndex(self, link.index)] = value,
    }
}

inline fn isMatch(self: *const Encoder, l: u32) bool {
    return (self.item_type[l >> 3] & (@as(u8, 1) << @intCast(l & 7))) != 0;
}

inline fn mpSlot(self: *const Encoder, matchpos: u32) u8 {
    if (matchpos < 1024) return self.slot_table[matchpos];
    if (matchpos < 524288) return 18 +% self.slot_table[matchpos >> 9];
    return @truncate(34 + (matchpos >> 17));
}

// --- output bits ---------------------------------------------------------

fn outputBits(self: *Encoder, n: u5, x: u32) void {
    if (n != 0) {
        // bitcount is in 17..32 here, so bitcount - n is in 0..31.
        const shift: u5 = @intCast(self.bitcount - @as(i8, @intCast(n)));
        self.bitbuf |= x << shift;
        self.bitcount -= @as(i8, @intCast(n));
    }

    while (self.bitcount <= 16) {
        if (self.out_cur >= self.out_end) {
            self.output_overflow = true;
            self.out_cur = 0;
        }
        self.out_buf[self.out_cur] = @truncate(self.bitbuf >> 16);
        self.out_cur += 1;
        self.out_buf[self.out_cur] = @truncate(self.bitbuf >> 24);
        self.out_cur += 1;
        self.bitbuf <<= 16;
        self.bitcount += 16;
    }
}

fn putRawByte(self: *Encoder, byte: u8) void {
    if (self.out_cur >= self.out_buf.len) {
        self.output_overflow = true;
        self.out_cur = 0;
    }
    self.out_buf[self.out_cur] = byte;
    self.out_cur += 1;
}

fn outMatch(self: *Encoder, len: u32, pos: u32) void {
    self.item_type[self.literals >> 3] |= @as(u8, 1) << @intCast(self.literals & 7);
    self.lit_data[self.literals] = @intCast(len - 2);
    self.literals += 1;
    self.dist_data[self.distances] = pos;
    self.distances += 1;
}

// --- setup ---------------------------------------------------------------

fn createOnesTable(self: *Encoder) void {
    for (0..256) |i| {
        var ones: u8 = 0;
        var value: u32 = @intCast(i);
        while (value != 0) : (value >>= 1) {
            if ((value & 1) != 0) ones += 1;
        }
        self.ones[i] = ones;
    }
}

fn createSlotLookupTable(self: *Encoder) void {
    self.slot_table[0] = 0;
    self.slot_table[1] = 1;
    self.slot_table[2] = 2;
    self.slot_table[3] = 3;

    var p: usize = 4;
    var elements_to_init: usize = 2;
    var slotnum: u8 = 4;

    while (p < 1024) {
        var j = elements_to_init;
        while (j > 0) : (j -= 1) {
            self.slot_table[p] = slotnum;
            p += 1;
        }
        slotnum += 1;
        j = elements_to_init;
        while (j > 0) : (j -= 1) {
            self.slot_table[p] = slotnum;
            p += 1;
        }
        slotnum += 1;
        elements_to_init <<= 1;
    }
}

fn initCompressionMemory(self: *Encoder) Error!void {
    self.num_position_slots = 4;
    var pos_start: u32 = 4;
    while (true) {
        pos_start +%= @as(u32, 1) << @intCast(c.extra_bits[self.num_position_slots]);
        self.num_position_slots += 1;
        if (pos_start >= self.window_size) break;
    }

    @memset(self.tree_root, 0);
    // C sets mem_window = real_mem_window - window_size, so window position i
    // lives at real index i - window_size until the first slide.
    self.mem_base = -@as(isize, self.window_size);
    self.bufpos = self.window_size;
    self.last_matchpos_offset = .{ 1, 1, 1 };
    self.repeated_offset_at_literal_zero = .{ 1, 1, 1 };
    self.first_block = true;
    self.need_to_recalc_stats = true;
    self.bufpos_last_output_block = self.bufpos;
    self.bitcount = 32;
    self.bitbuf = 0;
    self.output_overflow = false;

    const elements = c.mainTreeElements(self.num_position_slots);
    if (elements > self.main_tree_len.len) return error.LzxInvalidData;

    @memset(self.main_tree_prev_len[0..elements], 0);
    @memset(self.secondary_tree_prev_len[0..c.num_secondary_len], 0);
    @memset(self.main_tree_len[0..num_chars], 8);
    @memset(self.main_tree_len[num_chars..elements], 9);
    @memset(self.secondary_tree_len[0..c.num_secondary_len], 6);
    @memset(self.aligned_tree_len[0..c.aligned_num_elements], 3);

    preventFarMatches(
        self,
    );

    self.bufpos_at_last_block = self.bufpos;
    self.earliest_window_data_remaining = self.bufpos;
    self.input_running_total = 0;
    self.first_time_this_group = true;

    @memset(self.item_type, 0);

    self.literals = 0;
    self.distances = 0;
    self.instr_pos = 0;
    self.cfdata_frames = 0;
    self.num_block_splits = 0;
    self.repeated_offset_at_literal_zero = .{ 1, 1, 1 };

    @memset(self.main_tree_freq[0..], 0);
    @memset(self.secondary_tree_freq[0..], 0);
    @memset(self.aligned_tree_freq[0..], 0);
    @memset(self.real_mem_window, 0);
    @memset(self.real_left, 0);
    @memset(self.real_right, 0);
    @memset(self.decision_node, .{ .link = 0, .path = 0, .repeated_offset = .{ 0, 0, 0 }, .numbits = 0 });
    @memset(self.matchpos_table[0..], 0);
    @memset(self.tree_leftright[0..], 0);
    @memset(self.tree_heap[0..], 0);
    @memset(self.tree_len_cnt[0..], 0);

    createSlotLookupTable(
        self,
    );
    createOnesTable(
        self,
    );
}

fn preventFarMatches(self: *Encoder) void {
    var i: u32 = mpSlot(self, max_length_two_offset);
    while (i < self.num_position_slots) : (i += 1) {
        self.main_tree_len[num_chars + (i << nl_shift)] = 100;
    }
}

// --- input ---------------------------------------------------------------

fn readInputData(self: *Encoder, mem: []u8, amount: u32) usize {
    if (@as(i64, amount) <= self.input_left) {
        const n: usize = @intCast(amount);
        @memcpy(mem[0..n], self.input_ptr[self.input_at..][0..n]);
        self.input_at += n;
        self.input_left -= amount;
        return n;
    }

    if (self.input_left <= 0) return 0;
    const n: usize = @intCast(self.input_left);
    @memcpy(mem[0..n], self.input_ptr[self.input_at..][0..n]);
    self.input_at += n;
    self.input_left = 0;
    return n;
}

/// translate_e8 from lzx_encoder.c. Unused while file_size_for_translation is
/// zero (XEX basefiles are PowerPC), kept so the algorithm is complete.
fn translateE8(self: *Encoder, mem: []u8, bytes: usize) Error!void {
    if (bytes <= 6) {
        self.instr_pos +%= @intCast(bytes);
        return;
    }

    var temp: [6]u8 = undefined;
    @memcpy(&temp, mem[bytes - 6 .. bytes]);
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

        // The C code reads a whole long here (8 bytes on LP64); the field is a
        // 32 bit relative address, so this reads it the way the decoder does.
        const offset = std.mem.readInt(i32, mem[i..][0..4], .little);
        var absolute: i64 = @as(i64, self.instr_pos) + offset;

        if (absolute >= 0) {
            const absolute_u32: u32 = @truncate(@as(u64, @bitCast(absolute)));
            if (absolute_u32 < self.file_size_for_translation + self.instr_pos) {
                if (absolute_u32 >= self.file_size_for_translation) {
                    absolute = offset - @as(i64, self.file_size_for_translation);
                }
                std.mem.writeInt(u32, mem[i..][0..4], @truncate(@as(u64, @bitCast(absolute))), .little);
            }
        }

        i += 4;
        self.instr_pos +%= 5;
    }

    @memcpy(mem[bytes - 6 .. bytes], &temp);
    self.instr_pos = end_instr_pos +% 10;
}

fn readInput(self: *Encoder, buf_pos: usize, size: u32) Error!usize {
    if (size == 0) return 0;

    const bytes_read = readInputData(self, self.real_mem_window[buf_pos..], size);

    if (self.file_size_for_translation == 0 or self.cfdata_frames >= e8_cfdata_frame_threshold) {
        self.cfdata_frames +%= 1;
        return bytes_read;
    }

    try translateE8(self, self.real_mem_window[buf_pos..][0..bytes_read], bytes_read);
    self.cfdata_frames +%= 1;
    return bytes_read;
}

// --- Huffman construction ------------------------------------------------

fn downHeap(self: *Encoder, freq: []const u16, i_in: i32) void {
    const k = self.tree_heap[@intCast(i_in)];
    var i = i_in;
    while (true) {
        var j = i << 1;
        if (j > self.tree_heapsize) break;
        if (j < self.tree_heapsize and freq[@intCast(self.tree_heap[@intCast(j)])] > freq[@intCast(self.tree_heap[@intCast(j + 1)])]) j += 1;
        if (freq[@intCast(k)] <= freq[@intCast(self.tree_heap[@intCast(j)])]) break;
        self.tree_heap[@intCast(i)] = self.tree_heap[@intCast(j)];
        i = j;
    }
    self.tree_heap[@intCast(i)] = k;
}

fn countLen(self: *Encoder, i: i32) void {
    if (i < self.tree_n) {
        const index: usize = @intCast(@min(self.depth, 16));
        self.tree_len_cnt[index] +%= 1;
    } else {
        self.depth += 1;
        countLen(self, self.tree_leftright[@intCast(i * 2)]);
        countLen(self, self.tree_leftright[@intCast(i * 2 + 1)]);
        self.depth -= 1;
    }
}

fn makeLen(self: *Encoder, root: i32, len: []u8, code: []const u16) void {
    @memset(self.tree_len_cnt[0..], 0);
    countLen(self, root);

    var cum: u16 = 0;
    var i: i32 = 16;
    while (i > 0) : (i -= 1) {
        cum +%= @truncate(@as(u32, self.tree_len_cnt[@intCast(i)]) << @intCast(16 - i));
    }

    while (cum != 0) {
        self.tree_len_cnt[16] -%= 1;
        var j: i32 = 15;
        while (j > 0) : (j -= 1) {
            if (self.tree_len_cnt[@intCast(j)] != 0) {
                self.tree_len_cnt[@intCast(j)] -%= 1;
                self.tree_len_cnt[@intCast(j + 1)] +%= 2;
                break;
            }
        }
        cum -%= 1;
    }

    i = 16;
    while (i > 0) : (i -= 1) {
        var k: u16 = self.tree_len_cnt[@intCast(i)];
        while (k > 0) : (k -= 1) {
            if (self.tree_sortptr >= code.len) return;
            len[code[self.tree_sortptr]] = @intCast(i);
            self.tree_sortptr += 1;
        }
    }
}

fn makeCode(self: *Encoder, n: u32, len: []const u8, code: []u16) void {
    var start: [18]u16 = @splat(0);
    var i: u32 = 1;
    while (i <= 16) : (i += 1) {
        start[i + 1] = (start[i] +% self.tree_len_cnt[i]) << 1;
    }

    i = 0;
    while (i < n) : (i += 1) {
        const l = len[i];
        code[i] = start[l];
        start[l] +%= 1;
    }
}

fn makeTree2(self: *Encoder, avail_in: u32, freq: []u16, code: []u16, len: []u8) Error!void {
    var i: i32 = self.tree_heapsize >> 1;
    while (i >= 1) : (i -= 1) downHeap(self, freq, i);

    self.tree_sortptr = 0;
    var avail = avail_in;
    var k: u32 = 0;

    while (true) {
        i = self.tree_heap[1];
        if (i < self.tree_n) {
            if (self.tree_sortptr >= code.len) return error.LzxFailed;
            code[self.tree_sortptr] = @intCast(i);
            self.tree_sortptr += 1;
        }

        self.tree_heap[1] = self.tree_heap[@intCast(self.tree_heapsize)];
        self.tree_heapsize -= 1;
        downHeap(self, freq, 1);

        const j = self.tree_heap[1];
        if (j < self.tree_n) {
            if (self.tree_sortptr >= code.len) return error.LzxFailed;
            code[self.tree_sortptr] = @intCast(j);
            self.tree_sortptr += 1;
        }

        k = avail;
        avail += 1;

        freq[k] = freq[@intCast(i)] +% freq[@intCast(j)];
        self.tree_heap[1] = @intCast(k);
        downHeap(self, freq, 1);

        self.tree_leftright[k * 2] = @intCast(i);
        self.tree_leftright[k * 2 + 1] = @intCast(j);

        if (self.tree_heapsize <= 1) break;
    }

    self.tree_sortptr = 0;
    makeLen(self, @intCast(k), len, code);
}

fn makeTree(self: *Encoder, nparm: u32, freq: []u16, len: []u8, code: []u16, make_codes: bool) Error!void {
    while (true) {
        self.tree_n = @intCast(nparm);
        self.tree_heapsize = 0;
        self.depth = 0;
        self.tree_heap[1] = 0;

        var i: u32 = 0;
        while (i < nparm) : (i += 1) {
            len[i] = 0;
            if (freq[i] != 0) {
                self.tree_heapsize += 1;
                self.tree_heap[@intCast(self.tree_heapsize)] = @intCast(i);
            }
        }

        if (self.tree_heapsize < 2) {
            if (self.tree_heapsize == 0) {
                code[@intCast(self.tree_heap[1])] = 0;
                return;
            }

            if (self.tree_heap[1] == 0) freq[1] = 1 else freq[0] = 1;
            continue;
        }

        try makeTree2(self, nparm, freq, code, len);
        if (make_codes) makeCode(self, nparm, len, code);
        return;
    }
}

fn createTrees(self: *Encoder, generate_codes: bool) Error!void {
    try makeTree(
        self,
        num_chars + (self.num_position_slots * (c.num_primary_len + 1)),
        self.main_tree_freq[0..],
        self.main_tree_len[0..],
        self.main_tree_code[0..],
        generate_codes,
    );
    try makeTree(
        self,
        c.num_secondary_len,
        self.secondary_tree_freq[0..],
        self.secondary_tree_len[0..],
        self.secondary_tree_code[0..],
        generate_codes,
    );
    try makeTree(
        self,
        c.aligned_num_elements,
        self.aligned_tree_freq[0..],
        self.aligned_tree_len[0..],
        self.aligned_tree_code[0..],
        true,
    );
}

// --- cost estimation and block statistics --------------------------------

fn tallyFrequency(self: *Encoder, start: u32, start_at: u32, end: u32) u32 {
    var bytes_compressed: u32 = 0;
    var d = start_at;

    var i: u32 = start;
    while (i < end) : (i += 1) {
        if (!isMatch(self, i)) {
            self.main_tree_freq[self.lit_data[i]] +%= 1;
            bytes_compressed += 1;
        } else {
            const slot = mpSlot(self, self.dist_data[d]);
            if (self.lit_data[i] < c.num_primary_len) {
                self.main_tree_freq[num_chars + (@as(u32, slot) << nl_shift) + self.lit_data[i]] +%= 1;
            } else {
                self.main_tree_freq[(num_chars + c.num_primary_len) + (@as(u32, slot) << nl_shift)] +%= 1;
                self.secondary_tree_freq[self.lit_data[i] - c.num_primary_len] +%= 1;
            }
            bytes_compressed += @as(u32, self.lit_data[i]) + c.min_match;
            d += 1;
        }
    }

    return bytes_compressed;
}

fn fixTreeCostEstimates(self: *Encoder) void {
    var i: u32 = 0;
    while (i < num_chars) : (i += 1) {
        if (self.main_tree_len[i] == 0) self.main_tree_len[i] = 11;
    }
    while (i < num_chars + (self.num_position_slots * (c.num_primary_len + 1))) : (i += 1) {
        if (self.main_tree_len[i] == 0) self.main_tree_len[i] = 12;
    }
    i = 0;
    while (i < c.num_secondary_len) : (i += 1) {
        if (self.secondary_tree_len[i] == 0) self.secondary_tree_len[i] = 8;
    }
    preventFarMatches(
        self,
    );
}

fn getBlockStats(self: *Encoder, start: u32, start_at: u32, end: u32) u32 {
    @memset(self.main_tree_freq[0..c.mainTreeElements(self.num_position_slots)], 0);
    @memset(self.secondary_tree_freq[0..c.num_secondary_len], 0);
    return tallyFrequency(self, start, start_at, end);
}

fn updateTreeEstimates(self: *Encoder) Error!void {
    if (self.literals == 0) return;

    if (self.need_to_recalc_stats) {
        _ = getBlockStats(self, 0, 0, self.literals);
        self.need_to_recalc_stats = false;
    } else {
        _ = tallyFrequency(self, self.last_literals, self.last_distances, self.literals);
    }

    try createTrees(self, false);
    fixTreeCostEstimates(
        self,
    );
    self.last_literals = self.literals;
    self.last_distances = self.distances;
}

fn tallyAlignedBits(self: *Encoder, end_at: u32) void {
    var i: u32 = 0;
    while (i < end_at) : (i += 1) {
        const match_pos = self.dist_data[i];
        if (match_pos >= mpslot3_cutoff) self.aligned_tree_freq[match_pos & 7] +%= 1;
    }
}

fn getAlignedStats(self: *Encoder, end_at: u32) u32 {
    @memset(self.aligned_tree_freq[0..], 0);
    tallyAlignedBits(self, end_at);

    var total_l3: u32 = 0;
    var largest_l3: u32 = 0;
    for (0..c.aligned_num_elements) |i| {
        if (self.aligned_tree_freq[i] > largest_l3) largest_l3 = self.aligned_tree_freq[i];
        total_l3 += self.aligned_tree_freq[i];
    }

    if (largest_l3 > total_l3 / 5 and end_at >= 100) return @backingInt(c.BlockType.aligned);
    return @backingInt(c.BlockType.verbatim);
}

fn estimateCompressedBlockSize(self: *const Encoder) u32 {
    var block_size: u32 = 150 * 8;

    var i: u32 = 0;
    while (i < num_chars) : (i += 1) {
        block_size += @as(u32, self.main_tree_len[i]) * self.main_tree_freq[i];
    }

    var mpslot: u32 = 0;
    while (mpslot < self.num_position_slots) : (mpslot += 1) {
        var element: u32 = num_chars + (mpslot << nl_shift);
        var primary: u32 = 0;
        while (primary <= c.num_primary_len) : (primary += 1) {
            block_size += (@as(u32, self.main_tree_len[element]) + c.extra_bits[mpslot]) * self.main_tree_freq[element];
            element += 1;
        }
    }

    i = 0;
    while (i < c.num_secondary_len) : (i += 1) {
        block_size += @as(u32, self.secondary_tree_freq[i]) * self.secondary_tree_len[i];
    }

    return (block_size + 7) >> 3;
}

// --- block splitting -----------------------------------------------------

fn returnDifference(self: *Encoder, item_start1_in: u32, item_start2_in: u32, dist_at_1_in: u32, dist_at_2_in: u32, size: u32) u32 {
    var freq1: [800]u16 = @splat(0);
    var freq2: [800]u16 = @splat(0);

    const elements = c.mainTreeElements(self.num_position_slots);
    if (elements >= freq1.len) return 0;

    var item_start1 = item_start1_in;
    var item_start2 = item_start2_in;
    var dist_at_1 = dist_at_1_in;
    var dist_at_2 = dist_at_2_in;

    var i: u32 = 0;
    while (i < size) : (i += 1) {
        var element: u32 = undefined;
        if (!isMatch(self, item_start1)) {
            element = self.lit_data[item_start1];
        } else {
            const slot = mpSlot(self, self.dist_data[dist_at_1]);
            if (self.lit_data[item_start1] < c.num_primary_len) {
                element = num_chars + (@as(u32, slot) << nl_shift) + self.lit_data[item_start1];
            } else {
                element = (num_chars + c.num_primary_len) + (@as(u32, slot) << nl_shift);
            }
            dist_at_1 += 1;
        }
        item_start1 += 1;
        freq1[element] +%= 1;

        if (!isMatch(self, item_start2)) {
            element = self.lit_data[item_start2];
        } else {
            const slot = mpSlot(self, self.dist_data[dist_at_2]);
            if (self.lit_data[item_start2] < c.num_primary_len) {
                element = num_chars + (@as(u32, slot) << nl_shift) + self.lit_data[item_start2];
            } else {
                element = (num_chars + c.num_primary_len) + (@as(u32, slot) << nl_shift);
            }
            dist_at_2 += 1;
        }
        item_start2 += 1;
        freq2[element] +%= 1;
    }

    var cum_diff: u32 = 0;
    i = 0;
    while (i < elements) : (i += 1) {
        const log2a = c.log2(freq1[i]);
        const log2b = c.log2(freq2[i]);
        // The C code stores the signed difference in a uint32_t and then calls
        // abs((long)diff); abs takes an int, so the long is truncated back and
        // the result is the magnitude of the signed difference.
        const diff = c.square_table[log2a] - c.square_table[log2b];
        const magnitude: u32 = @intCast(if (diff < 0) -diff else diff);
        cum_diff +%= magnitude;
    }

    return cum_diff;
}

fn splitBlock(
    self: *Encoder,
    start_in: u32,
    end: u32,
    distance_to_end_at: u32,
    split_at_literal: *u32,
    split_at_distance: ?*u32,
) bool {
    var num_dist_at_item: [(max_literal_items / step_size) + 8]u16 = @splat(0);

    split_at_literal.* = end;
    if (split_at_distance) |p| p.* = distance_to_end_at;
    if (end -% start_in < min_literals_required) return false;
    if (self.num_block_splits >= max_block_splits) return false;

    var d: u32 = 0;
    var nd: usize = 0;
    var i: u32 = 0;
    while (i < (end >> 3)) : (i += 1) {
        if ((i & ((step_size >> 3) - 1)) == 0) {
            num_dist_at_item[nd] = @truncate(d);
            nd += 1;
        }
        d += self.ones[self.item_type[i]];
    }

    const start = (start_in +% (step_size - 1)) & ~(step_size - 1);

    i = start + 2 * resolution;
    while (i < end -% (4 * resolution)) : (i += resolution) {
        const d1 = returnDifference(self, i, i + resolution, num_dist_at_item[i / step_size], num_dist_at_item[(i + resolution) / step_size], resolution);
        const d2 = returnDifference(self, i - resolution, i + 2 * resolution, num_dist_at_item[(i - resolution) / step_size], num_dist_at_item[(i + 2 * resolution) / step_size], resolution);
        const d3 = returnDifference(self, i - 2 * resolution, i + 3 * resolution, num_dist_at_item[(i - 2 * resolution) / step_size], num_dist_at_item[(i + 3 * resolution) / step_size], resolution);
        if (d1 > threshold and d2 > threshold and d3 > threshold) {
            var max_diff: u32 = 0;
            var literal_split: u32 = 0;

            var j: u32 = i + resolution / 2;
            while (j < i + (5 * resolution) / 2) : (j += step_size) {
                const diff = returnDifference(self, j - resolution, j, num_dist_at_item[(j - resolution) / step_size], num_dist_at_item[j / step_size], resolution);
                if (diff > max_diff) {
                    max_diff = diff;
                    literal_split = j;
                }
            }

            if (max_diff >= early_break_threshold and (literal_split -% start) >= min_literals_in_block) {
                self.num_block_splits += 1;
                split_at_literal.* = literal_split;
                if (split_at_distance) |p| p.* = num_dist_at_item[literal_split / step_size];
                return true;
            }
        }
    }

    return false;
}

// --- tree serialisation --------------------------------------------------

fn countSame(p_len: []const u8, i: u32) u32 {
    var same: u32 = 0;
    var j = i + 1;
    while (p_len[j] == p_len[i]) : (j += 1) same += 1;
    return same;
}

fn writeRepTree(self: *Encoder, p_len: []u8, p_last_len: []u8, num: u32) Error!void {
    var small_freq: [2 * 24]u16 = @splat(0);
    var mini_code: [24]u16 = @splat(0);
    var mini_len: [24]u8 = @splat(0);

    const temp_store = p_len[num];
    p_len[num] = 123;

    var i: u32 = 0;
    while (i < num) : (i += 1) {
        var same = countSame(p_len, i);

        if (same >= tree_enc_rep_min) {
            if (p_len[i] == 0) {
                if (same > tree_enc_rep_min + tree_enc_rep_zero_first + tree_enc_rep_zero_second - 1) {
                    same = tree_enc_rep_min + tree_enc_rep_zero_first + tree_enc_rep_zero_second - 1;
                }
                if (same <= tree_enc_rep_min + tree_enc_rep_zero_first - 1) {
                    small_freq[17] +%= 1;
                } else {
                    small_freq[18] +%= 1;
                }
            } else {
                if (same > tree_enc_rep_min + tree_enc_rep_same_first - 1) {
                    same = tree_enc_rep_min + tree_enc_rep_same_first - 1;
                }
                small_freq[@intCast(@rem(@as(i32, p_last_len[i]) - @as(i32, p_len[i]) + 17, 17))] +%= 1;
                small_freq[19] +%= 1;
            }
            i += same - 1;
        } else {
            small_freq[@intCast(@rem(@as(i32, p_last_len[i]) - @as(i32, p_len[i]) + 17, 17))] +%= 1;
        }
    }

    try makeTree(self, c.num_decode_small, small_freq[0..], mini_len[0..], mini_code[0..], true);

    i = 0;
    while (i < c.num_decode_small) : (i += 1) {
        outputBits(self, 4, mini_len[i]);
    }

    i = 0;
    while (i < num) : (i += 1) {
        var same = countSame(p_len, i);
        var k: u32 = undefined;

        if (same >= tree_enc_rep_min) {
            if (p_len[i] == 0) {
                if (same > tree_enc_rep_min + tree_enc_rep_zero_first + tree_enc_rep_zero_second - 1) {
                    same = tree_enc_rep_min + tree_enc_rep_zero_first + tree_enc_rep_zero_second - 1;
                }
                if (same <= tree_enc_rep_min + tree_enc_rep_zero_first - 1) {
                    k = 17;
                } else {
                    k = 18;
                }
            } else {
                if (same > tree_enc_rep_min + tree_enc_rep_same_first - 1) {
                    same = tree_enc_rep_min + tree_enc_rep_same_first - 1;
                }
                k = 19;
            }
        } else {
            k = @intCast(@rem(@as(i32, p_last_len[i]) - @as(i32, p_len[i]) + 17, 17));
        }

        outputBits(self, @intCast(mini_len[k]), mini_code[k]);

        if (k == 17) {
            outputBits(self, tree_enc_repz_first_extra_bits, same - tree_enc_rep_min);
            i += same - 1;
        } else if (k == 18) {
            outputBits(self, tree_enc_repz_second_extra_bits, same - (tree_enc_rep_min + tree_enc_rep_zero_first));
            i += same - 1;
        } else if (k == 19) {
            outputBits(self, tree_enc_rep_same_extra_bits, same - tree_enc_rep_min);
            k = @intCast(@rem(@as(i32, p_last_len[i]) - @as(i32, p_len[i]) + 17, 17));
            outputBits(self, @intCast(mini_len[k]), mini_code[k]);
            i += same - 1;
        }
    }

    p_len[num] = temp_store;
    @memcpy(p_last_len[0..num], p_len[0..num]);
}

fn encodeTrees(self: *Encoder) Error!void {
    const position_len = self.num_position_slots * (c.num_primary_len + 1);
    if (num_chars + position_len > self.main_tree_len.len) return error.LzxFailed;

    try writeRepTree(self, self.main_tree_len[0..], self.main_tree_prev_len[0..], num_chars);
    try writeRepTree(self, self.main_tree_len[num_chars..], self.main_tree_prev_len[num_chars..], position_len);
    try writeRepTree(self, self.secondary_tree_len[0..], self.secondary_tree_prev_len[0..], c.num_secondary_len);
}

fn encodeAlignedTree(self: *Encoder) Error!void {
    try makeTree(
        self,
        c.aligned_num_elements,
        self.aligned_tree_freq[0..],
        self.aligned_tree_len[0..],
        self.aligned_tree_code[0..],
        true,
    );
    var i: u32 = 0;
    while (i < 8) : (i += 1) {
        outputBits(self, 3, self.aligned_tree_len[i]);
    }
}

// --- block encoding ------------------------------------------------------

fn encodeVerbatimBlock(self: *Encoder, literals_end: u32) Error!void {
    var d: u32 = 0;
    var l: u32 = 0;

    while (l < literals_end) {
        if (!isMatch(self, l)) {
            const lit = self.lit_data[l];
            outputBits(self, @intCast(self.main_tree_len[lit]), self.main_tree_code[lit]);
            l += 1;
            self.input_running_total += 1;
        } else {
            const match_len = self.lit_data[l];
            l += 1;
            const match_pos = self.dist_data[d];
            d += 1;
            const slot = mpSlot(self, match_pos);

            if (match_len < c.num_primary_len) {
                const element = num_chars + (@as(u32, slot) << nl_shift) + match_len;
                outputBits(self, @intCast(self.main_tree_len[element]), self.main_tree_code[element]);
            } else {
                const element = (num_chars + c.num_primary_len) + (@as(u32, slot) << nl_shift);
                outputBits(self, @intCast(self.main_tree_len[element]), self.main_tree_code[element]);
                const secondary = match_len - c.num_primary_len;
                outputBits(self, @intCast(self.secondary_tree_len[secondary]), self.secondary_tree_code[secondary]);
            }

            const extra = c.extra_bits[slot];
            if (extra != 0) {
                outputBits(self, @intCast(extra), match_pos & c.slot_mask[slot]);
            }

            self.input_running_total += @as(u32, match_len) + c.min_match;
        }

        if (self.input_running_total == c.chunk_size) {
            try encodeFlush(
                self,
            );
            self.num_block_splits = 0;
        }
    }
}

fn encodeAlignedBlock(self: *Encoder, literals_end: u32) Error!void {
    var l: u32 = 0;
    var d: u32 = 0;

    while (l < literals_end) {
        if (!isMatch(self, l)) {
            const lit = self.lit_data[l];
            outputBits(self, @intCast(self.main_tree_len[lit]), self.main_tree_code[lit]);
            l += 1;
            self.input_running_total += 1;
        } else {
            const match_len = self.lit_data[l];
            l += 1;
            const match_pos = self.dist_data[d];
            d += 1;
            const slot = mpSlot(self, match_pos);

            if (match_len < c.num_primary_len) {
                const element = num_chars + (@as(u32, slot) << nl_shift) + match_len;
                outputBits(self, @intCast(self.main_tree_len[element]), self.main_tree_code[element]);
            } else {
                const element = (num_chars + c.num_primary_len) + (@as(u32, slot) << nl_shift);
                outputBits(self, @intCast(self.main_tree_len[element]), self.main_tree_code[element]);
                const secondary = match_len - c.num_primary_len;
                outputBits(self, @intCast(self.secondary_tree_len[secondary]), self.secondary_tree_code[secondary]);
            }

            const extra = c.extra_bits[slot];
            if (extra >= 3) {
                if (extra > 3) {
                    outputBits(self, @intCast(extra - 3), (match_pos >> 3) & ((@as(u32, 1) << @intCast(extra - 3)) - 1));
                }
                const lower: u8 = @truncate(match_pos & 7);
                outputBits(self, @intCast(self.aligned_tree_len[lower]), self.aligned_tree_code[lower]);
            } else if (extra != 0) {
                outputBits(self, @intCast(extra), match_pos & c.slot_mask[slot]);
            }

            self.input_running_total += @as(u32, match_len) + c.min_match;
        }

        if (self.input_running_total == c.chunk_size) {
            try encodeFlush(
                self,
            );
            self.num_block_splits = 0;
        }
    }
}

fn encodeUncompressedBlock(self: *Encoder, bufpos_in: u32, block_size_in: u32) Error!void {
    outputBits(self, @intCast(self.bitcount - 16), 0);

    var i: u32 = 0;
    while (i < c.num_repeated_offsets) : (i += 1) {
        var val = self.repeated_offset_at_literal_zero[i];
        var j: u32 = 0;
        while (j < 4) : (j += 1) {
            putRawByte(self, @truncate(val));
            val >>= 8;
        }
    }

    const block_size_odd = (block_size_in & 1) != 0;
    var block_size = block_size_in;
    var bufpos = bufpos_in;

    while (block_size > 0) {
        putRawByte(self, memGet(self, bufpos));
        bufpos += 1;
        block_size -= 1;
        self.input_running_total += 1;

        if (self.input_running_total >= c.chunk_size) {
            try encodeFlush(
                self,
            );
            self.num_block_splits = 0;
        }
    }

    if (block_size_odd) putRawByte(self, 0);

    self.bitcount = 32;
    self.bitbuf = 0;
}

fn getFinalRepeatedOffsetStates(self: *Encoder, distances: u32) void {
    var consecutive: u8 = 0;
    var d: isize = @as(isize, @intCast(distances)) - 1;

    while (d >= 0) : (d -= 1) {
        if (self.dist_data[@intCast(d)] > 2) {
            consecutive += 1;
            if (consecutive >= 3) break;
        } else {
            consecutive = 0;
        }
    }

    if (consecutive < 3) d = 0;

    while (d < @as(isize, @intCast(distances))) : (d += 1) {
        const match_pos = self.dist_data[@intCast(d)];

        if (match_pos == 0) {
            // repeated offset 0: unchanged
        } else if (match_pos <= 2) {
            const temp = self.repeated_offset_at_literal_zero[match_pos];
            self.repeated_offset_at_literal_zero[match_pos] = self.repeated_offset_at_literal_zero[0];
            self.repeated_offset_at_literal_zero[0] = temp;
        } else {
            self.repeated_offset_at_literal_zero[2] = self.repeated_offset_at_literal_zero[1];
            self.repeated_offset_at_literal_zero[1] = self.repeated_offset_at_literal_zero[0];
            self.repeated_offset_at_literal_zero[0] = match_pos - 2;
        }
    }
}

fn doBlockOutput(self: *Encoder, end: u32, distance_to_end_at: u32) Error!void {
    const bytes_compressed = getBlockStats(self, 0, 0, end);
    var block_type: u32 = getAlignedStats(self, distance_to_end_at);

    try createTrees(self, true);

    const estimated_block_size = estimateCompressedBlockSize(
        self,
    );
    if (estimated_block_size >= bytes_compressed) {
        if (self.bufpos_at_last_block >= self.earliest_window_data_remaining) {
            block_type = @backingInt(c.BlockType.uncompressed);
        }
    }

    outputBits(self, 3, block_type);
    outputBits(self, 8, (bytes_compressed >> 16) & 255);
    outputBits(self, 8, (bytes_compressed >> 8) & 255);
    outputBits(self, 8, bytes_compressed & 255);

    if (block_type == @backingInt(c.BlockType.verbatim)) {
        try encodeTrees(
            self,
        );
        try encodeVerbatimBlock(self, end);
        getFinalRepeatedOffsetStates(self, distance_to_end_at);
    } else if (block_type == @backingInt(c.BlockType.aligned)) {
        try encodeAlignedTree(
            self,
        );
        try encodeTrees(
            self,
        );
        try encodeAlignedBlock(self, end);
        getFinalRepeatedOffsetStates(self, distance_to_end_at);
    } else if (block_type == @backingInt(c.BlockType.uncompressed)) {
        getFinalRepeatedOffsetStates(self, distance_to_end_at);
        try encodeUncompressedBlock(self, self.bufpos_at_last_block, bytes_compressed);
    }

    self.bufpos_at_last_block += bytes_compressed;
}

fn outputBlock(self: *Encoder) Error!void {
    self.first_block = false;

    var where_to_split: u32 = 0;
    var distances: u32 = 0;
    _ = splitBlock(self, 0, self.literals, self.distances, &where_to_split, &distances);
    try doBlockOutput(self, where_to_split, distances);

    if (where_to_split == self.literals) {
        @memset(self.item_type, 0);
        self.literals = 0;
        self.distances = 0;
    } else {
        const src_start = where_to_split / 8;
        const src_end = 1 + self.literals / 8;
        const count = src_end - src_start;
        std.mem.copyForwards(u8, self.item_type[0..count], self.item_type[src_start..][0..count]);

        const zero_start = 1 + (self.literals - where_to_split) / 8;
        @memset(self.item_type[zero_start..], 0);

        const lit_count = self.literals - where_to_split;
        std.mem.copyForwards(u8, self.lit_data[0..lit_count], self.lit_data[where_to_split..][0..lit_count]);

        const dist_count = self.distances - distances;
        std.mem.copyForwards(u32, self.dist_data[0..dist_count], self.dist_data[distances..][0..dist_count]);

        self.literals -= where_to_split;
        self.distances -= distances;
    }

    fixTreeCostEstimates(
        self,
    );
}

fn blockEnd(self: *Encoder, buf_pos: isize) Error!void {
    self.first_block = false;
    self.need_to_recalc_stats = true;

    try outputBlock(
        self,
    );

    if (self.literals < tree_create_interval) {
        self.next_tree_create = tree_create_interval;
    } else {
        self.next_tree_create = self.literals + tree_create_interval;
    }

    self.bufpos_last_output_block = @intCast(buf_pos);
}

// --- match search --------------------------------------------------------

fn fillMatchPositions(self: *Encoder, buf_pos: isize, ptr: isize, same: isize, match_length: *isize) void {
    while (match_length.* < same) {
        match_length.* += 1;
        self.matchpos_table[@intCast(match_length.*)] = @intCast(buf_pos - ptr + 2);
    }
}

fn binarySearchFindmatch(self: *Encoder, buf_pos: isize) isize {
    const tree_index = memReadU16(self, buf_pos);
    var ptr: isize = @intCast(self.tree_root[tree_index]);
    self.tree_root[tree_index] = @intCast(buf_pos);

    const end_pos: isize = buf_pos - (@as(isize, self.window_size) - 4);

    if (ptr <= end_pos) {
        leftAt(self, buf_pos).* = 0;
        rightAt(self, buf_pos).* = 0;
        return 0;
    }

    var clen: isize = 2;
    var match_length: isize = 2;
    var small_len: isize = 2;
    var big_len: isize = 2;
    self.matchpos_table[2] = @intCast(buf_pos - ptr + 2);

    var small_is_left = true;
    var small_index = buf_pos;
    var big_is_left = false;
    var big_index = buf_pos;

    var early = false;

    search: while (true) {
        var same: isize = clen;
        var a = ptr + clen;
        var b = buf_pos + clen;
        var current_val: i32 = 0;
        var long_hit = false;

        while (true) {
            current_val = @as(i32, memGet(self, a)) - @as(i32, memGet(self, b));
            a += 1;
            b += 1;
            if (current_val != 0) break;
            same += 1;
            if (same >= @as(isize, c.max_match)) {
                long_hit = true;
                break;
            }
        }

        if (long_hit) {
            // goto long_match: the enclosing `same > big_len` tests are skipped.
            fillMatchPositions(self, buf_pos, ptr, same, &match_length);
            if (same >= break_length) {
                const lv = leftAt(self, ptr).*;
                const rv = rightAt(self, ptr).*;
                setLinkByFlag(self, small_is_left, small_index, lv);
                setLinkByFlag(self, big_is_left, big_index, rv);
                early = true;
                break :search;
            }
            big_len = same;
            clen = @min(small_len, big_len);
            setLinkByFlag(self, big_is_left, big_index, @intCast(ptr));
            big_is_left = true;
            big_index = ptr;
            ptr = @intCast(leftAt(self, ptr).*);
        } else if (current_val < 0) {
            if (same > big_len) {
                if (same > match_length) {
                    fillMatchPositions(self, buf_pos, ptr, same, &match_length);
                    if (same >= break_length) {
                        const lv = leftAt(self, ptr).*;
                        const rv = rightAt(self, ptr).*;
                        setLinkByFlag(self, small_is_left, small_index, lv);
                        setLinkByFlag(self, big_is_left, big_index, rv);
                        early = true;
                        break :search;
                    }
                }
                big_len = same;
                clen = @min(small_len, big_len);
            }
            setLinkByFlag(self, big_is_left, big_index, @intCast(ptr));
            big_is_left = true;
            big_index = ptr;
            ptr = @intCast(leftAt(self, ptr).*);
        } else {
            if (same > small_len) {
                if (same > match_length) {
                    fillMatchPositions(self, buf_pos, ptr, same, &match_length);
                    if (same >= break_length) {
                        const lv = leftAt(self, ptr).*;
                        const rv = rightAt(self, ptr).*;
                        setLinkByFlag(self, small_is_left, small_index, lv);
                        setLinkByFlag(self, big_is_left, big_index, rv);
                        early = true;
                        break :search;
                    }
                }
                small_len = same;
                clen = @min(small_len, big_len);
            }
            setLinkByFlag(self, small_is_left, small_index, @intCast(ptr));
            small_is_left = false;
            small_index = ptr;
            ptr = @intCast(rightAt(self, ptr).*);
        }

        if (!(ptr > end_pos)) break;
    }

    if (!early) {
        setLinkByFlag(self, small_is_left, small_index, 0);
        setLinkByFlag(self, big_is_left, big_index, 0);
    }

    // Prefer repeated offsets when they cover the match.
    var i: isize = 0;
    while (i < match_length) : (i += 1) {
        if (memGet(self, buf_pos + i) != memGet(self, buf_pos - @as(isize, self.last_matchpos_offset[0]) + i)) break;
    }
    var best = i;

    if (i >= c.min_match) {
        var k = i;
        while (k >= 2) : (k -= 1) self.matchpos_table[@intCast(k)] = 0;
        if (best > break_length) return finishMatchLength(buf_pos, match_length);
    }

    i = 0;
    while (i < match_length) : (i += 1) {
        if (memGet(self, buf_pos + i) != memGet(self, buf_pos - @as(isize, self.last_matchpos_offset[1]) + i)) break;
    }
    if (i > best) {
        while (best < i) {
            best += 1;
            self.matchpos_table[@intCast(best)] = 1;
        }
    }

    i = 0;
    while (i < match_length) : (i += 1) {
        if (memGet(self, buf_pos + i) != memGet(self, buf_pos - @as(isize, self.last_matchpos_offset[2]) + i)) break;
    }
    if (i > best) {
        while (best < i) {
            best += 1;
            self.matchpos_table[@intCast(best)] = 2;
        }
    }

    return finishMatchLength(buf_pos, match_length);
}

fn finishMatchLength(buf_pos: isize, match_length_in: isize) isize {
    var match_length = match_length_in;
    const bytes_to_boundary: isize = @as(isize, c.chunk_size) - 1 - @mod(buf_pos, @as(isize, c.chunk_size));

    if (match_length > bytes_to_boundary) {
        match_length = bytes_to_boundary;
        if (match_length < c.min_match) match_length = 0;
    }
    return match_length;
}

inline fn setLinkByFlag(self: *Encoder, is_left: bool, index: isize, value: u32) void {
    if (is_left) leftAt(self, index).* = value else rightAt(self, index).* = value;
}

fn binarySearchRemoveNode(self: *Encoder, buf_pos: isize, end_pos: isize) void {
    const tree_index = memReadU16(self, buf_pos);
    if (self.tree_root[tree_index] != @as(u32, @intCast(buf_pos))) return;

    var link = Link{ .kind = .root, .index = tree_index };

    if (self.tree_root[tree_index] <= @as(u32, @intCast(end_pos))) {
        linkSet(self, link, 0);
        leftAt(self, buf_pos).* = 0;
        rightAt(self, buf_pos).* = 0;
        return;
    }

    var ptr = buf_pos;

    var left_node: u32 = leftAt(self, ptr).*;
    if (left_node <= @as(u32, @intCast(end_pos))) {
        left_node = 0;
        leftAt(self, ptr).* = 0;
    }

    var right_node: u32 = rightAt(self, ptr).*;
    if (right_node <= @as(u32, @intCast(end_pos))) {
        right_node = 0;
        rightAt(self, ptr).* = 0;
    }

    while (true) {
        if (@as(isize, @intCast(left_node)) > @as(isize, @intCast(right_node))) {
            if (left_node <= @as(u32, @intCast(end_pos))) left_node = 0;

            linkSet(self, link, left_node);
            ptr = @intCast(left_node);
            if (ptr == 0) break;

            left_node = rightAt(self, ptr).*;
            link = .{ .kind = .right, .index = ptr };
        } else {
            if (right_node <= @as(u32, @intCast(end_pos))) right_node = 0;

            linkSet(self, link, right_node);
            ptr = @intCast(right_node);
            if (ptr == 0) break;

            right_node = leftAt(self, ptr).*;
            link = .{ .kind = .left, .index = ptr };
        }
    }
}

fn quickInsertBsearchFindmatch(self: *Encoder, buf_pos: isize, end_pos: isize) void {
    const tree_index = memReadU16(self, buf_pos);
    var ptr: isize = @intCast(self.tree_root[tree_index]);
    self.tree_root[tree_index] = @intCast(buf_pos);

    if (ptr <= end_pos) {
        leftAt(self, buf_pos).* = 0;
        rightAt(self, buf_pos).* = 0;
        return;
    }

    var clen: isize = 2;
    var small_len: isize = 2;
    var big_len: isize = 2;

    var small_is_left = true;
    var small_index = buf_pos;
    var big_is_left = false;
    var big_index = buf_pos;

    while (true) {
        var same: isize = clen;
        var a = ptr + clen;
        var b = buf_pos + clen;
        var val: i32 = 0;

        while (true) {
            val = @as(i32, memGet(self, a)) - @as(i32, memGet(self, b));
            a += 1;
            b += 1;
            if (val != 0) break;
            same += 1;
            if (same >= break_length) break;
        }

        if (val < 0) {
            if (same > big_len) {
                if (same >= break_length) {
                    const lv = leftAt(self, ptr).*;
                    const rv = rightAt(self, ptr).*;
                    setLinkByFlag(self, small_is_left, small_index, lv);
                    setLinkByFlag(self, big_is_left, big_index, rv);
                    return;
                }
                big_len = same;
                clen = @min(small_len, big_len);
            }
            setLinkByFlag(self, big_is_left, big_index, @intCast(ptr));
            big_is_left = true;
            big_index = ptr;
            ptr = @intCast(leftAt(self, ptr).*);
        } else {
            if (same > small_len) {
                if (same >= break_length) {
                    const lv = leftAt(self, ptr).*;
                    const rv = rightAt(self, ptr).*;
                    setLinkByFlag(self, small_is_left, small_index, lv);
                    setLinkByFlag(self, big_is_left, big_index, rv);
                    return;
                }
                small_len = same;
                clen = @min(small_len, big_len);
            }
            setLinkByFlag(self, small_is_left, small_index, @intCast(ptr));
            small_is_left = false;
            small_index = ptr;
            ptr = @intCast(rightAt(self, ptr).*);
        }

        if (!(ptr > end_pos)) break;
    }

    setLinkByFlag(self, small_is_left, small_index, 0);
    setLinkByFlag(self, big_is_left, big_index, 0);
}

// --- main encoding loop --------------------------------------------------

fn charEst(self: *const Encoder, value: u8) u32 {
    return self.main_tree_len[value];
}

fn matchEst(self: *const Encoder, match_len: u32, match_pos: u32) u32 {
    const slot: u32 = mpSlot(self, match_pos);
    if (match_len < c.num_primary_len + 2) {
        const element = (num_chars - 2) + (slot << nl_shift) + match_len;
        return @as(u32, self.main_tree_len[element]) + c.extra_bits[slot];
    }
    const element = (num_chars + c.num_primary_len) + (slot << nl_shift);
    return @as(u32, self.main_tree_len[element]) + self.secondary_tree_len[match_len - (c.num_primary_len + 2)] + c.extra_bits[slot];
}

inline fn dn(self: *Encoder, pos: isize) *DecisionNode {
    return &self.decision_node[@intCast(pos - self.dn_base)];
}

fn rptAt(self: *Encoder, pos: isize, which: u32) u32 {
    return dn(self, pos).repeated_offset[which];
}

fn redoFirstBlock(self: *Encoder, buf_pos_ptr: *isize) Error!bool {
    self.first_block = false;

    const buf_pos = buf_pos_ptr.*;
    var history_needed: isize = buf_pos - @as(isize, self.bufpos_last_output_block);

    const distance = @as(isize, self.bufpos_last_output_block) - @as(isize, self.window_size);
    if (distance < @as(isize, self.window_size)) {
        history_needed += distance;
    } else {
        history_needed += @as(isize, self.window_size);
    }

    const history_avail: isize = buf_pos + self.mem_base;
    if (history_needed > history_avail) return false;

    const start_at: isize = @intCast(self.bufpos_last_output_block);

    var split_at_literal: u32 = 0;
    var cks: u32 = 0;
    for (self.lit_data[0..self.literals]) |b| cks +%= b;
    var itc: u32 = 0;
    for (self.item_type[0 .. self.literals / 8 + 1]) |b| itc +%= b;
    var dck: u32 = 0;
    for (self.dist_data[0..self.distances]) |d| dck +%= d;
    _ = splitBlock(self, 0, self.literals, self.distances, &split_at_literal, null);

    _ = getBlockStats(self, 0, 0, split_at_literal);

    try createTrees(self, false);
    fixTreeCostEstimates(
        self,
    );

    @memset(self.tree_root, 0);
    @memset(self.item_type, 0);

    self.last_matchpos_offset = .{ 1, 1, 1 };
    self.repeated_offset_at_literal_zero = .{ 1, 1, 1 };

    self.input_running_total = 0;
    self.literals = 0;
    self.distances = 0;

    self.need_to_recalc_stats = true;
    self.next_tree_create = split_at_literal;

    buf_pos_ptr.* = start_at;
    return true;
}

fn optEncodeTop(self: *Encoder, bytes_read: usize) Error!void {
    var buf_pos: isize = @intCast(self.bufpos);
    const buf_pos_end: isize = buf_pos + @as(isize, @intCast(bytes_read));

    if (self.first_time_this_group) {
        self.first_time_this_group = false;
        self.next_tree_create = 10000;

        if (self.file_size_for_translation != 0) {
            outputBits(self, 1, 1);
            outputBits(self, 16, self.file_size_for_translation >> 16);
            outputBits(self, 16, self.file_size_for_translation & 65535);
        } else {
            outputBits(self, 1, 0);
        }
    } else {
        var i: isize = break_length;
        while (i > 0) : (i -= 1) {
            quickInsertBsearchFindmatch(self, buf_pos - i, buf_pos - @as(isize, self.window_size) + 4);
        }
    }

    main_loop: while (true) {
        while (buf_pos < buf_pos_end) {
            var chunk_end = (buf_pos + @as(isize, c.chunk_size)) & ~@as(isize, c.chunk_size - 1);
            if (chunk_end > buf_pos_end) chunk_end = buf_pos_end;

            var enc_match_len = binarySearchFindmatch(self, buf_pos);

            if (enc_match_len < c.min_match) {
                self.lit_data[self.literals] = memGet(self, buf_pos);
                self.literals += 1;
                buf_pos += 1;
                if (self.literals >= max_literal_items - 8) try blockEnd(self, buf_pos);
                continue;
            }

            if (enc_match_len + buf_pos > chunk_end) {
                enc_match_len = chunk_end - buf_pos;
                if (enc_match_len < c.min_match) {
                    self.lit_data[self.literals] = memGet(self, buf_pos);
                    self.literals += 1;
                    buf_pos += 1;
                    if (self.literals >= max_literal_items - 8) try blockEnd(self, buf_pos);
                    continue;
                }
            }

            if (enc_match_len < fast_decision_threshold) {
                var span: isize = buf_pos + enc_match_len;
                const epos: isize = buf_pos + look;
                const bpos: isize = buf_pos;

                self.dn_base = bpos;
                {
                    var me: u32 = 0;
                    const has2 = enc_match_len >= 2;
                    const mp2: u32 = if (has2) self.matchpos_table[2] else 0;
                    me = matchEst(self, 2, mp2);
                }
                // The C code writes decision_node[1] here, not node[bpos]; the
                // shifted pointer makes those the same slot as dn(bpos + 1).
                dn(self, bpos + 1).numbits = charEst(self, memGet(self, buf_pos));
                dn(self, bpos + 1).path = @intCast(buf_pos);

                var i: isize = c.min_match;
                while (i <= enc_match_len) : (i += 1) {
                    const mp = self.matchpos_table[@intCast(i)];
                    dn(self, buf_pos + i).numbits = matchEst(self, @intCast(i), mp);
                    dn(self, buf_pos + i).path = @intCast(buf_pos);
                    dn(self, buf_pos + i).link = mp;
                }

                dn(self, bpos).numbits = 0;
                dn(self, bpos).repeated_offset = self.last_matchpos_offset;

                while (true) {
                    buf_pos += 1;

                    const node = dn(self, buf_pos);
                    if (node.path != @as(u32, @intCast(buf_pos - 1))) {
                        const last_pos: isize = @intCast(node.path);
                        if (node.link >= c.num_repeated_offsets) {
                            self.last_matchpos_offset[0] = node.link - (c.num_repeated_offsets - 1);
                            self.last_matchpos_offset[1] = rptAt(self, last_pos, 0);
                            self.last_matchpos_offset[2] = rptAt(self, last_pos, 1);
                        } else if (node.link == 0) {
                            self.last_matchpos_offset[0] = rptAt(self, last_pos, 0);
                            self.last_matchpos_offset[1] = rptAt(self, last_pos, 1);
                            self.last_matchpos_offset[2] = rptAt(self, last_pos, 2);
                        } else if (node.link == 1) {
                            self.last_matchpos_offset[0] = rptAt(self, last_pos, 1);
                            self.last_matchpos_offset[1] = rptAt(self, last_pos, 0);
                            self.last_matchpos_offset[2] = rptAt(self, last_pos, 2);
                        } else {
                            self.last_matchpos_offset[0] = rptAt(self, last_pos, 2);
                            self.last_matchpos_offset[1] = rptAt(self, last_pos, 1);
                            self.last_matchpos_offset[2] = rptAt(self, last_pos, 0);
                        }
                    }

                    dn(self, buf_pos).repeated_offset = self.last_matchpos_offset;

                    if (span == buf_pos) break;

                    enc_match_len = binarySearchFindmatch(self, buf_pos);

                    if (enc_match_len + buf_pos > chunk_end) {
                        enc_match_len = chunk_end - buf_pos;
                        if (enc_match_len < c.min_match) enc_match_len = 0;
                    }

                    if (enc_match_len > fast_decision_threshold or buf_pos + enc_match_len >= epos) {
                        const match_pos = self.matchpos_table[@intCast(enc_match_len)];
                        dn(self, buf_pos + enc_match_len).link = match_pos;
                        dn(self, buf_pos + enc_match_len).path = @intCast(buf_pos);

                        if (match_pos == 3 and enc_match_len > 16) {
                            quickInsertBsearchFindmatch(self, buf_pos + 1, buf_pos - @as(isize, self.window_size) + 5);
                        } else {
                            var j: isize = 1;
                            while (j < enc_match_len) : (j += 1) {
                                quickInsertBsearchFindmatch(self, buf_pos + j, buf_pos + j - @as(isize, self.window_size) + 4);
                            }
                        }

                        buf_pos += enc_match_len;

                        if (match_pos >= c.num_repeated_offsets) {
                            self.last_matchpos_offset[2] = self.last_matchpos_offset[1];
                            self.last_matchpos_offset[1] = self.last_matchpos_offset[0];
                            self.last_matchpos_offset[0] = match_pos - (c.num_repeated_offsets - 1);
                        } else if (match_pos != 0) {
                            const temp = self.last_matchpos_offset[0];
                            self.last_matchpos_offset[0] = self.last_matchpos_offset[match_pos];
                            self.last_matchpos_offset[match_pos] = temp;
                        }

                        break;
                    }

                    if (enc_match_len > 2 or (enc_match_len == 2 and self.matchpos_table[2] < break_max_length_two_offset)) {
                        if (span < buf_pos + enc_match_len) {
                            const limit = @min(buf_pos + enc_match_len - bpos, @as(isize, look) - 1);
                            var j: isize = span - bpos + 1;
                            while (j <= limit) : (j += 1) {
                                self.decision_node[@intCast(j)].numbits = 0xFFFFFFFF;
                            }
                            span = buf_pos + enc_match_len;
                        }
                    }

                    const cum_numbits = dn(self, buf_pos).numbits;
                    var est: u32 = cum_numbits +% charEst(self, memGet(self, buf_pos));

                    if (est < dn(self, buf_pos + 1).numbits) {
                        dn(self, buf_pos + 1).numbits = est;
                        dn(self, buf_pos + 1).path = @intCast(buf_pos);
                    }

                    i = c.min_match;
                    while (i <= enc_match_len) : (i += 1) {
                        const mp = self.matchpos_table[@intCast(i)];
                        est = matchEst(self, @intCast(i), mp) +% cum_numbits;

                        if (est < dn(self, buf_pos + i).numbits) {
                            dn(self, buf_pos + i).numbits = est;
                            dn(self, buf_pos + i).path = @intCast(buf_pos);
                            dn(self, buf_pos + i).link = mp;
                        }
                    }
                }

                var iterations: u32 = 0;
                var next_prev_pos: u32 = dn(self, buf_pos).path;

                while (true) {
                    const prev_pos = next_prev_pos;
                    next_prev_pos = dn(self, @intCast(prev_pos)).path;
                    dn(self, @intCast(prev_pos)).path = @intCast(buf_pos);
                    buf_pos = @intCast(prev_pos);
                    iterations += 1;
                    if (buf_pos == bpos) break;
                }

                while (self.literals + iterations >= (max_literal_items - 8) or self.distances + iterations >= (max_dist_items - 8)) {
                    try blockEnd(self, buf_pos);
                }

                while (true) {
                    const node = dn(self, buf_pos);
                    if (node.path > @as(u32, @intCast(buf_pos + 1))) {
                        outMatch(self, node.path - @as(u32, @intCast(buf_pos)), dn(self, @intCast(node.path)).link);
                        buf_pos = @intCast(node.path);
                    } else {
                        self.lit_data[self.literals] = memGet(self, buf_pos);
                        self.literals += 1;
                        buf_pos += 1;
                    }
                    iterations -= 1;
                    if (iterations == 0) break;
                }

                if (self.literals >= self.next_tree_create) {
                    try updateTreeEstimates(
                        self,
                    );
                    self.next_tree_create +%= tree_create_interval;
                }

                if (self.first_block and (self.literals >= (max_literal_items - 512) or self.distances >= (max_dist_items - 512))) {
                    if (try redoFirstBlock(self, &buf_pos)) continue :main_loop;
                    try blockEnd(self, buf_pos);
                }
            } else {
                const match_pos = self.matchpos_table[@intCast(enc_match_len)];

                if (match_pos == 3 and enc_match_len > 16) {
                    quickInsertBsearchFindmatch(self, buf_pos + 1, buf_pos - @as(isize, self.window_size) + 5);
                } else {
                    var i: isize = 1;
                    while (i < enc_match_len) : (i += 1) {
                        quickInsertBsearchFindmatch(self, buf_pos + i, buf_pos + i - @as(isize, self.window_size) + 4);
                    }
                }

                buf_pos += enc_match_len;
                outMatch(self, @intCast(enc_match_len), match_pos);

                if (match_pos >= c.num_repeated_offsets) {
                    self.last_matchpos_offset[2] = self.last_matchpos_offset[1];
                    self.last_matchpos_offset[1] = self.last_matchpos_offset[0];
                    self.last_matchpos_offset[0] = match_pos - (c.num_repeated_offsets - 1);
                } else if (match_pos != 0) {
                    const temp = self.last_matchpos_offset[0];
                    self.last_matchpos_offset[0] = self.last_matchpos_offset[match_pos];
                    self.last_matchpos_offset[match_pos] = temp;
                }

                if (self.literals >= (max_literal_items - 8) or self.distances >= (max_dist_items - 8)) {
                    try blockEnd(self, buf_pos);
                }
            }
        }

        self.earliest_window_data_remaining = @intCast(buf_pos - @as(isize, self.window_size));

        if (bytes_read < c.chunk_size) {
            if (self.first_block) {
                if (try redoFirstBlock(self, &buf_pos)) continue :main_loop;
            }
            break;
        }

        const end_pos: isize = buf_pos - (@as(isize, self.window_size) - 4 - break_length);

        var i: isize = 1;
        while (i <= break_length) : (i += 1) {
            binarySearchRemoveNode(self, buf_pos - i, end_pos);
        }

        const real_buf_pos: isize = buf_pos + self.mem_base;
        if (real_buf_pos < @as(isize, self.window_size) + @as(isize, self.encoder_second_partition_size)) break;

        if (self.first_block) {
            if (try redoFirstBlock(self, &buf_pos)) continue :main_loop;
        }

        const part: usize = self.encoder_second_partition_size;
        const window_len: usize = self.window_size;
        std.mem.copyForwards(u8, self.real_mem_window[0..window_len], self.real_mem_window[part..][0..window_len]);
        std.mem.copyForwards(u32, self.real_left[0..window_len], self.real_left[part..][0..window_len]);
        std.mem.copyForwards(u32, self.real_right[0..window_len], self.real_right[part..][0..window_len]);

        self.earliest_window_data_remaining = @intCast(buf_pos - @as(isize, self.window_size));
        self.mem_base -= @as(isize, self.encoder_second_partition_size);

        break;
    }

    self.bufpos = @intCast(buf_pos);
}

fn encodeFlush(self: *Encoder) Error!void {
    if (self.input_running_total > 0) {
        if (self.bitcount < 32) {
            outputBits(self, @intCast(self.bitcount - 16), 0);
        }

        const output_size = self.out_cur;

        if (output_size > 0) {
            if (self.output_overflow) return error.LzxBufferOverflow;

            const compressed: u16 = @intCast(self.out_cur);
            const uncompressed: u16 = @intCast(self.input_running_total);

            self.output_buffer_size +%= 4 + compressed;
            self.output_buffer_block_count += 1;

            if (self.dest_pos + 4 + compressed > self.destination.len) {
                self.output_overflow = true;
                return error.LzxBufferOverflow;
            }

            std.mem.writeInt(u16, self.destination[self.dest_pos..][0..2], compressed, .little);
            std.mem.writeInt(u16, self.destination[self.dest_pos + 2 ..][0..2], uncompressed, .little);
            self.dest_pos += 4;

            @memcpy(self.destination[self.dest_pos..][0..compressed], self.out_buf[0..compressed]);
            self.dest_pos += compressed;
        }
    }

    self.input_running_total = 0;
    self.out_cur = 0;
    self.bitcount = 32;
    self.bitbuf = 0;
}

fn encodeStart(self: *Encoder) Error!void {
    const buf_pos: usize = @intCast(@as(isize, self.bufpos) + self.mem_base);
    const bytes_read = try readInput(self, buf_pos, c.chunk_size);
    if (bytes_read > 0) try optEncodeTop(self, bytes_read);
}

// --- tests ---------------------------------------------------------------

test "slot lookup table matches the C generator" {
    const allocator = std.testing.allocator;
    var dest: [1024]u8 = @splat(0);
    const encoder = try createCompressionWindow(allocator, &dest, 0x8000);
    defer destroyCompression(encoder);

    try std.testing.expectEqual(@as(u8, 0), encoder.slot_table[0]);
    try std.testing.expectEqual(@as(u8, 3), encoder.slot_table[3]);
    try std.testing.expectEqual(@as(u8, 4), encoder.slot_table[4]);
    try std.testing.expectEqual(@as(u8, 4), encoder.slot_table[5]);
    try std.testing.expectEqual(@as(u8, 5), encoder.slot_table[6]);
    try std.testing.expectEqual(@as(u8, 5), encoder.slot_table[7]);
    try std.testing.expectEqual(@as(u8, 16), encoder.slot_table[256]);
    try std.testing.expectEqual(@as(u8, 19), encoder.slot_table[1023]);
}

test "ones table counts set bits" {
    const allocator = std.testing.allocator;
    var dest: [64]u8 = @splat(0);
    const encoder = try createCompressionWindow(allocator, &dest, 0x8000);
    defer destroyCompression(encoder);

    try std.testing.expectEqual(@as(u8, 0), encoder.ones[0]);
    try std.testing.expectEqual(@as(u8, 1), encoder.ones[1]);
    try std.testing.expectEqual(@as(u8, 8), encoder.ones[0xFF]);
    try std.testing.expectEqual(@as(u8, 4), encoder.ones[0xF0]);
}

test "invalid window sizes are rejected" {
    const allocator = std.testing.allocator;
    var dest: [64]u8 = @splat(0);
    try std.testing.expectError(error.LzxInvalidData, createCompressionWindow(allocator, &dest, 0x4000));
    try std.testing.expectError(error.LzxInvalidData, createCompressionWindow(allocator, &dest, 0x30000));
}

test "compressing empty input writes nothing" {
    const allocator = std.testing.allocator;
    var dest: [4096]u8 = @splat(0);
    const encoder = try createCompressionWindow(allocator, &dest, 0x8000);
    defer destroyCompression(encoder);

    try flushCompression(encoder);
    try std.testing.expectEqual(@as(u32, 0), compressedSize(encoder));
    try std.testing.expectEqual(@as(u32, 0), blockCount(encoder));
}

test "compressing a tiny input writes one block header" {
    const allocator = std.testing.allocator;
    var dest: [4096]u8 = @splat(0);
    const encoder = try createCompressionWindow(allocator, &dest, 0x8000);
    defer destroyCompression(encoder);

    try compressBlock(encoder, "abc");
    try flushCompression(encoder);

    try std.testing.expectEqual(@as(u32, 1), blockCount(encoder));
    const compressed = std.mem.readInt(u16, dest[0..2], .little);
    const uncompressed = std.mem.readInt(u16, dest[2..4], .little);
    try std.testing.expectEqual(@as(u16, 3), uncompressed);
    try std.testing.expectEqual(@as(u32, 4 + compressed), compressedSize(encoder));
}

test "compress block rejects more than one chunk" {
    const allocator = std.testing.allocator;
    var dest: [4096]u8 = @splat(0);
    const encoder = try createCompressionWindow(allocator, &dest, 0x8000);
    defer destroyCompression(encoder);

    var big: [0x8001]u8 = undefined;
    @memset(&big, 0);
    try std.testing.expectError(error.LzxInvalidData, compressBlock(encoder, &big));
}

test "destination overflow is reported, not silently truncated" {
    const allocator = std.testing.allocator;
    var dest: [8]u8 = @splat(0);
    const encoder = try createCompressionWindow(allocator, &dest, 0x8000);
    defer destroyCompression(encoder);

    try compressBlock(encoder, "abc");
    try std.testing.expectError(error.LzxBufferOverflow, flushCompression(encoder));
}

test "window base slides back by the secondary partition" {
    const allocator = std.testing.allocator;
    var dest: [1024 * 1024]u8 = @splat(0);
    const encoder = try createCompressionWindow(allocator, &dest, 0x8000);
    defer destroyCompression(encoder);

    try std.testing.expectEqual(@as(isize, -0x8000), encoder.mem_base);

    var data: [0x8000]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i *% 31);

    try compressBlock(encoder, &data);
    try compressBlock(encoder, &data);
    try compressBlock(encoder, &data);
    try compressBlock(encoder, &data);
    try flushCompression(encoder);

    // After four chunks the window slid once: base = 32768 - 65536.
    try std.testing.expectEqual(@as(isize, -0x8000 - 0x10000), encoder.mem_base);
}
