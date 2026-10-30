// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// This is an altered, Zig port of tinyxml2 11.0.0 by Lee Thomason
// (www.grinninglizard.com), originally distributed under the zlib license.
// The original notice is retained here:
//
//   Original code by Lee Thomason (www.grinninglizard.com)
//
//   This software is provided 'as-is', without any express or implied
//   warranty. In no event will the authors be held liable for any
//   damages arising from the use of this software.
//
//   Permission is granted to anyone to use this software for any
//   purpose, including commercial applications, and to alter it and
//   redistribute it freely, subject to the following restrictions:
//
//   1. The origin of this software must not be misrepresented; you must
//   not claim that you wrote the original software. If you use this
//   software in a product, an acknowledgment in the product documentation
//   would be appreciated but is not required.
//
//   2. Altered source versions must be plainly marked as such, and
//   must not be misrepresented as being the original software.
//
//   3. This notice may not be removed or altered from any source
//   distribution.

//! tinyxml2 11.0.0 ported to Zig 0.17.0.
//!
//! The DOM, parser, printer, and numeric conversion behavior follow
//! `XexTool/third_party/tinyxml2/tinyxml2.cpp`. The public shape is Zig:
//! values are slices, optional nodes replace null pointers, allocation failure
//! is an error, and the document owns every node it created.
//!
//! Typical use:
//!
//! ```zig
//! var doc: XMLDocument = undefined;
//! doc.init(gpa, .{});
//! defer doc.deinit();
//! _ = try doc.parse("<root a=\"1\">text</root>");
//! var printer = try XMLPrinter.init(gpa, .{});
//! defer printer.deinit();
//! try doc.print(&printer);
//! // printer.cstr() == "<root a=\"1\">text</root>\n"
//! ```

const std = @import("std");
const Allocator = std.mem.Allocator;
const util = @import("util.zig");

pub const XMLError = util.XMLError;
pub const error_count = util.error_count;
pub const errorIDToName = util.errorIDToName;
pub const errorIDFromInt = util.errorIDFromInt;
pub const TIXML2_MAJOR_VERSION = 11;
pub const TIXML2_MINOR_VERSION = 0;
pub const TIXML2_PATCH_VERSION = 0;
pub const TIXML2_MAX_ELEMENT_DEPTH = 500;

/// Public fallible operations. `OutOfMemory` is the only expected allocator
/// error; the others name caller misuse that the C++ version answers with a
/// null pointer or an assertion.
pub const Error = error{
    OutOfMemory,
    WrongDocument,
    NotAChild,
    CannotCloneDocument,
};

/// `enum Whitespace`.
pub const Whitespace = enum {
    preserve,
    collapse,
    pedantic,
};

/// `XMLElement::ElementClosingType`.
pub const ClosingType = enum {
    open,
    closed,
    closing,
};

pub const NodeKind = enum {
    document,
    element,
    text,
    comment,
    declaration,
    unknown,
};

pub const DocumentOptions = struct {
    process_entities: bool = true,
    whitespace: Whitespace = .preserve,
};

pub const PrinterOptions = struct {
    compact: bool = false,
    depth: i32 = 0,
    /// tinyxml2 11 escapes `'` in attribute values by default.
    escape_apos_in_attributes: bool = true,
};

/// A NUL-terminated parse buffer plus its real length. Reads at `len` observe
/// the sentinel, never memory beyond the allocation.
const Buffer = struct {
    bytes: [:0]u8,

    fn at(self: Buffer, i: usize) u8 {
        return if (i < self.bytes.len) self.bytes[i] else 0;
    }

    fn matchesAt(self: Buffer, p: usize, lit: []const u8) bool {
        if (p + lit.len > self.bytes.len) return false;
        return std.mem.eql(u8, self.bytes[p..][0..lit.len], lit);
    }
};

fn detailName(buf: []u8, prefix: []const u8, name: []const u8) []const u8 {
    var n: usize = 0;
    const first = @min(prefix.len, buf.len);
    @memcpy(buf[0..first], prefix[0..first]);
    n += first;
    const room = buf.len - n;
    const second = @min(name.len, room);
    @memcpy(buf[n..][0..second], name[0..second]);
    n += second;
    return buf[0..n];
}

// ---------- XMLNode ---------- //

/// Base node for every DOM object except attributes. The reference uses a
/// class hierarchy; this port uses one struct with a kind tag. `toElement`,
/// `toText`, and friends provide the same guarded casts.
pub const XMLNode = struct {
    doc: *XMLDocument,
    parent: ?*XMLNode = null,
    first_child: ?*XMLNode = null,
    last_child: ?*XMLNode = null,
    prev: ?*XMLNode = null,
    next: ?*XMLNode = null,
    value_pair: util.StrPair = .{},
    line: i32 = 0,
    user_data: ?*anyopaque = null,
    kind: NodeKind,
    closing_type: ClosingType = .open,
    root_attribute: ?*XMLAttribute = null,
    is_cdata: bool = false,

    pub fn getDocument(self: *const XMLNode) *XMLDocument {
        return self.doc;
    }

    pub fn setUserData(self: *XMLNode, data: ?*anyopaque) void {
        self.user_data = data;
    }

    pub fn getUserData(self: *const XMLNode) ?*anyopaque {
        return self.user_data;
    }

    pub fn toElement(self: *XMLNode) ?*XMLNode {
        return if (self.kind == .element) self else null;
    }

    pub fn toText(self: *XMLNode) ?*XMLNode {
        return if (self.kind == .text) self else null;
    }

    pub fn toComment(self: *XMLNode) ?*XMLNode {
        return if (self.kind == .comment) self else null;
    }

    pub fn toDeclaration(self: *XMLNode) ?*XMLNode {
        return if (self.kind == .declaration) self else null;
    }

    pub fn toUnknown(self: *XMLNode) ?*XMLNode {
        return if (self.kind == .unknown) self else null;
    }

    pub fn toDocument(self: *XMLNode) ?*XMLDocument {
        return if (self.kind == .document) self.doc else null;
    }

    pub fn value(self: *const XMLNode) ?[]const u8 {
        if (self.kind == .document) return null;
        return self.value_pair.getStr();
    }

    pub fn setValue(self: *XMLNode, val: []const u8) Error!void {
        try self.value_pair.setStr(self.doc.allocator, val);
    }

    /// `SetValue(val, staticMem=true)`: the caller owns `val`'s storage.
    pub fn setValueStatic(self: *XMLNode, val: []const u8) void {
        self.value_pair.setInterned(self.doc.allocator, val);
    }

    pub fn lineNum(self: *const XMLNode) i32 {
        return self.line;
    }

    pub fn parentNode(self: *const XMLNode) ?*XMLNode {
        return self.parent;
    }

    pub fn noChildren(self: *const XMLNode) bool {
        return self.first_child == null;
    }

    pub fn firstChild(self: *const XMLNode) ?*XMLNode {
        return self.first_child;
    }

    pub fn lastChild(self: *const XMLNode) ?*XMLNode {
        return self.last_child;
    }

    pub fn previousSibling(self: *const XMLNode) ?*XMLNode {
        return self.prev;
    }

    pub fn nextSibling(self: *const XMLNode) ?*XMLNode {
        return self.next;
    }

    pub fn childElementCount(self: *const XMLNode, name_wanted: ?[]const u8) i32 {
        var count: i32 = 0;
        var e = self.firstChildElement(name_wanted);
        while (e) |element| {
            e = element.nextSiblingElement(name_wanted);
            count += 1;
        }
        return count;
    }

    pub fn firstChildElement(self: *const XMLNode, name_wanted: ?[]const u8) ?*XMLNode {
        var node = self.first_child;
        while (node) |n| {
            if (toElementWithName(n, name_wanted)) |element| return element;
            node = n.next;
        }
        return null;
    }

    pub fn lastChildElement(self: *const XMLNode, name_wanted: ?[]const u8) ?*XMLNode {
        var node = self.last_child;
        while (node) |n| {
            if (toElementWithName(n, name_wanted)) |element| return element;
            node = n.prev;
        }
        return null;
    }

    pub fn nextSiblingElement(self: *const XMLNode, name_wanted: ?[]const u8) ?*XMLNode {
        var node = self.next;
        while (node) |n| {
            if (toElementWithName(n, name_wanted)) |element| return element;
            node = n.next;
        }
        return null;
    }

    pub fn previousSiblingElement(self: *const XMLNode, name_wanted: ?[]const u8) ?*XMLNode {
        var node = self.prev;
        while (node) |n| {
            if (toElementWithName(n, name_wanted)) |element| return element;
            node = n.prev;
        }
        return null;
    }

    fn toElementWithName(node: *const XMLNode, name_wanted: ?[]const u8) ?*XMLNode {
        if (node.kind != .element) return null;
        if (name_wanted) |want| {
            if (!std.mem.eql(u8, node.value_pair.getStr(), want)) return null;
        }
        // C++ const-casts here; node navigation is presented as mutable because
        // the document itself is owned mutably by the caller.
        return @constCast(node);
    }

    pub fn insertEndChild(self: *XMLNode, add_this: *XMLNode) Error!*XMLNode {
        if (add_this.doc != self.doc) return error.WrongDocument;
        insertChildPreamble(add_this);
        if (self.last_child) |last| {
            last.next = add_this;
            add_this.prev = last;
            self.last_child = add_this;
            add_this.next = null;
        } else {
            self.first_child = add_this;
            self.last_child = add_this;
            add_this.prev = null;
            add_this.next = null;
        }
        add_this.parent = self;
        return add_this;
    }

    pub fn linkEndChild(self: *XMLNode, add_this: *XMLNode) Error!*XMLNode {
        return self.insertEndChild(add_this);
    }

    pub fn insertFirstChild(self: *XMLNode, add_this: *XMLNode) Error!*XMLNode {
        if (add_this.doc != self.doc) return error.WrongDocument;
        insertChildPreamble(add_this);
        if (self.first_child) |first| {
            first.prev = add_this;
            add_this.next = first;
            self.first_child = add_this;
            add_this.prev = null;
        } else {
            self.first_child = add_this;
            self.last_child = add_this;
            add_this.prev = null;
            add_this.next = null;
        }
        add_this.parent = self;
        return add_this;
    }

    pub fn insertAfterChild(self: *XMLNode, after_this: *XMLNode, add_this: *XMLNode) Error!*XMLNode {
        if (add_this.doc != self.doc) return error.WrongDocument;
        if (after_this.parent != self) return error.NotAChild;
        if (after_this == add_this) return add_this;
        if (after_this.next == null) return self.insertEndChild(add_this);
        insertChildPreamble(add_this);
        add_this.prev = after_this;
        add_this.next = after_this.next;
        after_this.next.?.prev = add_this;
        after_this.next = add_this;
        add_this.parent = self;
        return add_this;
    }

    pub fn deleteChildren(self: *XMLNode) void {
        while (self.first_child) |child| {
            self.deleteChildUnchecked(child);
        }
        self.first_child = null;
        self.last_child = null;
    }

    pub fn deleteChild(self: *XMLNode, node: *XMLNode) Error!void {
        if (node.parent != self) return error.NotAChild;
        self.deleteChildUnchecked(node);
    }

    fn deleteChildUnchecked(self: *XMLNode, node: *XMLNode) void {
        self.unlink(node);
        self.doc.destroyTree(node);
    }

    fn unlink(self: *XMLNode, child: *XMLNode) void {
        std.debug.assert(child.parent == self);
        if (self.first_child == child) self.first_child = child.next;
        if (self.last_child == child) self.last_child = child.prev;
        if (child.prev) |prev| prev.next = child.next;
        if (child.next) |next| next.prev = child.prev;
        child.next = null;
        child.prev = null;
        child.parent = null;
    }

    fn insertChildPreamble(insert_this: *XMLNode) void {
        if (insert_this.parent) |parent| {
            parent.unlink(insert_this);
        } else {
            insert_this.doc.markInUse(insert_this);
        }
    }

    pub fn shallowClone(self: *const XMLNode, document: ?*XMLDocument) Error!*XMLNode {
        const target = document orelse self.doc;
        switch (self.kind) {
            .element => {
                const element = try target.newElement(self.name());
                var attr = self.root_attribute;
                while (attr) |a| {
                    try element.setAttribute(a.name(), a.value());
                    attr = a.next;
                }
                return element;
            },
            .text => {
                const text = try target.newText(self.value_pair.getStr());
                text.setCData(self.is_cdata);
                return text;
            },
            .comment => return target.newComment(self.value_pair.getStr()),
            .declaration => return target.newDeclaration(self.value_pair.getStr()),
            .unknown => return target.newUnknown(self.value_pair.getStr()),
            .document => return error.CannotCloneDocument,
        }
    }

    pub fn deepClone(self: *const XMLNode, target: ?*XMLDocument) Error!*XMLNode {
        const clone = try self.shallowClone(target);
        var child = self.first_child;
        while (child) |c| {
            _ = try clone.insertEndChild(try c.deepClone(target));
            child = c.next;
        }
        return clone;
    }

    pub fn shallowEqual(self: *const XMLNode, compare: *const XMLNode) bool {
        switch (self.kind) {
            .element => {
                if (compare.kind != .element) return false;
                if (!std.mem.eql(u8, compare.name(), self.name())) return false;
                var a = self.root_attribute;
                var b = compare.root_attribute;
                while (a != null and b != null) {
                    if (!std.mem.eql(u8, a.?.value(), b.?.value())) return false;
                    a = a.?.next;
                    b = b.?.next;
                }
                // The reference compares values only, not attribute names.
                return a == null and b == null;
            },
            .text => {
                if (compare.kind != .text) return false;
                return std.mem.eql(u8, compare.value_pair.getStr(), self.value_pair.getStr());
            },
            .comment => {
                if (compare.kind != .comment) return false;
                return std.mem.eql(u8, compare.value_pair.getStr(), self.value_pair.getStr());
            },
            .declaration => {
                if (compare.kind != .declaration) return false;
                return std.mem.eql(u8, compare.value_pair.getStr(), self.value_pair.getStr());
            },
            .unknown => {
                if (compare.kind != .unknown) return false;
                return std.mem.eql(u8, compare.value_pair.getStr(), self.value_pair.getStr());
            },
            .document => return false,
        }
    }

    pub fn accept(self: *const XMLNode, visitor: *const XMLVisitor) bool {
        switch (self.kind) {
            .document => {
                if (visitor.visitEnterDocument(self.doc)) {
                    var child = self.first_child;
                    while (child) |c| {
                        if (!c.accept(visitor)) break;
                        child = c.next;
                    }
                }
                return visitor.visitExitDocument(self.doc);
            },
            .element => {
                if (visitor.visitEnterElement(self, self.root_attribute)) {
                    var child = self.first_child;
                    while (child) |c| {
                        if (!c.accept(visitor)) break;
                        child = c.next;
                    }
                }
                return visitor.visitExitElement(self);
            },
            .text => return visitor.visitText(self),
            .comment => return visitor.visitComment(self),
            .declaration => return visitor.visitDeclaration(self),
            .unknown => return visitor.visitUnknown(self),
        }
    }

    pub fn print(self: *const XMLNode, printer: *XMLPrinter) Error!void {
        try printer.print(self);
    }

    // ----- element and attribute access ----- //

    pub fn name(self: *const XMLNode) []const u8 {
        std.debug.assert(self.kind == .element);
        return self.value_pair.getStr();
    }

    pub fn setName(self: *XMLNode, str: []const u8) Error!void {
        try self.setValue(str);
    }

    pub fn setNameStatic(self: *XMLNode, str: []const u8) void {
        self.setValueStatic(str);
    }

    pub fn firstAttribute(self: *const XMLNode) ?*XMLAttribute {
        std.debug.assert(self.kind == .element);
        return self.root_attribute;
    }

    pub fn findAttribute(self: *const XMLNode, name_wanted: []const u8) ?*XMLAttribute {
        var attr = self.root_attribute;
        while (attr) |a| {
            if (std.mem.eql(u8, a.name(), name_wanted)) return a;
            attr = a.next;
        }
        return null;
    }

    pub fn attribute(self: *const XMLNode, name_wanted: []const u8, value_wanted: ?[]const u8) ?[]const u8 {
        const attr = self.findAttribute(name_wanted) orelse return null;
        if (value_wanted) |want| {
            if (!std.mem.eql(u8, attr.value(), want)) return null;
        }
        return attr.value();
    }

    fn findOrCreateAttribute(self: *XMLNode, name_wanted: []const u8) Error!*XMLAttribute {
        var last: ?*XMLAttribute = null;
        var attr = self.root_attribute;
        while (attr) |a| {
            if (std.mem.eql(u8, a.name(), name_wanted)) return a;
            last = a;
            attr = a.next;
        }
        const created = try self.doc.createAttribute();
        created.setName(name_wanted) catch |err| {
            self.doc.freeAttribute(created);
            return err;
        };
        if (last) |l| {
            l.next = created;
        } else {
            self.root_attribute = created;
        }
        return created;
    }

    pub fn deleteAttribute(self: *XMLNode, name_wanted: []const u8) void {
        var prev: ?*XMLAttribute = null;
        var attr = self.root_attribute;
        while (attr) |a| {
            if (std.mem.eql(u8, a.name(), name_wanted)) {
                if (prev) |p| {
                    p.next = a.next;
                } else {
                    self.root_attribute = a.next;
                }
                self.doc.freeAttribute(a);
                return;
            }
            prev = a;
            attr = a.next;
        }
    }

    pub fn setAttribute(self: *XMLNode, name_wanted: []const u8, new_value: []const u8) Error!void {
        const attr = try self.findOrCreateAttribute(name_wanted);
        try attr.setValue(new_value);
    }

    pub fn setAttributeInt(self: *XMLNode, name_wanted: []const u8, new_value: i32) Error!void {
        var buf: [200]u8 = undefined;
        try self.setAttribute(name_wanted, util.formatInt(&buf, new_value));
    }

    pub fn setAttributeUnsigned(self: *XMLNode, name_wanted: []const u8, new_value: u32) Error!void {
        var buf: [200]u8 = undefined;
        try self.setAttribute(name_wanted, util.formatUnsigned(&buf, new_value));
    }

    pub fn setAttributeInt64(self: *XMLNode, name_wanted: []const u8, new_value: i64) Error!void {
        var buf: [200]u8 = undefined;
        try self.setAttribute(name_wanted, util.formatInt64(&buf, new_value));
    }

    pub fn setAttributeUnsigned64(self: *XMLNode, name_wanted: []const u8, new_value: u64) Error!void {
        var buf: [200]u8 = undefined;
        try self.setAttribute(name_wanted, util.formatUnsigned64(&buf, new_value));
    }

    pub fn setAttributeBool(self: *XMLNode, name_wanted: []const u8, new_value: bool) Error!void {
        var buf: [200]u8 = undefined;
        try self.setAttribute(name_wanted, util.formatBool(&buf, new_value, 0));
    }

    pub fn setAttributeDouble(self: *XMLNode, name_wanted: []const u8, new_value: f64) Error!void {
        var buf: [200]u8 = undefined;
        try self.setAttribute(name_wanted, util.formatDouble(&buf, new_value));
    }

    pub fn setAttributeFloat(self: *XMLNode, name_wanted: []const u8, new_value: f32) Error!void {
        var buf: [200]u8 = undefined;
        try self.setAttribute(name_wanted, util.formatFloat(&buf, new_value));
    }

    pub fn queryIntAttribute(self: *const XMLNode, name_wanted: []const u8, out: *i32) XMLError {
        const attr = self.findAttribute(name_wanted) orelse return .no_attribute;
        return attr.queryIntValue(out);
    }

    pub fn queryUnsignedAttribute(self: *const XMLNode, name_wanted: []const u8, out: *u32) XMLError {
        const attr = self.findAttribute(name_wanted) orelse return .no_attribute;
        return attr.queryUnsignedValue(out);
    }

    pub fn queryInt64Attribute(self: *const XMLNode, name_wanted: []const u8, out: *i64) XMLError {
        const attr = self.findAttribute(name_wanted) orelse return .no_attribute;
        return attr.queryInt64Value(out);
    }

    pub fn queryUnsigned64Attribute(self: *const XMLNode, name_wanted: []const u8, out: *u64) XMLError {
        const attr = self.findAttribute(name_wanted) orelse return .no_attribute;
        return attr.queryUnsigned64Value(out);
    }

    pub fn queryBoolAttribute(self: *const XMLNode, name_wanted: []const u8, out: *bool) XMLError {
        const attr = self.findAttribute(name_wanted) orelse return .no_attribute;
        return attr.queryBoolValue(out);
    }

    pub fn queryDoubleAttribute(self: *const XMLNode, name_wanted: []const u8, out: *f64) XMLError {
        const attr = self.findAttribute(name_wanted) orelse return .no_attribute;
        return attr.queryDoubleValue(out);
    }

    pub fn queryFloatAttribute(self: *const XMLNode, name_wanted: []const u8, out: *f32) XMLError {
        const attr = self.findAttribute(name_wanted) orelse return .no_attribute;
        return attr.queryFloatValue(out);
    }

    pub fn queryStringAttribute(self: *const XMLNode, name_wanted: []const u8, out: *?[]const u8) XMLError {
        const attr = self.findAttribute(name_wanted) orelse return .no_attribute;
        out.* = attr.value();
        return .success;
    }

    pub fn intAttribute(self: *const XMLNode, name_wanted: []const u8, default_value: i32) i32 {
        var result = default_value;
        _ = self.queryIntAttribute(name_wanted, &result);
        return result;
    }

    pub fn unsignedAttribute(self: *const XMLNode, name_wanted: []const u8, default_value: u32) u32 {
        var result = default_value;
        _ = self.queryUnsignedAttribute(name_wanted, &result);
        return result;
    }

    pub fn int64Attribute(self: *const XMLNode, name_wanted: []const u8, default_value: i64) i64 {
        var result = default_value;
        _ = self.queryInt64Attribute(name_wanted, &result);
        return result;
    }

    pub fn unsigned64Attribute(self: *const XMLNode, name_wanted: []const u8, default_value: u64) u64 {
        var result = default_value;
        _ = self.queryUnsigned64Attribute(name_wanted, &result);
        return result;
    }

    pub fn boolAttribute(self: *const XMLNode, name_wanted: []const u8, default_value: bool) bool {
        var result = default_value;
        _ = self.queryBoolAttribute(name_wanted, &result);
        return result;
    }

    pub fn doubleAttribute(self: *const XMLNode, name_wanted: []const u8, default_value: f64) f64 {
        var result = default_value;
        _ = self.queryDoubleAttribute(name_wanted, &result);
        return result;
    }

    pub fn floatAttribute(self: *const XMLNode, name_wanted: []const u8, default_value: f32) f32 {
        var result = default_value;
        _ = self.queryFloatAttribute(name_wanted, &result);
        return result;
    }

    // ----- text access ----- //

    pub fn getText(self: *const XMLNode) ?[]const u8 {
        var node = self.first_child;
        while (node) |n| {
            if (n.kind == .comment) {
                node = n.next;
                continue;
            }
            break;
        }
        if (node) |n| {
            if (n.kind == .text) return n.value_pair.getStr();
        }
        return null;
    }

    pub fn setText(self: *XMLNode, text: []const u8) Error!void {
        if (self.first_child) |first| {
            if (first.kind == .text) {
                try first.setValue(text);
                return;
            }
        }
        const node = try self.doc.newText(text);
        _ = try self.insertFirstChild(node);
    }

    pub fn setTextInt(self: *XMLNode, new_value: i32) Error!void {
        var buf: [200]u8 = undefined;
        try self.setText(util.formatInt(&buf, new_value));
    }

    pub fn setTextUnsigned(self: *XMLNode, new_value: u32) Error!void {
        var buf: [200]u8 = undefined;
        try self.setText(util.formatUnsigned(&buf, new_value));
    }

    pub fn setTextInt64(self: *XMLNode, new_value: i64) Error!void {
        var buf: [200]u8 = undefined;
        try self.setText(util.formatInt64(&buf, new_value));
    }

    pub fn setTextUnsigned64(self: *XMLNode, new_value: u64) Error!void {
        var buf: [200]u8 = undefined;
        try self.setText(util.formatUnsigned64(&buf, new_value));
    }

    pub fn setTextBool(self: *XMLNode, new_value: bool) Error!void {
        var buf: [200]u8 = undefined;
        try self.setText(util.formatBool(&buf, new_value, 0));
    }

    pub fn setTextDouble(self: *XMLNode, new_value: f64) Error!void {
        var buf: [200]u8 = undefined;
        try self.setText(util.formatDouble(&buf, new_value));
    }

    pub fn setTextFloat(self: *XMLNode, new_value: f32) Error!void {
        var buf: [200]u8 = undefined;
        try self.setText(util.formatFloat(&buf, new_value));
    }

    fn childText(self: *const XMLNode) ?[]const u8 {
        if (self.first_child) |first| {
            if (first.kind == .text) return first.value_pair.getStr();
        }
        return null;
    }

    pub fn queryIntText(self: *const XMLNode, out: *i32) XMLError {
        const text = self.childText() orelse return .no_text_node;
        return if (util.toInt(text, out)) .success else .can_not_convert_text;
    }

    pub fn queryUnsignedText(self: *const XMLNode, out: *u32) XMLError {
        const text = self.childText() orelse return .no_text_node;
        return if (util.toUnsigned(text, out)) .success else .can_not_convert_text;
    }

    pub fn queryInt64Text(self: *const XMLNode, out: *i64) XMLError {
        const text = self.childText() orelse return .no_text_node;
        return if (util.toInt64(text, out)) .success else .can_not_convert_text;
    }

    pub fn queryUnsigned64Text(self: *const XMLNode, out: *u64) XMLError {
        const text = self.childText() orelse return .no_text_node;
        return if (util.toUnsigned64(text, out)) .success else .can_not_convert_text;
    }

    pub fn queryBoolText(self: *const XMLNode, out: *bool) XMLError {
        const text = self.childText() orelse return .no_text_node;
        return if (util.toBool(text, out)) .success else .can_not_convert_text;
    }

    pub fn queryDoubleText(self: *const XMLNode, out: *f64) XMLError {
        const text = self.childText() orelse return .no_text_node;
        return if (util.toDouble(text, out)) .success else .can_not_convert_text;
    }

    pub fn queryFloatText(self: *const XMLNode, out: *f32) XMLError {
        const text = self.childText() orelse return .no_text_node;
        return if (util.toFloat(text, out)) .success else .can_not_convert_text;
    }

    pub fn intText(self: *const XMLNode, default_value: i32) i32 {
        var result = default_value;
        _ = self.queryIntText(&result);
        return result;
    }

    pub fn unsignedText(self: *const XMLNode, default_value: u32) u32 {
        var result = default_value;
        _ = self.queryUnsignedText(&result);
        return result;
    }

    pub fn int64Text(self: *const XMLNode, default_value: i64) i64 {
        var result = default_value;
        _ = self.queryInt64Text(&result);
        return result;
    }

    pub fn unsigned64Text(self: *const XMLNode, default_value: u64) u64 {
        var result = default_value;
        _ = self.queryUnsigned64Text(&result);
        return result;
    }

    pub fn boolText(self: *const XMLNode, default_value: bool) bool {
        var result = default_value;
        _ = self.queryBoolText(&result);
        return result;
    }

    pub fn doubleText(self: *const XMLNode, default_value: f64) f64 {
        var result = default_value;
        _ = self.queryDoubleText(&result);
        return result;
    }

    pub fn floatText(self: *const XMLNode, default_value: f32) f32 {
        var result = default_value;
        _ = self.queryFloatText(&result);
        return result;
    }

    pub fn insertNewChildElement(self: *XMLNode, name_wanted: []const u8) Error!*XMLNode {
        const node = try self.doc.newElement(name_wanted);
        _ = try self.insertEndChild(node);
        return node;
    }

    pub fn insertNewComment(self: *XMLNode, text: []const u8) Error!*XMLNode {
        const node = try self.doc.newComment(text);
        _ = try self.insertEndChild(node);
        return node;
    }

    pub fn insertNewText(self: *XMLNode, text: []const u8) Error!*XMLNode {
        const node = try self.doc.newText(text);
        _ = try self.insertEndChild(node);
        return node;
    }

    pub fn insertNewDeclaration(self: *XMLNode, text: ?[]const u8) Error!*XMLNode {
        const node = try self.doc.newDeclaration(text);
        _ = try self.insertEndChild(node);
        return node;
    }

    pub fn insertNewUnknown(self: *XMLNode, text: []const u8) Error!*XMLNode {
        const node = try self.doc.newUnknown(text);
        _ = try self.insertEndChild(node);
        return node;
    }

    pub fn closingType(self: *const XMLNode) ClosingType {
        return self.closing_type;
    }

    pub fn cdata(self: *const XMLNode) bool {
        return self.is_cdata;
    }

    pub fn setCData(self: *XMLNode, is_cdata: bool) void {
        self.is_cdata = is_cdata;
    }

    // ----- parsing ----- //

    fn parseDeep(self: *XMLNode, buf: Buffer, start: usize, parent_end_tag: ?*util.StrPair) Error!?usize {
        return switch (self.kind) {
            .element => self.parseElementDeep(buf, start, parent_end_tag),
            .text => self.parseTextNodeDeep(buf, start),
            .comment => self.parseBoundedDeep(buf, start, "-->", util.comment, .error_parsing_comment),
            .declaration => self.parseBoundedDeep(buf, start, "?>", .{ .newlines = true }, .error_parsing_declaration),
            .unknown => self.parseBoundedDeep(buf, start, ">", .{ .newlines = true }, .error_parsing_unknown),
            .document => unreachable,
        };
    }

    fn parseBoundedDeep(self: *XMLNode, buf: Buffer, start: usize, end_tag: []const u8, flags: util.StrFlags, err: XMLError) Error!?usize {
        const result = try parseTextInto(self.doc.allocator, &self.value_pair, buf, start, end_tag, flags, &self.doc.parse_cur_line);
        if (result == null) self.doc.setError(err, self.line, null);
        return result;
    }

    fn parseTextNodeDeep(self: *XMLNode, buf: Buffer, start: usize) Error!?usize {
        if (self.is_cdata) {
            const result = try parseTextInto(self.doc.allocator, &self.value_pair, buf, start, "]]>", .{ .newlines = true }, &self.doc.parse_cur_line);
            if (result == null) self.doc.setError(.error_parsing_cdata, self.line, null);
            return result;
        }
        var flags = if (self.doc.process_entities) util.text_element else util.text_element_leave_entities;
        if (self.doc.whitespace_mode == .collapse) flags.collapse = true;
        const result = try parseTextInto(self.doc.allocator, &self.value_pair, buf, start, "<", flags, &self.doc.parse_cur_line);
        if (result) |end| {
            if (buf.at(end) != 0) return end - 1;
            return null;
        }
        self.doc.setError(.error_parsing_text, self.line, null);
        return null;
    }

    fn parseElementDeep(self: *XMLNode, buf: Buffer, start: usize, parent_end_tag: ?*util.StrPair) Error!?usize {
        var p = util.skipWhitespace(buf.bytes, start, &self.doc.parse_cur_line);
        if (buf.at(p) == '/') {
            self.closing_type = .closing;
            p += 1;
        }
        const name_end = try parseNameInto(self.doc.allocator, &self.value_pair, buf, p);
        if (self.value_pair.isEmpty()) return null;
        p = name_end orelse return null;
        const after_attrs = try self.parseAttributes(buf, p);
        const attrs_end = after_attrs orelse return null;
        if (buf.at(attrs_end) == 0 or self.closing_type != .open) return attrs_end;
        return self.parseNodeListDeep(buf, attrs_end, parent_end_tag);
    }

    fn parseAttributes(self: *XMLNode, buf: Buffer, start: usize) Error!?usize {
        var prev: ?*XMLAttribute = null;
        var p = start;
        while (true) {
            p = util.skipWhitespace(buf.bytes, p, &self.doc.parse_cur_line);
            if (buf.at(p) == 0) {
                var detail_buf: [1000]u8 = undefined;
                self.doc.setError(.error_parsing_element, self.line, detailName(&detail_buf, "XMLElement name=", self.name()));
                return null;
            }

            if (util.isNameStartChar(buf.at(p))) {
                const attr = try self.doc.createAttribute();
                attr.line = self.doc.parse_cur_line;
                const attr_line = attr.line;
                const parsed = attr.parseDeep(buf, p, self.doc.process_entities) catch |err| {
                    self.doc.freeAttribute(attr);
                    return err;
                };
                const attr_end = parsed orelse {
                    self.doc.freeAttribute(attr);
                    var detail_buf: [1000]u8 = undefined;
                    self.doc.setError(.error_parsing_attribute, attr_line, detailName(&detail_buf, "XMLElement name=", self.name()));
                    return null;
                };
                if (self.attribute(attr.name(), null) != null) {
                    self.doc.freeAttribute(attr);
                    var detail_buf: [1000]u8 = undefined;
                    self.doc.setError(.error_parsing_attribute, attr_line, detailName(&detail_buf, "XMLElement name=", self.name()));
                    return null;
                }
                if (prev) |last| {
                    last.next = attr;
                } else {
                    self.root_attribute = attr;
                }
                prev = attr;
                p = attr_end;
            } else if (buf.at(p) == '>') {
                p += 1;
                break;
            } else if (buf.at(p) == '/' and buf.at(p + 1) == '>') {
                self.closing_type = .closed;
                return p + 2;
            } else {
                self.doc.setError(.error_parsing_element, self.line, null);
                return null;
            }
        }
        return p;
    }

    fn parseNodeListDeep(self: *XMLNode, buf: Buffer, start: usize, parent_end_tag: ?*util.StrPair) Error!?usize {
        self.doc.parse_depth += 1;
        defer self.doc.parse_depth -= 1;

        if (self.doc.parse_depth == TIXML2_MAX_ELEMENT_DEPTH) {
            self.doc.setError(.element_depth_exceeded, self.doc.parse_cur_line, "Element nesting is too deep.");
        }
        if (self.doc.hasError()) return null;

        var first = true;
        var p = start;
        while (buf.at(p) != 0) {
            const identified = try self.doc.identify(buf, p, first);
            const node = identified.node orelse break;
            p = identified.pos;
            first = false;
            const initial_line = node.line;

            var end_tag: util.StrPair = .{};
            defer end_tag.deinit(self.doc.allocator);
            const parsed = node.parseDeep(buf, p, &end_tag) catch |err| {
                self.doc.deleteNode(node);
                return err;
            };
            const new_pos = parsed orelse {
                self.doc.deleteNode(node);
                if (!self.doc.hasError()) self.doc.setError(.error_parsing, initial_line, null);
                break;
            };
            p = new_pos;

            if (node.kind == .declaration) {
                var well_located = false;
                if (self.kind == .document) {
                    if (self.first_child) |fc| {
                        well_located = fc.kind == .declaration and
                            self.last_child != null and self.last_child.?.kind == .declaration;
                    } else {
                        well_located = true;
                    }
                }
                if (!well_located) {
                    var detail_buf: [1000]u8 = undefined;
                    self.doc.setError(.error_parsing_declaration, initial_line, detailName(&detail_buf, "XMLDeclaration value=", node.value_pair.getStr()));
                    self.doc.deleteNode(node);
                    break;
                }
            }

            if (node.kind == .element) {
                if (node.closing_type == .closing) {
                    if (parent_end_tag) |parent_end| {
                        node.value_pair.transferTo(self.doc.allocator, parent_end);
                    }
                    self.doc.deleteNode(node);
                    return p;
                }

                var mismatch = false;
                if (end_tag.isEmpty()) {
                    if (node.closing_type == .open) mismatch = true;
                } else {
                    if (node.closing_type != .open) {
                        mismatch = true;
                    } else if (!std.mem.eql(u8, end_tag.getStr(), node.name())) {
                        mismatch = true;
                    }
                }
                if (mismatch) {
                    var detail_buf: [1000]u8 = undefined;
                    self.doc.setError(.error_mismatched_element, initial_line, detailName(&detail_buf, "XMLElement name=", node.name()));
                    self.doc.deleteNode(node);
                    break;
                }
            }

            _ = try self.insertEndChild(node);
        }
        return null;
    }
};

/// The reference has a class per node kind. This port uses one `XMLNode` with
/// a kind tag; these aliases keep the familiar names in signatures.
pub const XMLElement = XMLNode;
pub const XMLText = XMLNode;
pub const XMLComment = XMLNode;
pub const XMLDeclaration = XMLNode;
pub const XMLUnknown = XMLNode;

fn parseTextInto(
    gpa: Allocator,
    pair: *util.StrPair,
    buf: Buffer,
    start: usize,
    end_tag: []const u8,
    flags: util.StrFlags,
    line: *i32,
) Allocator.Error!?usize {
    const end_char = end_tag[0];
    var p = start;
    while (buf.at(p) != 0) {
        if (buf.at(p) == end_char and buf.matchesAt(p, end_tag)) {
            try pair.set(gpa, buf.bytes[start..p], flags);
            return p + end_tag.len;
        } else if (buf.at(p) == '\n') {
            line.* += 1;
        }
        p += 1;
    }
    return null;
}

fn parseNameInto(gpa: Allocator, pair: *util.StrPair, buf: Buffer, start: usize) Allocator.Error!?usize {
    if (buf.at(start) == 0 or !util.isNameStartChar(buf.at(start))) return null;
    var p = start + 1;
    while (buf.at(p) != 0 and util.isNameChar(buf.at(p))) p += 1;
    try pair.set(gpa, buf.bytes[start..p], util.plain);
    return p;
}

// ---------- XMLAttribute ---------- //

pub const XMLAttribute = struct {
    name_pair: util.StrPair = .{},
    value_pair: util.StrPair = .{},
    line: i32 = 0,
    next: ?*XMLAttribute = null,
    doc: *XMLDocument,

    pub fn name(self: *const XMLAttribute) []const u8 {
        return self.name_pair.getStr();
    }

    pub fn value(self: *const XMLAttribute) []const u8 {
        return self.value_pair.getStr();
    }

    pub fn lineNum(self: *const XMLAttribute) i32 {
        return self.line;
    }

    pub fn nextAttribute(self: *const XMLAttribute) ?*XMLAttribute {
        return self.next;
    }

    pub fn intValue(self: *const XMLAttribute) i32 {
        var result: i32 = 0;
        _ = self.queryIntValue(&result);
        return result;
    }

    pub fn unsignedValue(self: *const XMLAttribute) u32 {
        var result: u32 = 0;
        _ = self.queryUnsignedValue(&result);
        return result;
    }

    pub fn int64Value(self: *const XMLAttribute) i64 {
        var result: i64 = 0;
        _ = self.queryInt64Value(&result);
        return result;
    }

    pub fn unsigned64Value(self: *const XMLAttribute) u64 {
        var result: u64 = 0;
        _ = self.queryUnsigned64Value(&result);
        return result;
    }

    pub fn boolValue(self: *const XMLAttribute) bool {
        var result = false;
        _ = self.queryBoolValue(&result);
        return result;
    }

    pub fn doubleValue(self: *const XMLAttribute) f64 {
        var result: f64 = 0;
        _ = self.queryDoubleValue(&result);
        return result;
    }

    pub fn floatValue(self: *const XMLAttribute) f32 {
        var result: f32 = 0;
        _ = self.queryFloatValue(&result);
        return result;
    }

    pub fn queryIntValue(self: *const XMLAttribute, out: *i32) XMLError {
        return if (util.toInt(self.value(), out)) .success else .wrong_attribute_type;
    }

    pub fn queryUnsignedValue(self: *const XMLAttribute, out: *u32) XMLError {
        return if (util.toUnsigned(self.value(), out)) .success else .wrong_attribute_type;
    }

    pub fn queryInt64Value(self: *const XMLAttribute, out: *i64) XMLError {
        return if (util.toInt64(self.value(), out)) .success else .wrong_attribute_type;
    }

    pub fn queryUnsigned64Value(self: *const XMLAttribute, out: *u64) XMLError {
        return if (util.toUnsigned64(self.value(), out)) .success else .wrong_attribute_type;
    }

    pub fn queryBoolValue(self: *const XMLAttribute, out: *bool) XMLError {
        return if (util.toBool(self.value(), out)) .success else .wrong_attribute_type;
    }

    pub fn queryDoubleValue(self: *const XMLAttribute, out: *f64) XMLError {
        return if (util.toDouble(self.value(), out)) .success else .wrong_attribute_type;
    }

    pub fn queryFloatValue(self: *const XMLAttribute, out: *f32) XMLError {
        return if (util.toFloat(self.value(), out)) .success else .wrong_attribute_type;
    }

    pub fn setValue(self: *XMLAttribute, new_value: []const u8) Error!void {
        try self.value_pair.setStr(self.doc.allocator, new_value);
    }

    pub fn setValueInt(self: *XMLAttribute, new_value: i32) Error!void {
        var buf: [200]u8 = undefined;
        try self.setValue(util.formatInt(&buf, new_value));
    }

    pub fn setValueUnsigned(self: *XMLAttribute, new_value: u32) Error!void {
        var buf: [200]u8 = undefined;
        try self.setValue(util.formatUnsigned(&buf, new_value));
    }

    pub fn setValueInt64(self: *XMLAttribute, new_value: i64) Error!void {
        var buf: [200]u8 = undefined;
        try self.setValue(util.formatInt64(&buf, new_value));
    }

    pub fn setValueUnsigned64(self: *XMLAttribute, new_value: u64) Error!void {
        var buf: [200]u8 = undefined;
        try self.setValue(util.formatUnsigned64(&buf, new_value));
    }

    pub fn setValueBool(self: *XMLAttribute, new_value: bool) Error!void {
        var buf: [200]u8 = undefined;
        try self.setValue(util.formatBool(&buf, new_value, 0));
    }

    pub fn setValueDouble(self: *XMLAttribute, new_value: f64) Error!void {
        var buf: [200]u8 = undefined;
        try self.setValue(util.formatDouble(&buf, new_value));
    }

    pub fn setValueFloat(self: *XMLAttribute, new_value: f32) Error!void {
        var buf: [200]u8 = undefined;
        try self.setValue(util.formatFloat(&buf, new_value));
    }

    fn setName(self: *XMLAttribute, name_wanted: []const u8) Error!void {
        try self.name_pair.setStr(self.doc.allocator, name_wanted);
    }

    fn parseDeep(self: *XMLAttribute, buf: Buffer, start: usize, process_entities: bool) Error!?usize {
        var p = start;
        p = (try parseNameInto(self.doc.allocator, &self.name_pair, buf, p)) orelse return null;
        if (buf.at(p) == 0) return null;
        p = util.skipWhitespace(buf.bytes, p, &self.doc.parse_cur_line);
        if (buf.at(p) != '=') return null;
        p += 1;
        p = util.skipWhitespace(buf.bytes, p, &self.doc.parse_cur_line);
        if (buf.at(p) != '"' and buf.at(p) != '\'') return null;
        const quote = buf.at(p);
        p += 1;
        const flags = if (process_entities) util.attribute_value else util.attribute_value_leave_entities;
        const end_tag = [1]u8{quote};
        return parseTextInto(self.doc.allocator, &self.value_pair, buf, p, &end_tag, flags, &self.doc.parse_cur_line);
    }
};

// ---------- XMLDocument ---------- //

pub const XMLDocument = struct {
    allocator: Allocator,
    node: XMLNode,
    write_bom: bool,
    process_entities: bool,
    whitespace_mode: Whitespace,
    error_id: XMLError,
    error_line_num: i32,
    error_buf: [1000]u8,
    error_len: usize,
    parse_cur_line: i32,
    parse_depth: i32,
    unlinked: std.ArrayListUnmanaged(*XMLNode),

    /// The document is self-referential (`node.doc` points back here), so it
    /// must be initialized in place through a pointer. Use `create`/`destroy`
    /// for heap ownership.
    pub fn init(self: *XMLDocument, allocator: Allocator, options: DocumentOptions) void {
        self.* = .{
            .allocator = allocator,
            .node = .{ .doc = self, .kind = .document },
            .write_bom = false,
            .process_entities = options.process_entities,
            .whitespace_mode = options.whitespace,
            .error_id = .success,
            .error_line_num = 0,
            .error_buf = undefined,
            .error_len = 0,
            .parse_cur_line = 0,
            .parse_depth = 0,
            .unlinked = .empty,
        };
    }

    pub fn create(allocator: Allocator, options: DocumentOptions) Error!*XMLDocument {
        const doc = try allocator.create(XMLDocument);
        doc.init(allocator, options);
        return doc;
    }

    pub fn destroy(self: *XMLDocument) void {
        const allocator = self.allocator;
        self.deinit();
        allocator.destroy(self);
    }

    pub fn deinit(self: *XMLDocument) void {
        self.clear();
        self.unlinked.deinit(self.allocator);
    }

    pub fn clear(self: *XMLDocument) void {
        self.node.deleteChildren();
        while (self.unlinked.items.len > 0) {
            const node = self.unlinked.pop().?;
            self.destroyTree(node);
        }
        self.clearError();
        self.parse_depth = 0;
    }

    pub fn deepCopy(self: *const XMLDocument, target: *XMLDocument) Error!void {
        if (target == self) return;
        target.clear();
        var node = self.node.first_child;
        while (node) |n| {
            _ = try target.insertEndChild(try n.deepClone(target));
            node = n.next;
        }
    }

    pub fn newElement(self: *XMLDocument, name: []const u8) Error!*XMLNode {
        const node = try self.createNode(.element);
        node.setName(name) catch |err| {
            self.deleteNode(node);
            return err;
        };
        return node;
    }

    pub fn newComment(self: *XMLDocument, text: []const u8) Error!*XMLNode {
        const node = try self.createNode(.comment);
        node.setValue(text) catch |err| {
            self.deleteNode(node);
            return err;
        };
        return node;
    }

    pub fn newText(self: *XMLDocument, text: []const u8) Error!*XMLNode {
        const node = try self.createNode(.text);
        node.setValue(text) catch |err| {
            self.deleteNode(node);
            return err;
        };
        return node;
    }

    pub fn newDeclaration(self: *XMLDocument, text: ?[]const u8) Error!*XMLNode {
        const node = try self.createNode(.declaration);
        node.setValue(text orelse "xml version=\"1.0\" encoding=\"UTF-8\"") catch |err| {
            self.deleteNode(node);
            return err;
        };
        return node;
    }

    pub fn newUnknown(self: *XMLDocument, text: []const u8) Error!*XMLNode {
        const node = try self.createNode(.unknown);
        node.setValue(text) catch |err| {
            self.deleteNode(node);
            return err;
        };
        return node;
    }

    pub fn deleteNode(self: *XMLDocument, node_opt: ?*XMLNode) void {
        const node = node_opt orelse return;
        std.debug.assert(node.doc == self);
        if (node.parent) |parent| {
            parent.unlink(node);
            self.destroyTree(node);
        } else {
            self.removeUnlinked(node);
            self.destroyTree(node);
        }
    }

    pub fn rootElement(self: *const XMLDocument) ?*XMLNode {
        return self.node.firstChildElement(null);
    }

    pub fn toDocument(self: *XMLDocument) *XMLDocument {
        return self;
    }

    pub fn asNode(self: *XMLDocument) *XMLNode {
        return &self.node;
    }

    pub fn firstChild(self: *const XMLDocument) ?*XMLNode {
        return self.node.first_child;
    }

    pub fn lastChild(self: *const XMLDocument) ?*XMLNode {
        return self.node.last_child;
    }

    pub fn firstChildElement(self: *const XMLDocument, name: ?[]const u8) ?*XMLNode {
        return self.node.firstChildElement(name);
    }

    pub fn lastChildElement(self: *const XMLDocument, name: ?[]const u8) ?*XMLNode {
        return self.node.lastChildElement(name);
    }

    pub fn childElementCount(self: *const XMLDocument, name: ?[]const u8) i32 {
        return self.node.childElementCount(name);
    }

    pub fn insertEndChild(self: *XMLDocument, add_this: *XMLNode) Error!*XMLNode {
        return self.node.insertEndChild(add_this);
    }

    pub fn insertFirstChild(self: *XMLDocument, add_this: *XMLNode) Error!*XMLNode {
        return self.node.insertFirstChild(add_this);
    }

    pub fn insertAfterChild(self: *XMLDocument, after: *XMLNode, add_this: *XMLNode) Error!*XMLNode {
        return self.node.insertAfterChild(after, add_this);
    }

    pub fn deleteChildren(self: *XMLDocument) void {
        self.node.deleteChildren();
    }

    pub fn deleteChild(self: *XMLDocument, node: *XMLNode) Error!void {
        return self.node.deleteChild(node);
    }

    pub fn value(self: *const XMLDocument) ?[]const u8 {
        _ = self;
        return null;
    }

    pub fn processEntities(self: *const XMLDocument) bool {
        return self.process_entities;
    }

    pub fn whitespaceMode(self: *const XMLDocument) Whitespace {
        return self.whitespace_mode;
    }

    pub fn hasBOM(self: *const XMLDocument) bool {
        return self.write_bom;
    }

    pub fn setBOM(self: *XMLDocument, use_bom: bool) void {
        self.write_bom = use_bom;
    }

    pub fn hasError(self: *const XMLDocument) bool {
        return self.error_id != .success;
    }

    pub fn errorID(self: *const XMLDocument) XMLError {
        return self.error_id;
    }

    pub fn errorName(self: *const XMLDocument) []const u8 {
        return util.errorIDToName(self.error_id);
    }

    pub fn errorIDToName(id: XMLError) []const u8 {
        return util.errorIDToName(id);
    }

    pub fn errorStr(self: *const XMLDocument) []const u8 {
        return self.error_buf[0..self.error_len];
    }

    pub fn errorLineNum(self: *const XMLDocument) i32 {
        return self.error_line_num;
    }

    pub fn clearError(self: *XMLDocument) void {
        self.error_id = .success;
        self.error_line_num = 0;
        self.error_len = 0;
    }

    pub fn printError(self: *const XMLDocument, io: std.Io) !void {
        var buf: [1024]u8 = undefined;
        // errorStr() is bounded to 1000 bytes by error_buf, so this cannot fail.
        const text = std.fmt.bufPrint(&buf, "{s}\n", .{self.errorStr()}) catch unreachable;
        try std.Io.File.stdout().writeStreamingAll(io, text);
    }

    pub fn print(self: *const XMLDocument, printer: *XMLPrinter) Error!void {
        try printer.print(&self.node);
    }

    pub fn printToStdout(self: *const XMLDocument, io: std.Io) !void {
        var printer = try XMLPrinter.init(self.allocator, .{});
        defer printer.deinit();
        try self.print(&printer);
        try std.Io.File.stdout().writeStreamingAll(io, printer.cstr());
    }

    pub fn accept(self: *const XMLDocument, visitor: *const XMLVisitor) bool {
        return self.node.accept(visitor);
    }

    /// `XMLDocument::Parse`. The slice replaces `xml` plus `nBytes`; callers
    /// that only want a prefix pass a slice of that prefix. An empty slice or
    /// a slice that starts with NUL reports `error_empty_document`.
    pub fn parse(self: *XMLDocument, xml: []const u8) Error!XMLError {
        self.clear();
        if (xml.len == 0 or xml[0] == 0) {
            self.setError(.error_empty_document, 0, null);
            return self.error_id;
        }

        const buf = try self.allocator.allocSentinel(u8, xml.len, 0);
        defer self.allocator.free(buf);
        @memcpy(buf, xml);

        self.parseBuffer(.{ .bytes = buf }) catch |err| {
            self.node.deleteChildren();
            self.freeUnlinked();
            return err;
        };

        if (self.hasError()) {
            self.node.deleteChildren();
            self.freeUnlinked();
        }
        return self.error_id;
    }

    pub fn loadFile(self: *XMLDocument, io: std.Io, filename: ?[]const u8) !XMLError {
        const path = filename orelse {
            self.setError(.error_file_could_not_be_opened, 0, "filename=<null>");
            return self.error_id;
        };
        self.clear();

        const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch {
            var detail_buf: [1000]u8 = undefined;
            self.setError(.error_file_not_found, 0, detailName(&detail_buf, "filename=", path));
            return self.error_id;
        };
        defer file.close(io);

        const stat = file.stat(io) catch {
            self.setError(.error_file_read_error, 0, null);
            return self.error_id;
        };
        if (stat.kind == .directory or stat.size >= std.math.maxInt(usize)) {
            self.setError(.error_file_read_error, 0, null);
            return self.error_id;
        }
        if (stat.size == 0) {
            self.setError(.error_empty_document, 0, null);
            return self.error_id;
        }

        // Checked above: stat.size < maxInt(usize).
        const data = try self.allocator.alloc(u8, @intCast(stat.size));
        defer self.allocator.free(data);

        var file_reader = file.reader(io, &.{});
        file_reader.interface.readSliceAll(data) catch {
            self.setError(.error_file_read_error, 0, null);
            return self.error_id;
        };
        return self.parse(data);
    }

    pub fn saveFile(self: *XMLDocument, io: std.Io, filename: ?[]const u8, compact: bool) !XMLError {
        const path = filename orelse {
            self.setError(.error_file_could_not_be_opened, 0, "filename=<null>");
            return self.error_id;
        };
        const file = std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true }) catch {
            var detail_buf: [1000]u8 = undefined;
            self.setError(.error_file_could_not_be_opened, 0, detailName(&detail_buf, "filename=", path));
            return self.error_id;
        };
        defer file.close(io);

        self.clearError();
        var printer = try XMLPrinter.init(self.allocator, .{ .compact = compact });
        defer printer.deinit();
        try self.print(&printer);
        try file.writeStreamingAll(io, printer.cstr());
        return self.error_id;
    }

    fn parseBuffer(self: *XMLDocument, buf: Buffer) Error!void {
        self.parse_cur_line = 1;
        self.node.line = 1;
        var p = util.skipWhitespace(buf.bytes, 0, &self.parse_cur_line);
        const bom = util.readBOM(buf.bytes, p);
        p = bom.pos;
        self.write_bom = bom.has_bom;
        if (buf.at(p) == 0) {
            self.setError(.error_empty_document, 0, null);
            return;
        }
        _ = try self.node.parseNodeListDeep(buf, p, null);
    }

    fn identify(self: *XMLDocument, buf: Buffer, start: usize, first: bool) Error!struct { pos: usize, node: ?*XMLNode } {
        const start_line = self.parse_cur_line;
        var p = util.skipWhitespace(buf.bytes, start, &self.parse_cur_line);
        if (buf.at(p) == 0) return .{ .pos = p, .node = null };

        var node: *XMLNode = undefined;
        if (buf.matchesAt(p, "<?")) {
            node = try self.createNode(.declaration);
            node.line = self.parse_cur_line;
            p += 2;
        } else if (buf.matchesAt(p, "<!--")) {
            node = try self.createNode(.comment);
            node.line = self.parse_cur_line;
            p += 4;
        } else if (buf.matchesAt(p, "<![CDATA[")) {
            node = try self.createNode(.text);
            node.line = self.parse_cur_line;
            node.is_cdata = true;
            p += 9;
        } else if (buf.matchesAt(p, "<!")) {
            node = try self.createNode(.unknown);
            node.line = self.parse_cur_line;
            p += 2;
        } else if (buf.matchesAt(p, "<")) {
            if (self.whitespace_mode == .pedantic and first and p != start and buf.at(p + 1) == '/') {
                node = try self.createNode(.text);
                node.line = start_line;
                p = start;
                self.parse_cur_line = start_line;
            } else {
                node = try self.createNode(.element);
                node.line = self.parse_cur_line;
                p += 1;
            }
        } else {
            node = try self.createNode(.text);
            node.line = self.parse_cur_line;
            p = start;
            self.parse_cur_line = start_line;
        }
        return .{ .pos = p, .node = node };
    }

    fn createNode(self: *XMLDocument, kind: NodeKind) Error!*XMLNode {
        const node = try self.allocator.create(XMLNode);
        node.* = .{ .doc = self, .kind = kind };
        errdefer self.allocator.destroy(node);
        try self.unlinked.append(self.allocator, node);
        return node;
    }

    fn createAttribute(self: *XMLDocument) Error!*XMLAttribute {
        const attr = try self.allocator.create(XMLAttribute);
        attr.* = .{ .doc = self };
        return attr;
    }

    fn freeAttribute(self: *XMLDocument, attr: *XMLAttribute) void {
        attr.name_pair.deinit(self.allocator);
        attr.value_pair.deinit(self.allocator);
        self.allocator.destroy(attr);
    }

    fn destroyTree(self: *XMLDocument, node: *XMLNode) void {
        var child = node.first_child;
        while (child) |c| {
            const next = c.next;
            c.parent = null;
            self.destroyTree(c);
            child = next;
        }
        node.value_pair.deinit(self.allocator);
        if (node.kind == .element) {
            var attr = node.root_attribute;
            while (attr) |a| {
                const next = a.next;
                self.freeAttribute(a);
                attr = next;
            }
        }
        self.allocator.destroy(node);
    }

    fn freeUnlinked(self: *XMLDocument) void {
        while (self.unlinked.items.len > 0) {
            const node = self.unlinked.pop().?;
            self.destroyTree(node);
        }
    }

    fn markInUse(self: *XMLDocument, node: *XMLNode) void {
        self.removeUnlinked(node);
    }

    fn removeUnlinked(self: *XMLDocument, node: *XMLNode) void {
        for (self.unlinked.items, 0..) |candidate, i| {
            if (candidate == node) {
                _ = self.unlinked.swapRemove(i);
                return;
            }
        }
    }

    fn setError(self: *XMLDocument, id: XMLError, line: i32, detail: ?[]const u8) void {
        self.error_id = id;
        self.error_line_num = line;
        const base = std.fmt.bufPrint(
            &self.error_buf,
            "Error={s} ErrorID={d} (0x{x}) Line number={d}",
            .{
                util.errorIDToName(id),
                @as(i32, @backingInt(id)),
                @as(u32, @intCast(@backingInt(id))), // enum values are 0..18

                line,
            },
        ) catch unreachable; // fixed text is far below 1000 bytes.
        var len = base.len;
        if (detail) |d| {
            const sep = ": ";
            const sep_n = @min(sep.len, self.error_buf.len - 1 - len);
            @memcpy(self.error_buf[len..][0..sep_n], sep[0..sep_n]);
            len += sep_n;
            // snprintf leaves room for its NUL, so at most 999 characters.
            const room = self.error_buf.len - 1 - len;
            const n = @min(d.len, room);
            @memcpy(self.error_buf[len..][0..n], d[0..n]);
            len += n;
        }
        self.error_len = len;
    }
};

// ---------- visitor ---------- //

/// Callback-based equivalent of `XMLVisitor`. A null callback continues the
/// visit, exactly like the reference's default methods.
pub const XMLVisitor = struct {
    ctx: ?*anyopaque = null,
    enter_document: ?*const fn (ctx: ?*anyopaque, document: *const XMLDocument) bool = null,
    exit_document: ?*const fn (ctx: ?*anyopaque, document: *const XMLDocument) bool = null,
    enter_element: ?*const fn (ctx: ?*anyopaque, element: *const XMLNode, first_attribute: ?*const XMLAttribute) bool = null,
    exit_element: ?*const fn (ctx: ?*anyopaque, element: *const XMLNode) bool = null,
    visit_declaration: ?*const fn (ctx: ?*anyopaque, declaration: *const XMLNode) bool = null,
    visit_text: ?*const fn (ctx: ?*anyopaque, text: *const XMLNode) bool = null,
    visit_comment: ?*const fn (ctx: ?*anyopaque, comment: *const XMLNode) bool = null,
    visit_unknown: ?*const fn (ctx: ?*anyopaque, unknown: *const XMLNode) bool = null,

    fn visitEnterDocument(self: *const XMLVisitor, document: *const XMLDocument) bool {
        if (self.enter_document) |f| return f(self.ctx, document);
        return true;
    }

    fn visitExitDocument(self: *const XMLVisitor, document: *const XMLDocument) bool {
        if (self.exit_document) |f| return f(self.ctx, document);
        return true;
    }

    fn visitEnterElement(self: *const XMLVisitor, element: *const XMLNode, first_attribute: ?*const XMLAttribute) bool {
        if (self.enter_element) |f| return f(self.ctx, element, first_attribute);
        return true;
    }

    fn visitExitElement(self: *const XMLVisitor, element: *const XMLNode) bool {
        if (self.exit_element) |f| return f(self.ctx, element);
        return true;
    }

    fn visitDeclaration(self: *const XMLVisitor, declaration: *const XMLNode) bool {
        if (self.visit_declaration) |f| return f(self.ctx, declaration);
        return true;
    }

    fn visitText(self: *const XMLVisitor, text: *const XMLNode) bool {
        if (self.visit_text) |f| return f(self.ctx, text);
        return true;
    }

    fn visitComment(self: *const XMLVisitor, comment: *const XMLNode) bool {
        if (self.visit_comment) |f| return f(self.ctx, comment);
        return true;
    }

    fn visitUnknown(self: *const XMLVisitor, unknown: *const XMLNode) bool {
        if (self.visit_unknown) |f| return f(self.ctx, unknown);
        return true;
    }
};

// ---------- handles ---------- //

pub const XMLHandle = struct {
    node: ?*XMLNode,

    pub fn init(node: ?*XMLNode) XMLHandle {
        return .{ .node = node };
    }

    pub fn firstChild(self: XMLHandle) XMLHandle {
        return .{ .node = if (self.node) |n| n.first_child else null };
    }

    pub fn firstChildElement(self: XMLHandle, name: ?[]const u8) XMLHandle {
        return .{ .node = if (self.node) |n| n.firstChildElement(name) else null };
    }

    pub fn lastChild(self: XMLHandle) XMLHandle {
        return .{ .node = if (self.node) |n| n.last_child else null };
    }

    pub fn lastChildElement(self: XMLHandle, name: ?[]const u8) XMLHandle {
        return .{ .node = if (self.node) |n| n.lastChildElement(name) else null };
    }

    pub fn previousSibling(self: XMLHandle) XMLHandle {
        return .{ .node = if (self.node) |n| n.prev else null };
    }

    pub fn previousSiblingElement(self: XMLHandle, name: ?[]const u8) XMLHandle {
        return .{ .node = if (self.node) |n| n.previousSiblingElement(name) else null };
    }

    pub fn nextSibling(self: XMLHandle) XMLHandle {
        return .{ .node = if (self.node) |n| n.next else null };
    }

    pub fn nextSiblingElement(self: XMLHandle, name: ?[]const u8) XMLHandle {
        return .{ .node = if (self.node) |n| n.nextSiblingElement(name) else null };
    }

    pub fn toNode(self: XMLHandle) ?*XMLNode {
        return self.node;
    }

    pub fn toElement(self: XMLHandle) ?*XMLNode {
        return if (self.node) |n| n.toElement() else null;
    }

    pub fn toText(self: XMLHandle) ?*XMLNode {
        return if (self.node) |n| n.toText() else null;
    }

    pub fn toUnknown(self: XMLHandle) ?*XMLNode {
        return if (self.node) |n| n.toUnknown() else null;
    }

    pub fn toDeclaration(self: XMLHandle) ?*XMLNode {
        return if (self.node) |n| n.toDeclaration() else null;
    }
};

pub const XMLConstHandle = struct {
    node: ?*const XMLNode,

    pub fn init(node: ?*const XMLNode) XMLConstHandle {
        return .{ .node = node };
    }

    pub fn firstChild(self: XMLConstHandle) XMLConstHandle {
        return .{ .node = if (self.node) |n| n.first_child else null };
    }

    pub fn firstChildElement(self: XMLConstHandle, name: ?[]const u8) XMLConstHandle {
        return .{ .node = if (self.node) |n| n.firstChildElement(name) else null };
    }

    pub fn lastChild(self: XMLConstHandle) XMLConstHandle {
        return .{ .node = if (self.node) |n| n.last_child else null };
    }

    pub fn lastChildElement(self: XMLConstHandle, name: ?[]const u8) XMLConstHandle {
        return .{ .node = if (self.node) |n| n.lastChildElement(name) else null };
    }

    pub fn previousSibling(self: XMLConstHandle) XMLConstHandle {
        return .{ .node = if (self.node) |n| n.prev else null };
    }

    pub fn previousSiblingElement(self: XMLConstHandle, name: ?[]const u8) XMLConstHandle {
        return .{ .node = if (self.node) |n| n.previousSiblingElement(name) else null };
    }

    pub fn nextSibling(self: XMLConstHandle) XMLConstHandle {
        return .{ .node = if (self.node) |n| n.next else null };
    }

    pub fn nextSiblingElement(self: XMLConstHandle, name: ?[]const u8) XMLConstHandle {
        return .{ .node = if (self.node) |n| n.nextSiblingElement(name) else null };
    }

    pub fn toNode(self: XMLConstHandle) ?*const XMLNode {
        return self.node;
    }

    pub fn toElement(self: XMLConstHandle) ?*const XMLNode {
        // The cast only reads the kind tag; the const handle never mutates.
        return if (self.node) |n| @constCast(n).toElement() else null;
    }

    pub fn toText(self: XMLConstHandle) ?*const XMLNode {
        // The cast only reads the kind tag; the const handle never mutates.
        return if (self.node) |n| @constCast(n).toText() else null;
    }

    pub fn toUnknown(self: XMLConstHandle) ?*const XMLNode {
        // The cast only reads the kind tag; the const handle never mutates.
        return if (self.node) |n| @constCast(n).toUnknown() else null;
    }

    pub fn toDeclaration(self: XMLConstHandle) ?*const XMLNode {
        // The cast only reads the kind tag; the const handle never mutates.
        return if (self.node) |n| @constCast(n).toDeclaration() else null;
    }
};

// ---------- printer ---------- //

pub const XMLPrinter = struct {
    allocator: Allocator,
    buf: std.ArrayListUnmanaged(u8) = .empty,
    stack: std.ArrayListUnmanaged([]const u8) = .empty,
    element_just_opened: bool = false,
    first_element: bool = true,
    depth: i32,
    text_depth: i32 = -1,
    process_entities: bool = true,
    compact_mode: bool,
    entity_flag: [64]bool = @splat(false),
    restricted_flag: [64]bool = @splat(false),

    pub fn init(allocator: Allocator, options: PrinterOptions) Error!XMLPrinter {
        var printer: XMLPrinter = .{
            .allocator = allocator,
            .depth = options.depth,
            .compact_mode = options.compact,
        };
        for (util.entities) |entity| {
            if (options.escape_apos_in_attributes or entity.value != '\'') {
                printer.entity_flag[entity.value] = true;
            }
        }
        printer.restricted_flag['&'] = true;
        printer.restricted_flag['<'] = true;
        printer.restricted_flag['>'] = true;
        try printer.buf.append(allocator, 0);
        return printer;
    }

    pub fn deinit(self: *XMLPrinter) void {
        self.buf.deinit(self.allocator);
        self.stack.deinit(self.allocator);
    }

    /// The printed bytes, without the trailing NUL.
    pub fn cstr(self: *const XMLPrinter) []const u8 {
        return self.buf.items[0 .. self.buf.items.len - 1];
    }

    /// `CStrSize`: includes the terminating NUL.
    pub fn cstrSize(self: *const XMLPrinter) usize {
        return self.buf.items.len;
    }

    pub fn clearBuffer(self: *XMLPrinter, reset_to_first_element: bool) void {
        self.buf.clearRetainingCapacity();
        self.buf.appendAssumeCapacity(0);
        self.first_element = reset_to_first_element;
    }

    fn write(self: *XMLPrinter, data: []const u8) Error!void {
        if (data.len == 0) return;
        try self.buf.ensureUnusedCapacity(self.allocator, data.len + 1);
        self.buf.items.len -= 1;
        self.buf.appendSliceAssumeCapacity(data);
        self.buf.appendAssumeCapacity(0);
    }

    fn putc(self: *XMLPrinter, ch: u8) Error!void {
        try self.buf.ensureUnusedCapacity(self.allocator, 2);
        self.buf.items.len -= 1;
        self.buf.appendAssumeCapacity(ch);
        self.buf.appendAssumeCapacity(0);
    }

    pub fn pushHeader(self: *XMLPrinter, write_bom: bool, write_declaration: bool) Error!void {
        if (write_bom) try self.write(&.{ 0xef, 0xbb, 0xbf });
        if (write_declaration) try self.pushDeclaration("xml version=\"1.0\"");
    }

    pub fn printSpace(self: *XMLPrinter, depth: i32) Error!void {
        var i: i32 = 0;
        while (i < depth) : (i += 1) try self.write("    ");
    }

    fn printString(self: *XMLPrinter, text: []const u8, restricted: bool) Error!void {
        if (!self.process_entities) {
            const end = std.mem.indexOfScalar(u8, text, 0) orelse text.len;
            try self.write(text[0..end]);
            return;
        }

        const flags = if (restricted) self.restricted_flag else self.entity_flag;
        var p: usize = 0;
        var q: usize = 0;
        while (q < text.len and text[q] != 0) : (q += 1) {
            const ch = text[q];
            if (ch > 0 and ch < 64 and flags[ch]) {
                try self.write(text[p..q]);
                for (util.entities) |entity| {
                    if (entity.value == ch) {
                        try self.putc('&');
                        try self.write(entity.pattern);
                        try self.putc(';');
                        break;
                    }
                }
                p = q + 1;
            }
        }
        try self.write(text[p..q]);
    }

    fn sealElementIfJustOpened(self: *XMLPrinter) Error!void {
        if (!self.element_just_opened) return;
        self.element_just_opened = false;
        try self.putc('>');
    }

    fn prepareForNewNode(self: *XMLPrinter, compact_mode: bool) Error!void {
        try self.sealElementIfJustOpened();
        if (compact_mode) return;
        if (self.first_element) {
            try self.printSpace(self.depth);
        } else if (self.text_depth < 0) {
            try self.putc('\n');
            try self.printSpace(self.depth);
        }
        self.first_element = false;
    }

    pub fn openElement(self: *XMLPrinter, name_wanted: []const u8, compact_mode: bool) Error!void {
        try self.prepareForNewNode(compact_mode);
        try self.stack.append(self.allocator, name_wanted);
        try self.write("<");
        try self.write(name_wanted);
        self.element_just_opened = true;
        self.depth += 1;
    }

    pub fn pushAttribute(self: *XMLPrinter, name_wanted: []const u8, value: []const u8) Error!void {
        std.debug.assert(self.element_just_opened);
        try self.putc(' ');
        try self.write(name_wanted);
        try self.write("=\"");
        try self.printString(value, false);
        try self.putc('"');
    }

    pub fn pushAttributeInt(self: *XMLPrinter, name_wanted: []const u8, value: i32) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushAttribute(name_wanted, util.formatInt(&buf, value));
    }

    pub fn pushAttributeUnsigned(self: *XMLPrinter, name_wanted: []const u8, value: u32) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushAttribute(name_wanted, util.formatUnsigned(&buf, value));
    }

    pub fn pushAttributeInt64(self: *XMLPrinter, name_wanted: []const u8, value: i64) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushAttribute(name_wanted, util.formatInt64(&buf, value));
    }

    pub fn pushAttributeUnsigned64(self: *XMLPrinter, name_wanted: []const u8, value: u64) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushAttribute(name_wanted, util.formatUnsigned64(&buf, value));
    }

    pub fn pushAttributeBool(self: *XMLPrinter, name_wanted: []const u8, value: bool) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushAttribute(name_wanted, util.formatBool(&buf, value, 0));
    }

    pub fn pushAttributeDouble(self: *XMLPrinter, name_wanted: []const u8, value: f64) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushAttribute(name_wanted, util.formatDouble(&buf, value));
    }

    pub fn pushAttributeFloat(self: *XMLPrinter, name_wanted: []const u8, value: f32) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushAttribute(name_wanted, util.formatFloat(&buf, value));
    }

    pub fn closeElement(self: *XMLPrinter, compact_mode: bool) Error!void {
        self.depth -= 1;
        std.debug.assert(self.stack.items.len > 0);
        const name_wanted = self.stack.pop().?;

        if (self.element_just_opened) {
            try self.write("/>");
        } else {
            if (self.text_depth < 0 and !compact_mode) {
                try self.putc('\n');
                try self.printSpace(self.depth);
            }
            try self.write("</");
            try self.write(name_wanted);
            try self.write(">");
        }

        if (self.text_depth == self.depth) self.text_depth = -1;
        if (self.depth == 0 and !compact_mode) try self.putc('\n');
        self.element_just_opened = false;
    }

    pub fn pushText(self: *XMLPrinter, text: []const u8, cdata: bool) Error!void {
        self.text_depth = self.depth - 1;
        try self.sealElementIfJustOpened();
        if (cdata) {
            try self.write("<![CDATA[");
            try self.write(text);
            try self.write("]]>");
        } else {
            try self.printString(text, true);
        }
    }

    pub fn pushTextInt(self: *XMLPrinter, value: i32) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushText(util.formatInt(&buf, value), false);
    }

    pub fn pushTextUnsigned(self: *XMLPrinter, value: u32) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushText(util.formatUnsigned(&buf, value), false);
    }

    pub fn pushTextInt64(self: *XMLPrinter, value: i64) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushText(util.formatInt64(&buf, value), false);
    }

    pub fn pushTextUnsigned64(self: *XMLPrinter, value: u64) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushText(util.formatUnsigned64(&buf, value), false);
    }

    pub fn pushTextBool(self: *XMLPrinter, value: bool) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushText(util.formatBool(&buf, value, 0), false);
    }

    pub fn pushTextDouble(self: *XMLPrinter, value: f64) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushText(util.formatDouble(&buf, value), false);
    }

    pub fn pushTextFloat(self: *XMLPrinter, value: f32) Error!void {
        var buf: [200]u8 = undefined;
        try self.pushText(util.formatFloat(&buf, value), false);
    }

    pub fn pushComment(self: *XMLPrinter, comment_text: []const u8) Error!void {
        try self.prepareForNewNode(self.compact_mode);
        try self.write("<!--");
        try self.write(comment_text);
        try self.write("-->");
    }

    pub fn pushDeclaration(self: *XMLPrinter, declaration_value: []const u8) Error!void {
        try self.prepareForNewNode(self.compact_mode);
        try self.write("<?");
        try self.write(declaration_value);
        try self.write("?>");
    }

    pub fn pushUnknown(self: *XMLPrinter, unknown_value: []const u8) Error!void {
        try self.prepareForNewNode(self.compact_mode);
        try self.write("<!");
        try self.write(unknown_value);
        try self.putc('>');
    }

    /// Prints a document or a single node, mirroring `XMLNode::Accept` with
    /// `XMLPrinter` as the visitor.
    pub fn print(self: *XMLPrinter, node: *const XMLNode) Error!void {
        switch (node.kind) {
            .document => {
                self.process_entities = node.doc.processEntities();
                if (node.doc.hasBOM()) try self.pushHeader(true, false);
                var child = node.first_child;
                while (child) |c| {
                    try self.print(c);
                    child = c.next;
                }
            },
            .element => {
                try self.openElement(node.name(), self.compact_mode);
                var attr = node.root_attribute;
                while (attr) |a| {
                    try self.pushAttribute(a.name(), a.value());
                    attr = a.next;
                }
                var child = node.first_child;
                while (child) |c| {
                    try self.print(c);
                    child = c.next;
                }
                try self.closeElement(self.compact_mode);
            },
            .text => try self.pushText(node.value_pair.getStr(), node.is_cdata),
            .comment => try self.pushComment(node.value_pair.getStr()),
            .declaration => try self.pushDeclaration(node.value_pair.getStr()),
            .unknown => try self.pushUnknown(node.value_pair.getStr()),
        }
    }
};

// ---------- XMLUtil facade ---------- //

pub const XMLUtil = struct {
    pub const setBoolSerialization = util.setBoolSerialization;
    pub const toStrInt = util.formatInt;
    pub const toStrUnsigned = util.formatUnsigned;
    pub const toStrBool = util.formatBool;
    pub const toStrFloat = util.formatFloat;
    pub const toStrDouble = util.formatDouble;
    pub const toStrInt64 = util.formatInt64;
    pub const toStrUnsigned64 = util.formatUnsigned64;
    pub const toInt = util.toInt;
    pub const toUnsigned = util.toUnsigned;
    pub const toBool = util.toBool;
    pub const toFloat = util.toFloat;
    pub const toDouble = util.toDouble;
    pub const toInt64 = util.toInt64;
    pub const toUnsigned64 = util.toUnsigned64;
    pub const readBOM = util.readBOM;
    pub const getCharacterRef = util.getCharacterRef;
    pub const convertUTF32ToUTF8 = util.convertUTF32ToUTF8;
};

// ---------- tests ---------- //

fn printDoc(doc: *const XMLDocument, allocator: Allocator, options: PrinterOptions) ![]u8 {
    var printer = try XMLPrinter.init(allocator, options);
    defer printer.deinit();
    try doc.print(&printer);
    return try allocator.dupe(u8, printer.cstr());
}

test "parse and print a simple element" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse("<element/>"));
    try std.testing.expect(!doc.hasError());

    const printed = try printDoc(&doc, gpa, .{});
    defer gpa.free(printed);
    try std.testing.expectEqualStrings("<element/>\n", printed);

    const compact = try printDoc(&doc, gpa, .{ .compact = true });
    defer gpa.free(compact);
    try std.testing.expectEqualStrings("<element/>", compact);
}

test "attributes keep parse order and query like tinyxml2" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse("<doc attr0='1' attr1='2.0' attr2='foo' />"));
    const element = doc.rootElement().?;

    var d: f64 = 0;
    try std.testing.expectEqual(XMLError.success, element.queryDoubleAttribute("attr0", &d));
    try std.testing.expectEqual(@as(f64, 1), d);

    var i: i32 = 0;
    try std.testing.expectEqual(XMLError.success, element.queryIntAttribute("attr1", &i));
    try std.testing.expectEqual(@as(i32, 2), i);
    try std.testing.expectEqual(XMLError.wrong_attribute_type, element.queryIntAttribute("attr2", &i));
    try std.testing.expectEqual(XMLError.no_attribute, element.queryIntAttribute("bar", &i));
    try std.testing.expectEqual(@as(f64, 4), element.doubleAttribute("attr2", 4.0));

    try std.testing.expectEqualStrings("1", element.firstAttribute().?.value());
    try std.testing.expectEqualStrings("attr1", element.firstAttribute().?.nextAttribute().?.name());
}

test "set text and attributes with concrete formats" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const element = try doc.newElement("foo");
    _ = try doc.insertEndChild(element);
    try element.setAttributeInt("int", 1);
    try element.setAttributeDouble("double", -1.0);
    try element.setAttributeBool("bool", true);
    try element.setTextInt(1);
    try std.testing.expectEqualStrings("1", element.getText().?);
    try element.setTextDouble(1.5);
    try std.testing.expectEqualStrings("1.5", element.getText().?);

    const printed = try printDoc(&doc, gpa, .{ .compact = true });
    defer gpa.free(printed);
    try std.testing.expectEqualStrings("<foo int=\"1\" double=\"-1\" bool=\"true\">1.5</foo>", printed);
}

test "entities, CDATA, comments, declaration and DOCTYPE" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const xml =
        "<?xml version=\"1.0\"?>" ++
        "<!DOCTYPE PLAY SYSTEM \"play.dtd\">" ++
        "<root a=\"&quot;&apos;&lt;&gt;&amp;\">" ++
        "<!-- comment -->" ++
        "<![CDATA[<b>raw</b>]]>" ++
        "</root>";
    try std.testing.expectEqual(XMLError.success, try doc.parse(xml));

    const root = doc.firstChildElement("root").?;
    try std.testing.expectEqualStrings("\"'<>&", root.attribute("a", null).?);
    try std.testing.expectEqualStrings("DOCTYPE PLAY SYSTEM \"play.dtd\"", doc.firstChild().?.nextSibling().?.value().?);
    try std.testing.expectEqualStrings(" comment ", root.firstChild().?.value().?);
    try std.testing.expectEqualStrings("<b>raw</b>", root.firstChild().?.nextSibling().?.value().?);
    try std.testing.expect(root.firstChild().?.nextSibling().?.cdata());

    const printed = try printDoc(&doc, gpa, .{});
    defer gpa.free(printed);
    try std.testing.expectEqualStrings(
        "<?xml version=\"1.0\"?>\n" ++
            "<!DOCTYPE PLAY SYSTEM \"play.dtd\">\n" ++
            "<root a=\"&quot;&apos;&lt;&gt;&amp;\">\n" ++
            "    <!-- comment --><![CDATA[<b>raw</b>]]></root>\n",
        printed,
    );
}

test "declaration value is available" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    try std.testing.expectEqual(XMLError.success, try doc.parse("<?xml version='1.0'?><a/>"));
    try std.testing.expectEqualStrings("xml version='1.0'", doc.firstChild().?.value().?);
}

test "mismatched and malformed documents report named errors" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    try std.testing.expectEqual(XMLError.error_mismatched_element, try doc.parse("<Hello>Text</Error>"));
    try std.testing.expectEqualStrings(
        "Error=XML_ERROR_MISMATCHED_ELEMENT ErrorID=14 (0xe) Line number=1: XMLElement name=Hello",
        doc.errorStr(),
    );

    try std.testing.expectEqual(XMLError.error_empty_document, try doc.parse(""));
    try std.testing.expectEqualStrings(
        "Error=XML_ERROR_EMPTY_DOCUMENT ErrorID=13 (0xd) Line number=0",
        doc.errorStr(),
    );

    try std.testing.expectEqual(XMLError.error_parsing_attribute, try doc.parse(
        "<?xml version=\"1.0\" standalone=\"no\" ?>\n" ++
            "<passages count=\"006\" formatversion=\"20020620\">\n" ++
            "    <wrong error>\n" ++
            "</passages>",
    ));
    try std.testing.expectEqualStrings(
        "Error=XML_ERROR_PARSING_ATTRIBUTE ErrorID=7 (0x7) Line number=3: XMLElement name=wrong",
        doc.errorStr(),
    );
}

test "whitespace modes" {
    const gpa = std.testing.allocator;

    var collapse: XMLDocument = undefined;
    collapse.init(gpa, .{ .whitespace = .collapse });
    defer collapse.deinit();
    try std.testing.expectEqual(XMLError.success, try collapse.parse("<element><a> This \nis &apos;  text  &apos; </a></element>"));
    try std.testing.expectEqualStrings("This is ' text '", collapse.firstChildElement("element").?.firstChildElement(null).?.getText().?);

    var preserve: XMLDocument = undefined;
    preserve.init(gpa, .{});
    defer preserve.deinit();
    try std.testing.expectEqual(XMLError.success, try preserve.parse("<element>This  is  &apos;  \n\n text &apos;</element>"));
    try std.testing.expectEqualStrings("This  is  '  \n\n text '", preserve.rootElement().?.getText().?);

    var pedantic: XMLDocument = undefined;
    pedantic.init(gpa, .{ .whitespace = .pedantic });
    defer pedantic.deinit();
    try std.testing.expectEqual(XMLError.success, try pedantic.parse("<element> </element>"));
    try std.testing.expectEqualStrings(" ", pedantic.rootElement().?.getText().?);

    try std.testing.expectEqual(XMLError.success, try pedantic.parse("<element><b> </b>  </element>"));
    try std.testing.expectEqualStrings(" ", pedantic.rootElement().?.firstChildElement(null).?.getText().?);
}

test "BOM is detected and written back" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    try std.testing.expectEqual(XMLError.success, try doc.parse("\xef\xbb\xbf<element/>\n"));
    try std.testing.expect(doc.hasBOM());
    const printed = try printDoc(&doc, gpa, .{});
    defer gpa.free(printed);
    try std.testing.expectEqualStrings("\xef\xbb\xbf<element/>\n", printed);
}

test "deep clone and shallow equal" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    var clone: XMLDocument = undefined;
    clone.init(gpa, .{});
    defer clone.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse(
        "<root><child1 foo='bar'/><!-- comment thing --><child2 val='1'>Text</child2></root>",
    ));
    const root = doc.rootElement().?;
    const copy = try root.deepClone(&clone);
    _ = try clone.insertFirstChild(copy);
    const printed = try printDoc(&clone, gpa, .{});
    defer gpa.free(printed);
    try std.testing.expectEqualStrings("<root>\n" ++
        "    <child1 foo=\"bar\"/>\n" ++
        "    <!-- comment thing -->\n" ++
        "    <child2 val=\"1\">Text</child2>\n" ++
        "</root>\n", printed);
    try std.testing.expect(copy.shallowEqual(root));
}

test "visitor sees line numbers" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const Recorder = struct {
        fn enterDocument(ctx: ?*anyopaque, document: *const XMLDocument) bool {
            _ = ctx;
            _ = document;
            return true;
        }
    };
    _ = Recorder;
    _ = try doc.parse("<?xml version=\"1.0\"?>\n<root a='b'/>");
    try std.testing.expectEqual(@as(i32, 1), doc.node.line);
    const root = doc.rootElement().?;
    try std.testing.expectEqual(@as(i32, 2), root.lineNum());
    try std.testing.expectEqual(@as(i32, 2), root.firstAttribute().?.lineNum());
}

test "unlinked nodes are released with the document" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    _ = try doc.newElement("never inserted");
    _ = try doc.newComment("also never inserted");
}

test "empty document and clear" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    try std.testing.expect(doc.node.noChildren());
    _ = try doc.parse("<a/>");
    try std.testing.expect(!doc.node.noChildren());
    doc.clear();
    try std.testing.expect(doc.node.noChildren());
    try std.testing.expect(!doc.hasError());
}
