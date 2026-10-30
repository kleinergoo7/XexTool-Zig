// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

//! Representative tests ported from tinyxml2's `xmltest.cpp`, plus golden
//! parse/print checks against the shipped resources.
//!
//! Resources are read from `XEXTOOL_TEST_DIR` (`dream.xml`, `utf8test.xml`,
//! `utf8testverify.xml`, `xmltest-*.xml`). When the variable is unset those
//! tests skip; no fixture is written or committed.

const std = @import("std");
const tx = @import("tinyxml2.zig");

const XMLError = tx.XMLError;
const XMLDocument = tx.XMLDocument;
const XMLPrinter = tx.XMLPrinter;

fn printToString(doc: *const XMLDocument, allocator: std.mem.Allocator, compact: bool) ![]u8 {
    var printer = try XMLPrinter.init(allocator, .{ .compact = compact });
    defer printer.deinit();
    try doc.print(&printer);
    return try allocator.dupe(u8, printer.cstr());
}

fn resourcePath(allocator: std.mem.Allocator, name: []const u8) !?[]u8 {
    const dir = std.process.Environ.getPosix(std.testing.environ, "XEXTOOL_TEST_DIR") orelse {
        std.debug.print("XEXTOOL_TEST_DIR unset; skipping resource test\n", .{});
        return null;
    };
    return try std.fs.path.join(allocator, &.{ dir, name });
}

test "Example 3: declaration, DOCTYPE, element text" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const xml =
        "<?xml version=\"1.0\"?>" ++
        "<!DOCTYPE PLAY SYSTEM \"play.dtd\">" ++
        "<PLAY><TITLE>A Midsummer Night's Dream</TITLE></PLAY>";
    try std.testing.expectEqual(XMLError.success, try doc.parse(xml));

    const title = doc.firstChildElement("PLAY").?.firstChildElement("TITLE").?;
    try std.testing.expectEqualStrings("A Midsummer Night's Dream", title.getText().?);
    try std.testing.expectEqualStrings("xml version=\"1.0\"", doc.firstChild().?.toDeclaration().?.value().?);
    try std.testing.expectEqualStrings(
        "DOCTYPE PLAY SYSTEM \"play.dtd\"",
        doc.firstChild().?.nextSibling().?.toUnknown().?.value().?,
    );
}

test "programmatic DOM matches the reference compact output" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const element = try doc.newElement("element");
    _ = try doc.insertEndChild(element);

    var subs: [3]*tx.XMLNode = undefined;
    for (&subs, 0..) |*slot, i| {
        slot.* = try doc.newElement("sub");
        try slot.*.setAttributeInt("attrib", @intCast(i)); // i is 0..2
    }
    _ = try element.insertEndChild(subs[2]);

    const comment = try element.insertFirstChild(try doc.newComment("comment"));
    var dummy: i32 = 1000;
    comment.user_data = &dummy;

    _ = try element.insertAfterChild(comment, subs[0]);
    _ = try element.insertAfterChild(subs[0], subs[1]);
    _ = try subs[2].insertFirstChild(try doc.newText("& Text!"));

    // The test only compares the pointer value round trip.
    try std.testing.expectEqual(@as(*anyopaque, @ptrCast(&dummy)), comment.user_data.?);
    try std.testing.expectEqualStrings("comment", element.firstChild().?.value().?);
    try std.testing.expectEqualStrings("0", element.firstChildElement(null).?.attribute("attrib", null).?);

    const first = try printToString(&doc, gpa, true);
    defer gpa.free(first);
    try std.testing.expectEqualStrings(
        "<element><!--comment--><sub attrib=\"0\"/><sub attrib=\"1\"/><sub attrib=\"2\">&amp; Text!</sub></element>",
        first,
    );

    try element.deleteChild(subs[2]);
    doc.deleteNode(comment);
    try element.firstChildElement(null).?.setAttributeBool("attrib", true);
    element.lastChildElement(null).?.deleteAttribute("attrib");

    try std.testing.expect(element.firstChildElement(null).?.boolAttribute("attrib", false));
    var int_value: i32 = 10;
    try std.testing.expectEqual(XMLError.no_attribute, element.lastChildElement(null).?.queryIntAttribute("attrib", &int_value));
    try std.testing.expectEqual(@as(i32, 10), int_value);
    try std.testing.expectEqual(@as(i32, 20), element.lastChildElement(null).?.intAttribute("attrib", 20));

    const second = try printToString(&doc, gpa, true);
    defer gpa.free(second);
    try std.testing.expectEqualStrings("<element><sub attrib=\"true\"/><sub/></element>", second);
}

test "moving a subtree with insert first/after/end" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const xml = "<?xml version=\"1.0\" ?><root><one><subtree><elem>element 1</elem>text<!-- comment --></subtree></one><two/></root>";
    const in_two = "<?xml version=\"1.0\" ?><root><one/><two><subtree><elem>element 1</elem>text<!-- comment --></subtree></two></root>";
    const after_one = "<?xml version=\"1.0\" ?><root><one/><subtree><elem>element 1</elem>text<!-- comment --></subtree><two/></root>";
    const after_two = "<?xml version=\"1.0\" ?><root><one/><two/><subtree><elem>element 1</elem>text<!-- comment --></subtree></root>";

    try std.testing.expectEqual(XMLError.success, try doc.parse(xml));
    var subtree = doc.rootElement().?.firstChildElement("one").?.firstChildElement("subtree").?;
    var two = doc.rootElement().?.firstChildElement("two").?;
    _ = try two.insertFirstChild(subtree);
    const one_move = try printToString(&doc, gpa, true);
    defer gpa.free(one_move);
    try std.testing.expectEqualStrings(in_two, one_move);

    try std.testing.expectEqual(XMLError.success, try doc.parse(xml));
    subtree = doc.rootElement().?.firstChildElement("one").?.firstChildElement("subtree").?;
    two = doc.rootElement().?.firstChildElement("two").?;
    _ = try doc.rootElement().?.insertAfterChild(two, subtree);
    const two_move = try printToString(&doc, gpa, true);
    defer gpa.free(two_move);
    try std.testing.expectEqualStrings(after_two, two_move);

    try std.testing.expectEqual(XMLError.success, try doc.parse(xml));
    const one = doc.rootElement().?.firstChildElement("one").?;
    subtree = one.firstChildElement("subtree").?;
    _ = try doc.rootElement().?.insertAfterChild(one, subtree);
    const one_after = try printToString(&doc, gpa, true);
    defer gpa.free(one_after);
    try std.testing.expectEqualStrings(after_one, one_after);

    try std.testing.expectEqual(XMLError.success, try doc.parse(xml));
    subtree = doc.rootElement().?.firstChildElement("one").?.firstChildElement("subtree").?;
    _ = try doc.rootElement().?.insertEndChild(subtree);
    const end_move = try printToString(&doc, gpa, true);
    defer gpa.free(end_move);
    try std.testing.expectEqualStrings(after_two, end_move);
}

test "attribute query matrix" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse("<doc attr0='1' attr1='2.0' attr2='foo' />"));
    const ele = doc.firstChildElement(null).?;

    var d: f64 = 0;
    try std.testing.expectEqual(XMLError.success, ele.queryDoubleAttribute("attr0", &d));
    try std.testing.expectEqual(@as(f64, 1), d);

    try std.testing.expectEqual(XMLError.success, ele.queryDoubleAttribute("attr1", &d));
    try std.testing.expectEqual(@as(f64, 2), d);

    var i: i32 = 0;
    try std.testing.expectEqual(XMLError.success, ele.queryIntAttribute("attr1", &i));
    try std.testing.expectEqual(@as(i32, 2), i);
    try std.testing.expectEqual(XMLError.wrong_attribute_type, ele.queryIntAttribute("attr2", &i));
    try std.testing.expectEqual(@as(f64, 4), ele.doubleAttribute("attr2", 4.0));
    try std.testing.expectEqual(XMLError.no_attribute, ele.queryIntAttribute("bar", &i));
    try std.testing.expect(ele.boolAttribute("bar", true));

    const big: i64 = -123456789012345678;
    const big_pos: u64 = 123456789012345678;
    try ele.setAttributeInt64("i64", big);
    try ele.setAttributeUnsigned64("u64", big_pos);
    var signed64: i64 = 0;
    var unsigned64: u64 = 0;
    try std.testing.expectEqual(XMLError.success, ele.queryInt64Attribute("i64", &signed64));
    try std.testing.expectEqual(big, signed64);
    try std.testing.expectEqual(XMLError.success, ele.queryUnsigned64Attribute("u64", &unsigned64));
    try std.testing.expectEqual(big_pos, unsigned64);
    try ele.setTextInt64(big);
    var text64: i64 = 0;
    try std.testing.expectEqual(XMLError.success, ele.queryInt64Text(&text64));
    try std.testing.expectEqual(big, text64);
}

test "boolean serialization override" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const element = try doc.newElement("element");
    _ = try doc.insertEndChild(element);
    try element.setAttributeBool("attrib", true);
    try std.testing.expectEqualStrings("true", element.attribute("attrib", null).?);

    tx.XMLUtil.setBoolSerialization("1", "0");
    defer tx.XMLUtil.setBoolSerialization(null, null);
    try element.setAttributeBool("attrib", true);
    try std.testing.expectEqualStrings("1", element.attribute("attrib", null).?);
}

test "entity transformation and re-escaping" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const xml = "<?xml version=\"1.0\" standalone=\"no\" ?>" ++
        "<passages count=\"006\" formatversion=\"20020620\">" ++
        "<psg context=\"Line 5 has &quot;quotation marks&quot; and &apos;apostrophe marks&apos;." ++
        " It also has &lt;, &gt;, and &amp;, as well as a fake copyright &#xA9;.\"> </psg>" ++
        "</passages>";
    try std.testing.expectEqual(XMLError.success, try doc.parse(xml));
    const psg = doc.rootElement().?.firstChildElement(null).?;
    try std.testing.expectEqualStrings(
        "Line 5 has \"quotation marks\" and 'apostrophe marks'. It also has <, >, and &, as well as a fake copyright \xc2\xa9.",
        psg.attribute("context", null).?,
    );

    const printed = try printToString(&doc, gpa, false);
    defer gpa.free(printed);
    try std.testing.expectEqualStrings(
        "<?xml version=\"1.0\" standalone=\"no\" ?>\n" ++
            "<passages count=\"006\" formatversion=\"20020620\">\n" ++
            "    <psg context=\"Line 5 has &quot;quotation marks&quot; and &apos;apostrophe marks&apos;." ++
            " It also has &lt;, &gt;, and &amp;, as well as a fake copyright \xc2\xa9.\"/>\n" ++
            "</passages>\n",
        printed,
    );
}

test "processEntities false keeps entities literal" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{ .process_entities = false });
    defer doc.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse(
        "<passages><psg context=\"&quot;q&quot; &apos;a&apos;\">Crazy &ttk;</psg></passages>",
    ));
    const psg = doc.rootElement().?.firstChildElement(null).?;
    try std.testing.expectEqualStrings("&quot;q&quot; &apos;a&apos;", psg.attribute("context", null).?);
    try std.testing.expectEqualStrings("Crazy &ttk;", psg.firstChild().?.value().?);
}

test "comments ignore entities and normalize newlines" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse(
        "<!-- declarations for <head> & <body> --><!-- far &amp; away -->",
    ));
    try std.testing.expectEqualStrings(" declarations for <head> & <body> ", doc.firstChild().?.value().?);
    try std.testing.expectEqualStrings(" far &amp; away ", doc.firstChild().?.nextSibling().?.value().?);

    try std.testing.expectEqual(XMLError.success, try doc.parse("<!-- Somewhat<evil> -->"));
    try std.testing.expectEqualStrings(" Somewhat<evil> ", doc.firstChild().?.value().?);
}

test "CDATA round trip and entity with one digit" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse(
        "<xmlElement><![CDATA[<b>I am > the rules!</b>\n...since I make symbolic puns]]></xmlElement>",
    ));
    try std.testing.expectEqualStrings(
        "<b>I am > the rules!</b>\n...since I make symbolic puns",
        doc.firstChildElement(null).?.firstChild().?.value().?,
    );

    try std.testing.expectEqual(XMLError.success, try doc.parse(
        "<element><Name>1.1 Start easy ignore fin thickness&#xA;</Name></element>",
    ));
    try std.testing.expectEqualStrings(
        "1.1 Start easy ignore fin thickness\n",
        doc.firstChildElement(null).?.firstChildElement(null).?.firstChild().?.value().?,
    );
}

test "BOM and default declaration output" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    _ = try doc.insertEndChild(try doc.newDeclaration(null));
    doc.setBOM(true);
    var printer = try XMLPrinter.init(gpa, .{});
    defer printer.deinit();
    try doc.print(&printer);
    try std.testing.expectEqualStrings(
        "\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        printer.cstr(),
    );
    try std.testing.expectEqual(@as(usize, 42), printer.cstrSize());
}

test "query text helpers and hexadecimal text" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const xml = "<point> <IntText>  0x2020</IntText> <UnsignedText>0X2020</UnsignedText>" ++
        " <Int64Text> 0x1234</Int64Text> <BoolText>true</BoolText>" ++
        " <DoubleText>2.35</DoubleText> </point>";
    try std.testing.expectEqual(XMLError.success, try doc.parse(xml));
    const point = doc.rootElement().?;

    try std.testing.expectEqual(@as(i32, 0x2020), point.firstChildElement("IntText").?.intText(0));
    try std.testing.expectEqual(@as(u32, 0x2020), point.firstChildElement("UnsignedText").?.unsignedText(0));
    try std.testing.expectEqual(@as(i64, 0x1234), point.firstChildElement("Int64Text").?.int64Text(0));
    try std.testing.expectEqual(@as(f64, 2.35), point.firstChildElement("DoubleText").?.doubleText(0));
    try std.testing.expectEqual(@as(f32, 2.35), point.firstChildElement("DoubleText").?.floatText(0));
    try std.testing.expect(point.firstChildElement("BoolText").?.boolText(false));
}

test "line numbers through a visitor" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const Recorder = struct {
        const Self = @This();

        buf: [256]u8 = undefined,
        len: usize = 0,

        fn push(self: *Self, kind: u8, line: i32) void {
            self.buf[self.len] = kind;
            self.buf[self.len + 1] = '0' + @as(u8, @intCast(@divTrunc(line, 10))); // test lines are 0..99
            self.buf[self.len + 2] = '0' + @as(u8, @intCast(@mod(line, 10))); // remainder is 0..9
            self.len += 3;
        }

        fn enterDocument(ctx: ?*anyopaque, document: *const XMLDocument) bool {
            const self: *Self = @ptrCast(@alignCast(ctx.?)); // ctx is always &recorder.
            self.push('D', document.node.lineNum());
            return true;
        }

        fn enterElement(ctx: ?*anyopaque, element: *const tx.XMLNode, first_attribute: ?*const tx.XMLAttribute) bool {
            const self: *Self = @ptrCast(@alignCast(ctx.?)); // ctx is always &recorder.
            self.push('E', element.lineNum());
            var attr = first_attribute;
            while (attr) |a| {
                self.push('A', a.lineNum());
                attr = a.nextAttribute();
            }
            return true;
        }

        fn visitDeclaration(ctx: ?*anyopaque, declaration: *const tx.XMLNode) bool {
            const self: *Self = @ptrCast(@alignCast(ctx.?)); // ctx is always &recorder.
            self.push('L', declaration.lineNum());
            return true;
        }

        fn visitText(ctx: ?*anyopaque, text: *const tx.XMLNode) bool {
            const self: *Self = @ptrCast(@alignCast(ctx.?)); // ctx is always &recorder.
            self.push('T', text.lineNum());
            return true;
        }

        fn visitComment(ctx: ?*anyopaque, comment: *const tx.XMLNode) bool {
            const self: *Self = @ptrCast(@alignCast(ctx.?)); // ctx is always &recorder.
            self.push('C', comment.lineNum());
            return true;
        }

        fn visitUnknown(ctx: ?*anyopaque, unknown: *const tx.XMLNode) bool {
            const self: *Self = @ptrCast(@alignCast(ctx.?)); // ctx is always &recorder.
            self.push('U', unknown.lineNum());
            return true;
        }
    };

    const docstr = "<?xml version=\"1.0\"?>\n" ++
        "<root a='b' \n" ++
        "c='d'> d <blah/>  \n" ++
        "newline in text \n" ++
        "and second <zxcv/><![CDATA[\n" ++
        " cdata test ]]><!-- comment -->\n" ++
        "<! unknown></root>";
    try std.testing.expectEqual(XMLError.success, try doc.parse(docstr));

    var recorder: Recorder = .{};
    const visitor = tx.XMLVisitor{
        .ctx = &recorder,
        .enter_document = Recorder.enterDocument,
        .enter_element = Recorder.enterElement,
        .visit_declaration = Recorder.visitDeclaration,
        .visit_text = Recorder.visitText,
        .visit_comment = Recorder.visitComment,
        .visit_unknown = Recorder.visitUnknown,
    };
    try std.testing.expect(doc.accept(&visitor));
    try std.testing.expectEqualStrings("D01L01E02A02A03T03E03T04E05T05C06U07", recorder.buf[0..recorder.len]);
}

test "line numbers with CRLF input" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    const docstr = "\r\n" ++
        "<?xml version=\"1.0\"?>\n" ++
        "<root>\r\n" ++
        "\n" ++
        "text containing new line \n" ++
        " and also containing crlf \r\n" ++
        "<sub><![CDATA[\n" ++
        "cdata containing new line \n" ++
        " and also containing cflr\r\n" ++
        "]]></sub><sub2/></root>";
    try std.testing.expectEqual(XMLError.success, try doc.parse(docstr));
    try std.testing.expectEqual(@as(i32, 2), doc.firstChild().?.lineNum());
    try std.testing.expectEqual(@as(i32, 3), doc.rootElement().?.lineNum());
    try std.testing.expectEqual(@as(i32, 10), doc.rootElement().?.lastChildElement(null).?.lineNum());
}

test "deep clone sub element prints identically" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    var clone: XMLDocument = undefined;
    clone.init(gpa, .{});
    defer clone.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse(
        "<?xml version ='1.0'?><root>    <child1 foo='bar'/>    <!-- comment thing -->    <child2 val='1'>Text</child2></root>",
    ));
    const child = doc.firstChildElement("root").?.firstChildElement("child2").?;

    var original_printer = try XMLPrinter.init(gpa, .{});
    defer original_printer.deinit();
    try child.print(&original_printer);

    const copy = try child.deepClone(&clone);
    _ = try clone.insertFirstChild(copy);

    var clone_printer = try XMLPrinter.init(gpa, .{});
    defer clone_printer.deinit();
    try clone.print(&clone_printer);

    try std.testing.expectEqualStrings(original_printer.cstr(), clone_printer.cstr());
}

test "handles find children safely" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse("<element attrib='bar'><sub>Text</sub></element>"));
    const element = tx.XMLHandle.init(&doc.node).firstChildElement("element").firstChild().toElement();
    try std.testing.expect(element != null);
    try std.testing.expectEqualStrings("sub", element.?.value().?);

    const missing = tx.XMLHandle.init(&doc.node).firstChildElement("noSuchElement").firstChildElement("element").toElement();
    try std.testing.expect(missing == null);

    const const_element = tx.XMLConstHandle.init(&doc.node).firstChildElement("element").firstChild().toElement();
    try std.testing.expect(const_element != null);
    try std.testing.expectEqualStrings("sub", const_element.?.value().?);
}

test "all error ids have names" {
    var raw: i32 = 0;
    while (raw < @as(i32, @intCast(tx.error_count))) : (raw += 1) { // 19 fits i32
        const id: XMLError = @fromBackingInt(raw); // raw is bounded by the loop condition.
        const name = XMLDocument.errorIDToName(id);
        try std.testing.expect(name.len > 0);
    }
}

test "float and double attribute formatting" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();

    try std.testing.expectEqual(XMLError.success, try doc.parse("<element/>"));
    const element = doc.firstChildElement(null).?;
    try element.setAttributeDouble("attrA-f64", 123456789.123456789);
    try element.setAttributeDouble("attrB-f64", 1.001e9);
    try element.setAttributeDouble("attrC-f64", 1.0e20);
    try element.setAttributeDouble("attrD-f64", 0.123456789);
    try element.setAttributeFloat("attrA-f32", 123456789.123456789);
    try element.setAttributeFloat("attrB-f32", 1.001e9);
    try element.setAttributeFloat("attrC-f32", 1.0e20);
    try element.setAttributeFloat("attrD-f32", 0.123456789);

    const printed = try printToString(&doc, gpa, false);
    defer gpa.free(printed);
    try std.testing.expectEqualStrings(
        "<element attrA-f64=\"123456789.12345679\" attrB-f64=\"1001000000\" attrC-f64=\"1e+20\"" ++
            " attrD-f64=\"0.123456789\" attrA-f32=\"1.2345679e+08\" attrB-f32=\"1.001e+09\"" ++
            " attrC-f32=\"1e+20\" attrD-f32=\"0.12345679\"/>\n",
        printed,
    );
}

test "save and load a file" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fs.path.join(gpa, &.{ std.testing.TmpDir.parent_dir_path, tmp.sub_path[0..], "roundtrip.xml" });
    defer gpa.free(path);

    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    try std.testing.expectEqual(XMLError.success, try doc.parse("<root><a b='1'>text</a></root>"));
    try std.testing.expectEqual(XMLError.success, try doc.saveFile(io, path, false));

    var loaded: XMLDocument = undefined;
    loaded.init(gpa, .{});
    defer loaded.deinit();
    try std.testing.expectEqual(XMLError.success, try loaded.loadFile(io, path));
    try std.testing.expectEqualStrings("text", loaded.rootElement().?.firstChildElement("a").?.getText().?);

    const empty_path = try std.fs.path.join(gpa, &.{ std.testing.TmpDir.parent_dir_path, tmp.sub_path[0..], "empty.xml" });
    defer gpa.free(empty_path);
    const empty_file = try std.Io.Dir.cwd().createFile(io, empty_path, .{ .truncate = true });
    empty_file.close(io);
    try std.testing.expectEqual(XMLError.error_empty_document, try loaded.loadFile(io, empty_path));

    try std.testing.expectEqual(XMLError.error_file_not_found, try loaded.loadFile(io, "no/such/file.xml"));
    try std.testing.expectEqualStrings("XML_ERROR_FILE_NOT_FOUND", loaded.errorName());
    try std.testing.expectEqualStrings(
        "Error=XML_ERROR_FILE_NOT_FOUND ErrorID=3 (0x3) Line number=0: filename=no/such/file.xml",
        loaded.errorStr(),
    );
    try std.testing.expectEqual(XMLError.error_file_could_not_be_opened, try loaded.saveFile(io, "no/such/dir/out.xml", false));
    try std.testing.expectEqualStrings(
        "Error=XML_ERROR_FILE_COULD_NOT_BE_OPENED ErrorID=4 (0x4) Line number=0: filename=no/such/dir/out.xml",
        loaded.errorStr(),
    );
    try std.testing.expectEqual(XMLError.error_file_could_not_be_opened, try loaded.loadFile(io, null));
    try std.testing.expectEqualStrings(
        "Error=XML_ERROR_FILE_COULD_NOT_BE_OPENED ErrorID=4 (0x4) Line number=0: filename=<null>",
        loaded.errorStr(),
    );
}

test "BOM survives a file round trip" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try std.fs.path.join(gpa, &.{ std.testing.TmpDir.parent_dir_path, tmp.sub_path[0..], "bom.xml" });
    defer gpa.free(path);

    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    try std.testing.expectEqual(XMLError.success, try doc.parse("\xef\xbb\xbf<element/>\n"));
    try std.testing.expectEqual(XMLError.success, try doc.saveFile(io, path, false));

    var loaded: XMLDocument = undefined;
    loaded.init(gpa, .{});
    defer loaded.deinit();
    try std.testing.expectEqual(XMLError.success, try loaded.loadFile(io, path));
    try std.testing.expect(loaded.hasBOM());

    var printer = try XMLPrinter.init(gpa, .{});
    defer printer.deinit();
    try loaded.print(&printer);
    try std.testing.expectEqualStrings("\xef\xbb\xbf<element/>\n", printer.cstr());
}

test "allocation failure during parse, print and clone leaves no leaks" {
    const base = std.testing.allocator;
    const xml = "<root a='1' b='2'><child>text&amp;more</child><!--c--><![CDATA[data]]></root>";

    var fail_index: usize = 0;
    while (fail_index < 120) : (fail_index += 1) {
        var failing = std.testing.FailingAllocator.init(base, .{ .fail_index = fail_index });
        const gpa = failing.allocator();

        {
            var doc: XMLDocument = undefined;
            doc.init(gpa, .{});
            defer doc.deinit();

            if (doc.parse(xml)) |_| {} else |err| {
                try std.testing.expectEqual(tx.Error.OutOfMemory, err);
            }

            if (!doc.hasError()) {
                var printer = XMLPrinter.init(gpa, .{}) catch |err| {
                    try std.testing.expectEqual(tx.Error.OutOfMemory, err);
                    continue;
                };
                defer printer.deinit();
                doc.print(&printer) catch |err| {
                    try std.testing.expectEqual(tx.Error.OutOfMemory, err);
                };
            }

            if (doc.rootElement()) |root| {
                var clone: XMLDocument = undefined;
                clone.init(gpa, .{});
                defer clone.deinit();
                if (root.deepClone(&clone)) |copy| {
                    _ = clone.insertFirstChild(copy) catch |err| {
                        try std.testing.expectEqual(tx.Error.OutOfMemory, err);
                    };
                } else |err| {
                    try std.testing.expectEqual(tx.Error.OutOfMemory, err);
                }
            }
        }
    }
}

test "document create/destroy and deepCopy" {
    const gpa = std.testing.allocator;
    const doc = try XMLDocument.create(gpa, .{});
    defer doc.destroy();

    try std.testing.expectEqual(XMLError.success, try doc.parse("<?xml version='1.0'?><!--top--><root><a>1</a></root>"));
    const source = try printToString(doc, gpa, false);
    defer gpa.free(source);

    var target: XMLDocument = undefined;
    target.init(gpa, .{});
    defer target.deinit();
    try doc.deepCopy(&target);
    const copied = try printToString(&target, gpa, false);
    defer gpa.free(copied);
    try std.testing.expectEqualStrings(source, copied);
}

test "printer buffer can be reused" {
    const gpa = std.testing.allocator;
    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    try std.testing.expectEqual(XMLError.success, try doc.parse("<a>1</a>"));

    var printer = try XMLPrinter.init(gpa, .{});
    defer printer.deinit();
    try doc.print(&printer);
    try std.testing.expectEqualStrings("<a>1</a>\n", printer.cstr());
    printer.clearBuffer(true);
    try doc.print(&printer);
    try std.testing.expectEqualStrings("<a>1</a>\n", printer.cstr());
}

// ---------- resource goldens (XEXTOOL_TEST_DIR) ---------- //

test "golden: dream.xml parse, print round trip and terminal text" {
    const gpa = std.testing.allocator;
    const path = (try resourcePath(gpa, "dream.xml")) orelse return error.SkipZigTest;
    defer gpa.free(path);

    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    try std.testing.expectEqual(XMLError.success, try doc.loadFile(std.testing.io, path));

    try std.testing.expectEqualStrings("xml version=\"1.0\"", doc.firstChild().?.toDeclaration().?.value().?);
    try std.testing.expectEqualStrings("DOCTYPE PLAY SYSTEM \"play.dtd\"", doc.firstChild().?.nextSibling().?.toUnknown().?.value().?);
    try std.testing.expectEqualStrings(
        "And Robin shall restore amends.",
        doc.lastChild().?.lastChild().?.lastChild().?.lastChild().?.lastChildElement(null).?.getText().?,
    );

    const first = try printToString(&doc, gpa, false);
    defer gpa.free(first);
    try std.testing.expect(first.len > 100000);

    var reparsed: XMLDocument = undefined;
    reparsed.init(gpa, .{});
    defer reparsed.deinit();
    try std.testing.expectEqual(XMLError.success, try reparsed.parse(first));
    const second = try printToString(&reparsed, gpa, false);
    defer gpa.free(second);
    try std.testing.expectEqualStrings(first, second);
}

test "golden: dream.xml parses in pedantic mode" {
    const gpa = std.testing.allocator;
    const path = (try resourcePath(gpa, "dream.xml")) orelse return error.SkipZigTest;
    defer gpa.free(path);

    var doc: XMLDocument = undefined;
    doc.init(gpa, .{ .whitespace = .pedantic });
    defer doc.deinit();
    try std.testing.expectEqual(XMLError.success, try doc.loadFile(std.testing.io, path));
    try std.testing.expectEqualStrings(
        "And Robin shall restore amends.",
        doc.lastChild().?.lastChild().?.lastChild().?.lastChild().?.lastChildElement(null).?.getText().?,
    );
}

test "golden: utf8test.xml prints utf8testverify.xml" {
    const gpa = std.testing.allocator;
    const in_path = (try resourcePath(gpa, "utf8test.xml")) orelse return error.SkipZigTest;
    defer gpa.free(in_path);
    const verify_path = (try resourcePath(gpa, "utf8testverify.xml")) orelse return error.SkipZigTest;
    defer gpa.free(verify_path);

    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    try std.testing.expectEqual(XMLError.success, try doc.loadFile(std.testing.io, in_path));

    const document_element = doc.firstChildElement("document").?;
    const russian = document_element.firstChildElement("Russian").?;
    try std.testing.expectEqualStrings(
        "\xd1\x86\xd0\xb5\xd0\xbd\xd0\xbd\xd0\xbe\xd1\x81\xd1\x82\xd1\x8c",
        russian.attribute("value", null).?,
    );

    const printed = try printToString(&doc, gpa, false);
    defer gpa.free(printed);
    const expected = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, verify_path, gpa, .unlimited);
    defer gpa.free(expected);
    try std.testing.expectEqualStrings(expected, printed);
}

test "golden: deep-nesting fixtures report XML_ELEMENT_DEPTH_EXCEEDED" {
    const gpa = std.testing.allocator;
    const names = [_][]const u8{
        "xmltest-5330.xml",
        "xmltest-4636783552757760.xml",
        "xmltest-5720541257269248.xml",
    };
    for (names) |name| {
        const path = (try resourcePath(gpa, name)) orelse return error.SkipZigTest;
        defer gpa.free(path);
        var doc: XMLDocument = undefined;
        doc.init(gpa, .{});
        defer doc.deinit();
        try std.testing.expectEqual(XMLError.element_depth_exceeded, try doc.loadFile(std.testing.io, path));
    }
}

test "golden: fuzz fixture does not crash or lock up" {
    const gpa = std.testing.allocator;
    const path = (try resourcePath(gpa, "xmltest-5662204197076992.xml")) orelse return error.SkipZigTest;
    defer gpa.free(path);

    var doc: XMLDocument = undefined;
    doc.init(gpa, .{});
    defer doc.deinit();
    const result = try doc.loadFile(std.testing.io, path);
    _ = result;
}
