// SPDX-FileCopyrightText: 2026 XexTool Zig rewrite contributors
// SPDX-License-Identifier: GPL-3.0-or-later

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const core = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const exe = b.addExecutable(.{
        .name = "XexTool",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{.{ .name = "xextool", .module = core }},
        }),
    });
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "title", buildTitle(b));
    exe.root_module.addOptions("build_options", build_options);
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step("run", "Run XexTool").dependOn(&run.step);

    const tests = b.addTest(.{ .root_module = core });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    inline for ([_][]const u8{ "src/agg.zig", "src/lzx/lzx.zig", "src/tinyxml2/tinyxml2.zig", "src/tinyxml2/xmltest.zig" }) |root| {
        const dep_tests = b.addTest(.{
            .root_module = b.createModule(.{
                .root_source_file = b.path(root),
                .target = target,
                .optimize = optimize,
            }),
        });
        test_step.dependOn(&b.addRunArtifact(dep_tests).step);
    }
}

fn buildTitle(b: *std.Build) []const u8 {
    if (b.option([]const u8, "build-title", "Override the XexTool build banner")) |title| return title;
    return formatBuildTitle(b.allocator, std.Io.Timestamp.now(b.graph.io, .real).toSeconds()) catch @panic("out of memory");
}

// Matches the C++ __DATE__/__TIME__ banner: "Fri Oct 30 11:01:45 2026".
fn formatBuildTitle(allocator: std.mem.Allocator, timestamp: i64) ![]const u8 {
    const epoch_seconds: u64 = @intCast(timestamp); // Build timestamps are post-1970.
    const seconds = std.time.epoch.EpochSeconds{ .secs = epoch_seconds };
    const epoch_day = seconds.getEpochDay();
    const day_seconds = seconds.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const weekdays = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    // 1970-01-01 was a Thursday, so index 4 is Thursday when 0 is Sunday.
    const weekday = @mod(epoch_day.day + 4, 7);
    return std.fmt.allocPrint(allocator, "XexTool v7.0  -  xorloser 2006-2017 (Build {s} {s} {d: >2} {d:0>2}:{d:0>2}:{d:0>2} {d})", .{
        weekdays[weekday],
        months[@as(usize, @backingInt(month_day.month)) - 1],
        month_day.day_index + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
        year_day.year,
    });
}
