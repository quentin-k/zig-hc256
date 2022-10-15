const std = @import("std");
const hc256 = @import("hc256");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var ts_begin: i128 = undefined;
    var ts_end: i128 = undefined;

    var key: [32]u8 = undefined;
    var iv: [32]u8 = undefined;

    var page_4k = try allocator.alloc(u8, 4 * 1024);
    defer allocator.free(page_4k);
    var page_8k = try allocator.alloc(u8, 8 * 1024);
    defer allocator.free(page_8k);
    var page_16k = try allocator.alloc(u8, 16 * 1024);
    defer allocator.free(page_16k);
    var page_32k = try allocator.alloc(u8, 32 * 1024);
    defer allocator.free(page_32k);

    try std.os.getrandom(&key);
    try std.os.getrandom(&iv);

    ts_begin = std.time.nanoTimestamp();
    var c4k = hc256.Hc256.init(key, iv);
    c4k.applyStream(page_4k);
    ts_end = std.time.nanoTimestamp();
    try stdout.print("It took {}ns to apply the stream on a 4 kilobyte page\n", .{ts_end - ts_begin});

    try std.os.getrandom(&key);
    try std.os.getrandom(&iv);

    ts_begin = std.time.nanoTimestamp();
    var c8k = hc256.Hc256.init(key, iv);
    c8k.applyStream(page_8k);
    ts_end = std.time.nanoTimestamp();
    try stdout.print("It took {}ns to apply the stream on a 8 kilobyte page\n", .{ts_end - ts_begin});

    try std.os.getrandom(&key);
    try std.os.getrandom(&iv);

    ts_begin = std.time.nanoTimestamp();
    var c16k = hc256.Hc256.init(key, iv);
    c16k.applyStream(page_16k);
    ts_end = std.time.nanoTimestamp();
    try stdout.print("It took {}ns to apply the stream on a 16 kilobyte page\n", .{ts_end - ts_begin});

    try std.os.getrandom(&key);
    try std.os.getrandom(&iv);

    ts_begin = std.time.nanoTimestamp();
    var c32k = hc256.Hc256.init(key, iv);
    c32k.applyStream(page_32k);
    ts_end = std.time.nanoTimestamp();
    try stdout.print("It took {}ns to apply the stream on a 32 kilobyte page\n", .{ts_end - ts_begin});
}