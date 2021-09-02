const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;

const Self = @This();

allocator: *Allocator,
data: ArrayList(u8),
trace: AutoHashMap(usize, void),

pub fn init(allocator: *Allocator) Self {
    return Self{
        .allocator = allocator,
        .data = ArrayList(u8).init(allocator),
        .trace = AutoHashMap(usize, void).init(allocator),
    };
}

pub fn deinit(self: *Self) void {
    self.data.deinit();
    self.trace.deinit();
}

pub fn writeToFile(self: *Self, filename: []const u8) !void {
    const file = try std.fs.cwd().createFile(
        filename,
        .{ .truncate = true },
    );
    defer file.close();
    try file.writeAll(self.data.items);
}