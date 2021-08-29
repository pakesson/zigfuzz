const std = @import("std");

pub const pid_t = std.os.linux.pid_t;

pub const AuxvErrors = error{
    PhdrNotFound,
};

pub const MapsErrors = error{
    BaseAddressNotFound
};

pub fn auxv_phdr_base_address(pid: pid_t) !usize {
    var filenamebuf: [64]u8 = undefined;
    const filenameslice = filenamebuf[0..];
    const filename = try std.fmt.bufPrint(filenameslice, "/proc/{}/auxv", .{pid});

    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();

    const last_type = std.elf.AT_L3_CACHEGEOMETRY;
    const bufsize = last_type * 2 * @sizeOf(usize);
    var buffer: [bufsize]u8 = undefined;

    const bytes_read = try file.readAll(&buffer);
    const numvals = bytes_read / 2 / @sizeOf(usize);

    const auxv = @ptrCast([*]const std.elf.Elf64_auxv_t, @alignCast(@alignOf(usize), &buffer))[0..numvals];

    for (auxv) |v| {
        switch (v.a_type) {
            std.elf.AT_BASE => {},
            std.elf.AT_PHDR => return v.a_un.a_val - @sizeOf(std.elf.Elf64_Ehdr),
            std.elf.AT_PHENT => {},
            else => {},
        }
    }

    return AuxvErrors.PhdrNotFound;
}

pub fn maps_base_address(pid: pid_t) !usize {
    var filenamebuf: [64]u8 = undefined;
    const filenameslice = filenamebuf[0..];
    const filename = try std.fmt.bufPrint(filenameslice, "/proc/{}/maps", .{pid});

    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();
    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();
    var buf: [1024]u8 = undefined;

    while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        std.log.debug("{s}", .{line});

        var it = std.mem.tokenize(line, " ");
        const address_range = it.next().?;
        const perms = it.next().?;

        if (perms[2] == 'x') {
            var address_it = std.mem.split(address_range, "-");
            const start_address = address_it.next().?;

            return std.fmt.parseInt(usize, start_address, 16);
        }
    }

    return MapsErrors.BaseAddressNotFound;
}