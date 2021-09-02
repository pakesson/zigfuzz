const std = @import("std");
const time = std.time;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const HashMap = std.HashMap;
const AutoHashMap = std.AutoHashMap;
const Sha256 = std.crypto.hash.sha2.Sha256;

const proc = @import("proc.zig");
const elf = @import("elf.zig");
const ElfFile = elf.ElfFile;
const Symbol = elf.Symbol;
const Sample = @import("Sample.zig");
const ptrace = @import("ptrace.zig");
const pid_t = ptrace.pid_t;
const personality = @import("personality.zig");

const Statistics = struct {
    cases: u64 = 0,
    crashes: u64 = 0,
    elapsed_time: f64 = 0,
    coverage: u64 = 0,
};

const FuzzResultData = struct {
    instruction_pointer: usize = 0,
    trace: *AutoHashMap(usize, void),
};

const FuzzResult = union(enum) {
    ok: FuzzResultData,
    crash: FuzzResultData,
    err: void,
};

// Workaround for a bug in std.os.WIFSTOPPED for Linux, FreeBSD and DragonFly BSD
// (Use truncating cast instead of @intCast)
fn WIFSTOPPED(s: u32) bool {
    return @truncate(u16, ((s & 0xffff) *% 0x10001) >> 8) > 0x7f00;
}

fn run_child(path: [*:0]const u8, filename: [*:0]const u8) void {
    _ = ptrace.ptrace(.PTRACE_TRACEME, 0, 0, 0);
    _ = personality.personality(personality.ADDR_NO_RANDOMIZE);

    const argv = [_:null]?[*:0]const u8{ path, filename, null };
    const envp = [_:null]?[*:0]const u8{null};
    const res = std.os.execveZ(path, &argv, &envp);
    std.debug.panic("{}", .{res});
}

fn run_parent(allocator: *Allocator, pid: pid_t, symbols: []Symbol) !FuzzResult {
    // Handle initial SIGTRAP
    const initstatus = std.os.waitpid(pid, 0).status;

    var base: usize = 0;

    // Used to keep track of the original data that we replace with breakpoints
    var breakpoint_replacements = AutoHashMap(usize, usize).init(allocator);
    defer breakpoint_replacements.deinit();

    // Trace for coverage
    var trace = AutoHashMap(usize, void).init(allocator);
    errdefer trace.deinit();

    if (WIFSTOPPED(initstatus) and
        std.os.WSTOPSIG(initstatus) == std.os.SIGTRAP)
    {
        base = proc.auxv_phdr_base_address(pid) catch return FuzzResult.err;

        for (symbols) |symbol| {
            if (symbol.address == 0) continue;
            if (std.mem.startsWith(u8, symbol.name.items, "_")) continue;

            const address = base + symbol.address;
            if (breakpoint_replacements.get(address) != null) continue;

            const original_data = ptrace.ptrace_getdata(pid, address);
            const breakpoint_data = (original_data & (@as(usize, std.math.maxInt(usize)) ^ 0xff)) | 0xcc;
            ptrace.ptrace_setdata(pid, address, breakpoint_data);
            breakpoint_replacements.put(base + symbol.address, original_data) catch return FuzzResult.err;
        }

        _ = ptrace.ptrace_cont(pid);
    } else {
        std.log.err("[PARENT] Child did not start correctly", .{});
        return FuzzResult.err;
    }

    while (true) {
        const status = std.os.waitpid(pid, 0).status;

        if (std.os.WIFEXITED(status)) {
            return FuzzResult{ .ok = FuzzResultData{ .trace = &trace } };
        } else if (std.os.WIFSIGNALED(status)) {
            std.log.debug("[PARENT] Unhandled: WIFSIGNALED", .{});
            return FuzzResult.err;
        } else if (WIFSTOPPED(status)) {
            const signal = std.os.WSTOPSIG(status);
            switch (signal) {
                std.os.SIGSEGV => {
                    const regs = ptrace.ptrace_getregs(pid);
                    return FuzzResult{ .crash = FuzzResultData{ .instruction_pointer = regs.rip, .trace = &trace } };
                },
                std.os.SIGTRAP => {
                    var regs = ptrace.ptrace_getregs(pid);
                    const address = regs.rip - 1;

                    try trace.put(address, {});

                    const original_data = breakpoint_replacements.get(address).?;
                    ptrace.ptrace_setdata(pid, address, original_data);

                    regs.rip = address;
                    ptrace.ptrace_setregs(pid, regs);
                    _ = breakpoint_replacements.remove(address);
                    _ = ptrace.ptrace_cont(pid);
                },
                else => {
                    std.log.err("[PARENT] Unhandled signal. Returning.", .{});
                    return FuzzResult.err;
                },
            }
        } else {
            std.log.err("[PARENT] Unknown child status. Returning.", .{});
            return FuzzResult.err;
        }
    }
}

fn merge_coverage(total_trace: *AutoHashMap(usize, void), new_trace: AutoHashMap(usize, void)) !bool {
    var it = new_trace.keyIterator();
    var ret = false;
    while (it.next()) |item| {
        const key = item.*;
        if (!total_trace.contains(key)) {
            const entry = try total_trace.fetchPut(key, {});
            if (entry == null) {
                // New coverage
                ret = true;
            }
        }
    }
    return ret;
}

fn cmpSamples(_: void, lhs: Sample, rhs: Sample) bool {
    return lhs.trace.count() > rhs.trace.count();
}

fn print_stats(stats: Statistics) void {
    const fcps = @floatToInt(u64, @intToFloat(f64, stats.cases) / stats.elapsed_time);
    std.log.info("Cases: {}\tCases per second: {}\tCoverage: {}\tCrashes: {}\tTime: {d:.2} seconds", .{ stats.cases, fcps, stats.coverage, stats.crashes, stats.elapsed_time });
}

fn save_crash(crash_directory: []const u8, sample: Sample) !void {
    var hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(sample.data.items, &hash, .{});

    var filenamebuf: [128]u8 = undefined;
    const filenameslice = filenamebuf[0..];
    const crash_filename = try std.fmt.bufPrint(filenameslice, "{s}/crash_{}", .{ crash_directory, std.fmt.fmtSliceHexLower(hash[0..]) });

    const file = try std.fs.cwd().createFile(
        crash_filename,
        .{ .truncate = true },
    );
    _ = try file.writeAll(sample.data.items);
    file.close();
}

pub fn main() anyerror!void {
    std.log.info("Initializing", .{});

    if (std.Target.current.cpu.arch != .x86_64) {
        std.log.err("Unsupported architecture", .{});
        return;
    }

    var prng = std.rand.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        try std.os.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });
    const rand = &prng.random;

    var stats = Statistics{};
    var running: bool = true;

    // TODO: Refactor into config struct
    const target_binary = "./examples/example1";
    const input_filename = "input_file";
    const crash_directory = "crashes";

    // Create directories
    std.fs.cwd().makeDir(crash_directory) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var gpalloc = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!gpalloc.deinit());
    const allocator = &gpalloc.allocator;

    // Load Elf file
    var elfFile = try ElfFile.open(allocator, target_binary);
    defer elfFile.deinit();
    // We will use symbols to track coverage
    try elfFile.load_symbols();

    // TODO: Load corpus from filesystem instead
    var start_sample = Sample.init(allocator);
    try start_sample.data.insertSlice(0, "aaaaaa");

    var sample_pool = ArrayList(Sample).init(allocator);
    try sample_pool.append(start_sample);
    defer {
        for (sample_pool.items) |*item| item.deinit();
        sample_pool.deinit();
    }

    var total_trace = AutoHashMap(usize, void).init(allocator);
    defer total_trace.deinit();

    var timer = try time.Timer.start();
    const start_time = timer.lap();
    var last_stats_time = start_time;

    // Main fuzz loop
    std.log.info("Starting fuzzing loop", .{});
    while (running) {
        // Sort samples by coverage
        std.sort.sort(Sample, sample_pool.items, {}, cmpSamples);

        // Pick a random sample
        var candidate = Sample.init(allocator);
        errdefer candidate.deinit();
        const coeff = rand.float(f64);
        const sample_idx = @floatToInt(usize, std.math.round(@intToFloat(f64, sample_pool.items.len - 1) * coeff * coeff));
        try candidate.data.insertSlice(0, sample_pool.items[sample_idx].data.items);

        // Mutate
        const bytes_to_modify = rand.intRangeAtMost(usize, 1, std.math.max(3, candidate.data.items.len - 1));
        var i: usize = 0;
        while (i < bytes_to_modify) {
            const byte_idx = rand.intRangeAtMost(usize, 0, candidate.data.items.len - 1);
            candidate.data.items[byte_idx] = rand.int(u8);
            i += 1;
        }

        // Write sample to disk
        {
            const file = try std.fs.cwd().createFile(
                input_filename,
                .{ .truncate = true },
            );
            _ = try file.writeAll(candidate.data.items);
            file.close();
        }

        const fork_pid = try std.os.fork();
        if (fork_pid == 0) {
            run_child(target_binary, input_filename);
            return;
        } else {
            var fuzz_result = try run_parent(allocator, fork_pid, elfFile.symbols.items);
            switch (fuzz_result) {
                .ok => |data| {
                    var trace = data.trace.*;
                    candidate.trace = trace;
                    if (try merge_coverage(&total_trace, trace)) {
                        // New coverage
                        stats.coverage = total_trace.count();
                        try sample_pool.append(candidate);
                    } else {
                        candidate.deinit();
                    }
                },
                .crash => |data| {
                    var trace = data.trace.*;
                    candidate.trace = trace;

                    try save_crash(crash_directory, candidate);

                    if (try merge_coverage(&total_trace, trace)) {
                        // New coverage
                        stats.coverage = total_trace.count();
                        try sample_pool.append(candidate);
                    } else {
                        candidate.deinit();
                    }
                    stats.crashes += 1;
                },
                .err => {},
            }
        }

        stats.cases += 1;
        const current_time = timer.read();
        stats.elapsed_time = @intToFloat(f64, current_time - start_time) / time.ns_per_s;

        // Print stats every five seconds
        if (@intToFloat(f64, current_time - last_stats_time) / time.ns_per_s > 5) {
            print_stats(stats);
            last_stats_time = current_time;
        }
    }

    stats.elapsed_time = @intToFloat(f64, timer.read() - start_time) / time.ns_per_s;
    print_stats(stats);
}
