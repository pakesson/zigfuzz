const std = @import("std");

pub const pid_t = std.os.linux.pid_t;

// zig fmt: off
pub const PtraceRequest = enum(usize) {
    PTRACE_TRACEME  = 0,
    PTRACE_PEEKTEXT = 1,
    PTRACE_PEEKDATA = 2,
    PTRACE_PEEKUSER = 3,
    PTRACE_POKETEXT = 4,
    PTRACE_POKEDATA = 5,
    PTRACE_POKEUSER = 6,
    PTRACE_CONT     = 7,
    PTRACE_GETREGS  = 12,
    PTRACE_SETREGS  = 13,
};

// Only x86_64 supported for now
pub const UserRegs = extern struct {
    r15: c_ulonglong,
    r14: c_ulonglong,
    r13: c_ulonglong,
    r12: c_ulonglong,
    rbp: c_ulonglong,
    rbx: c_ulonglong,
    r11: c_ulonglong,
    r10: c_ulonglong,
    r9: c_ulonglong,
    r8: c_ulonglong,
    rax: c_ulonglong,
    rcx: c_ulonglong,
    rdx: c_ulonglong,
    rsi: c_ulonglong,
    rdi: c_ulonglong,
    orig_rax: c_ulonglong,
    rip: c_ulonglong,
    cs: c_ulonglong,
    eflags: c_ulonglong,
    rsp: c_ulonglong,
    ss: c_ulonglong,
    fs_base: c_ulonglong,
    gs_base: c_ulonglong,
    ds: c_ulonglong,
    es: c_ulonglong,
    fs: c_ulonglong,
    gs: c_ulonglong
};
// zig fmt: on

pub fn ptrace(request: PtraceRequest, pid: pid_t, addr: usize, data: usize) usize {
    return std.os.linux.syscall4(.ptrace, @enumToInt(request), @bitCast(usize, @as(isize, pid)), addr, data);
}

pub fn ptrace_getregs(pid: pid_t) UserRegs {
    var regs: UserRegs = undefined;
    _ = ptrace(.PTRACE_GETREGS, pid, 0, @ptrToInt(&regs));
    return regs;
}

pub fn ptrace_setregs(pid: pid_t, regs: UserRegs) void {
    _ = ptrace(.PTRACE_SETREGS, pid, 0, @ptrToInt(&regs));
}

pub fn ptrace_cont(pid: pid_t) usize {
    return ptrace(.PTRACE_CONT, pid, 0, 0);
}

pub fn ptrace_setdata(pid: pid_t, addr: usize, data: usize) void {
    _ = ptrace(.PTRACE_POKETEXT, pid, addr, data);
}

pub fn ptrace_getdata(pid: pid_t, addr: usize) usize {
    var data: usize = 0;
    const res = ptrace(.PTRACE_PEEKTEXT, pid, addr, @ptrToInt(&data));
    if (std.os.errno(res) != 0) {
        std.log.debug("Errno: {}", .{std.os.errno(res)});
    }
    return data;
}
