const std = @import("std");

pub const UNAME26            = 0x0020000;
pub const ADDR_NO_RANDOMIZE  = 0x0040000;
pub const FDPIC_FUNCPTRS     = 0x0080000;
pub const MMAP_PAGE_ZERO     = 0x0100000;
pub const ADDR_COMPAT_LAYOUT = 0x0200000;
pub const READ_IMPLIES_EXEC  = 0x0400000;
pub const ADDR_LIMIT_32BIT   = 0x0800000;
pub const SHORT_INODE        = 0x1000000;
pub const WHOLE_SECONDS      = 0x2000000;
pub const STICKY_TIMEOUTS    = 0x4000000;
pub const ADDR_LIMIT_3GB     = 0x8000000;

const get_current_personality = 0xffffffff;

pub fn personality(persona: usize) usize {
    return std.os.linux.syscall1(.personality, persona);
}

pub fn personality_get() usize {
    return personality(get_current_personality);
}