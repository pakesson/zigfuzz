const std = @import("std");

const elf = std.elf;
const math = std.math;
const mem = std.mem;
const os = std.os;

const Allocator = mem.Allocator;
const ArrayList = std.ArrayList;
const builtin = @import("builtin");
const native_arch = builtin.target.cpu.arch;
const native_endian = native_arch.endian();

pub const Symbol = struct {
    name: ArrayList(u8),
    address: usize,
};

pub const ElfFile = struct {
    allocator: Allocator,
    mapped_mem: []align(mem.page_size) u8,

    hdr64: *std.elf.Elf64_Ehdr,

    symbols: ArrayList(Symbol),

    pub const Error = error{
        NotElfFile,
        NotExecutable,
        InvalidElfVersion,
        InvalidElfEndian,
        UnsupportedElfEndian,
        UnsupportedElfClass,
    };

    pub fn open(allocator: Allocator, path: []const u8) !ElfFile {
        var fd = try os.open(path, 0, os.O.RDONLY | os.O.CLOEXEC);
        defer os.close(fd);

        const stat = try os.fstat(fd);
        const size = try std.math.cast(usize, stat.size);

        var mapped_mem = try os.mmap(
            null,
            mem.alignForward(size, mem.page_size),
            os.PROT.READ,
            os.MAP.PRIVATE,
            fd,
            0,
        );
        errdefer os.munmap(mapped_mem);

        const hdr64: *std.elf.Elf64_Ehdr = @ptrCast(*std.elf.Elf64_Ehdr, mapped_mem[0..@sizeOf(std.elf.Elf64_Ehdr)]);

        if (!mem.eql(u8, hdr64.e_ident[0..4], "\x7fELF")) return error.NotElfFile;
        if (hdr64.e_ident[elf.EI_VERSION] != 1) return error.InvalidElfVersion;

        // We only support 64bit for now
        if (hdr64.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) return error.UnsupportedElfClass;

        const endian: std.builtin.Endian = switch (hdr64.e_ident[elf.EI_DATA]) {
            elf.ELFDATA2LSB => .Little,
            elf.ELFDATA2MSB => .Big,
            else => return error.InvalidElfEndian,
        };
        // No handling for non-native endianness
        if (endian != native_endian) return error.UnsupportedElfEndian;

        return ElfFile{
            .allocator = allocator,
            .mapped_mem = mapped_mem,
            .hdr64 = hdr64,
            .symbols = ArrayList(Symbol).init(allocator),
        };
    }

    pub fn deinit(self: *ElfFile) void {
        for (self.symbols.items) |item| item.name.deinit();
        self.symbols.deinit();
        os.munmap(self.mapped_mem);
    }

    pub fn load_symbols(self: *ElfFile) !void {
        const shoff = self.hdr64.e_shoff;
        const str_section_off = shoff + @as(u64, self.hdr64.e_shentsize) * @as(u64, self.hdr64.e_shstrndx);
        const str_shdr = @ptrCast(
            *const elf.Elf64_Shdr,
            @alignCast(@alignOf(elf.Elf64_Shdr), &self.mapped_mem[try math.cast(usize, str_section_off)]),
        );
        const header_strings = self.mapped_mem[str_shdr.sh_offset .. str_shdr.sh_offset + str_shdr.sh_size];
        const shdrs = @ptrCast([*]const elf.Elf64_Shdr, @alignCast(@alignOf(elf.Elf64_Shdr), &self.mapped_mem[shoff]))[0..self.hdr64.e_shnum];

        for (shdrs) |*shdr| {
            if (shdr.sh_type == elf.SHT_NULL) continue;

            const name = std.mem.span(std.meta.assumeSentinel(header_strings[shdr.sh_name..].ptr, 0));

            if (mem.eql(u8, name, ".symtab")) {
                const numsymbols = shdr.sh_size / shdr.sh_entsize;

                const symtab = @ptrCast([*]const elf.Elf64_Sym, @alignCast(@alignOf(elf.Elf64_Sym), &self.mapped_mem[shdr.sh_offset]))[0..numsymbols];

                const strtab = shdrs[shdr.sh_link];
                const strtab_strings = self.mapped_mem[strtab.sh_offset .. strtab.sh_offset + strtab.sh_size];

                for (symtab) |*sym| {
                    const sym_name = std.mem.span(std.meta.assumeSentinel(strtab_strings[sym.st_name..].ptr, 0));

                    var symname = ArrayList(u8).init(self.allocator);
                    try symname.appendSlice(sym_name);

                    var symbol: Symbol = Symbol{
                        .name = symname,
                        .address = sym.st_value,
                    };

                    try self.symbols.append(symbol);
                }

                break;
            }
        }
    }
};
