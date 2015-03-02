from idaapi import *
import struct


DSX_MAGIC = "3DSX"
DEFAULT_CPU = "ARM"
DEBUG = False

BASE_ADDR = 0x00100000


def accept_file(li, n):

    retval = 0

    if n == 0:
        li.seek(0)

        # Make sure this is a bFLT v4 file
        if li.read(4) == DSX_MAGIC:
            idaapi.set_processor_type(DEFAULT_CPU, SETPROC_ALL)
            retval = "%s executable" % (DSX_MAGIC)

    return retval


class SegmentInfo(object):

    def __init__(self, name, start, size):
        self.name = name
        self.start = start
        self.size = size
        self.seg_size = (self.size + 0xFFF) & (~0xFFF)
        self.end = self.start + self.seg_size

    def add_segm(self, flags):
        add_segm(0, self.start, self.end, self.name, flags)


def load_file(li, neflags, format):

    # read 3DSX header
    li.seek(0)
    (magic, header_size, reloc_hdr_size, version, flags,
        code_seg_size, rodata_seg_size, data_seg_size, bss_size
     ) = struct.unpack("<IHHIIIIII", li.read(4 * 7 + 2 * 2))

    n_reloc_tables = reloc_hdr_size / 4

    reloc_entries = []
    for i in range(3):
        n_relocs = struct.unpack(
            "<" + "I" * n_reloc_tables, li.read(4 * 2))
        reloc_entries.append(n_relocs)

    if DEBUG:
        print "header:"
        print "magic: 0x%.8X" % magic
        print "header_size: 0x%.4X" % header_size
        print "reloc_hdr_size: 0x%.4X (%d tables)" % (
            reloc_hdr_size, n_reloc_tables)
        print "version: 0x%.8X" % version
        print "flags: 0x%.8X" % flags
        print "code_seg_size: 0x%.8X" % code_seg_size
        print "rodata_seg_size: 0x%.8X" % rodata_seg_size
        print "data_seg_size (inc bss):0x%.8X" % data_seg_size
        print "bss_size: 0x%.8X\n" % bss_size

    # ADD SEGMENTS
    code_seg = SegmentInfo('.text', BASE_ADDR, code_seg_size)
    code_seg.add_segm("CODE")
    li.file2base(
        li.tell(), code_seg.start, code_seg.start + code_seg.size, True)
    # Explicitly set 32 bit addressing on .text segment
    set_segm_addressing(getseg(code_seg.start), 1)

    rodata_seg = SegmentInfo('.rodata', code_seg.end, rodata_seg_size)
    li.file2base(
        li.tell(), rodata_seg.start, rodata_seg.start + rodata_seg.size, True)
    rodata_seg.add_segm("RODATA")

    data_seg = SegmentInfo('.data', rodata_seg.end, data_seg_size)
    li.file2base(
        li.tell(), data_seg.start,
        data_seg.start + data_seg.size - bss_size,
        True
    )
    data_seg.add_segm("DATA")

    reloc_start_pos = li.tell()

    seg_info = [code_seg, rodata_seg, data_seg]

    tot_headers_size = header_size + reloc_hdr_size * 3
    # looks like we have N reloc table per section (bss excluded)
    li.seek(tot_headers_size)

    if DEBUG:
        print "Created File Segments: "
        print "\t.text   0x%.8X - 0x%.8X" % (code_seg.start, code_seg.end)
        print "\t.data   0x%.8X - 0x%.8X" % (rodata_seg.start, rodata_seg.end)
        print "\t.data   0x%.8X - 0x%.8X" % (data_seg.start, data_seg.end)

    # Entry point is at the beginning of the .text section
    add_entry(BASE_ADDR, BASE_ADDR, "_start", 1)

    # Set default processor
    set_processor_type(DEFAULT_CPU, SETPROC_ALL | SETPROC_FATAL)

    # Patch relocations
    li.seek(reloc_start_pos)  # position at the start of the relocation tables

    def translate_addr(addr):
        # now for each segment try to reloc
        if addr < code_seg.size:
            return addr + seg_info[0].start
        elif addr < code_seg.size + rodata_seg.size:
            return addr + seg_info[1].start - seg_info[0].seg_size
        else:
            return (addr + seg_info[2].start -
                    seg_info[0].seg_size - seg_info[1].seg_size)

        return addr

    for segment in range(0, 3):
        for current_reloc_table in range(n_reloc_tables):
            try:
                n_relocs = reloc_entries[segment][current_reloc_table]

                if current_reloc_table >= 2:
                    # skip those tables (see 3dsx.cpp from citra)
                    if DEBUG:
                        print "Skipping table %d!" % current_reloc_table
                    li.seek(n_relocs * 4, 1)
                    break

                # get positions for current segment
                pos = seg_info[segment].start  # start
                end_pos = seg_info[segment].end  # end

                if DEBUG:
                    print "relocation of 0x%.8x entries" % n_relocs

                for i in range(n_relocs):
                    # ok now go to the table read the u16 size, patch
                    # and patch the dwords, gut!

                    (skip, num_patches) = struct.unpack("<HH", li.read(4))
                    # update with number of bytes to skip
                    # the position in current segment
                    pos += skip * 4

                    if DEBUG:
                        print "number of patches %.4X" % patch

                    while(0 < num_patches and pos < end_pos):
                        try:
                            # In case this is a text reference, try to
                            # create a string at the data offset address.
                            # If that fails, just make it a DWORD.

                            # Replace pointer at reloc_offset with the
                            # address of the actual data
                            addr = Dword(pos)  # get the addr to patch

                            in_addr = translate_addr(addr)

                            if current_reloc_table == 1:
                                #  this is the relative reloc table
                                in_addr -= pos

                            try:
                                if in_addr > code_seg.end:
                                    if not Name(in_addr):
                                        if not MakeStr(in_addr, BADADDR):
                                            MakeDword(in_addr)
                            except:
                                print "error in data analysis of %.8X: %.8X <- %.8X" % (
                                    pos, addr, in_addr)

                            PatchDword(pos, in_addr)
                            SetFixup(
                                pos, idaapi.FIXUP_OFF32 | idaapi.FIXUP_CREATED,
                                0, in_addr, 0)

                            if DEBUG:
                                print "patched %.8X: %.8X <- %.8X" % (
                                    pos, addr, in_addr)
                        except Exception, e:
                            print "Error patching relocation entry: %s" % str(e)
                        pos += 4
                        num_patches -= 1

            except Exception, e:
                print "Error processing relocation entry: %s" % (str(e))
                raise

    return True
