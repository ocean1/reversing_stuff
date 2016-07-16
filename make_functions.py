from idautils import *
from idaapi import *

info = get_inf_structure()


def analyze_functions(curr_addr, end_addr):
    addiu = "27 BD"  # 27 BD XX XX addiu  $sp, immediate
    pushebp = "55 89 E5 81 EC"  # 55 89 E5 81 EC XX push ebp
    #                   mov ebp, esp
    #                   sub esp, XX

    if info.procName in ["mips", "mipsr"]:
        prologue = addiu
    elif info.procName in ["metapc"]:
        prologue = pushebp
    else:
        print "architecture %s not supported" % info.get_proc_name()
        return

    n = 0
    if curr_addr < end_addr:
        print (
            "prologue function search between: 0x%X and 0x%x" %
            (curr_addr, end_addr))

        while curr_addr < end_addr and curr_addr != BADADDR:
            curr_addr = FindBinary(curr_addr, SEARCH_DOWN, prologue)

            if (GetFunctionAttr(curr_addr, FUNCATTR_START) == BADADDR and
                    curr_addr != BADADDR and
                    curr_addr < end_addr and
                    curr_addr % 4 == 0):

                immediate = int(GetManyBytes(
                    curr_addr + 2, 2, False).encode('hex'), 16)
                # Jump(curr_addr) # useful for debugging, but has performance
                # impact
                # check if most sigificant bit is set -> $sp -0x1
                if immediate & 0x8000:
                    if MakeFunction(curr_addr):
                        n += 1
                    else:
                        print ('MakeFunction(0x%x) failed' /
                               '- running 2nd time maybe fixes this'
                               % curr_addr)
            curr_addr += 1

        print "Created %d new functions\n" % n
        return n
    else:
        print "Invalid end address of CODE segment!"

# makes sure start address is 4-byte aligned
curr_addr = ScreenEA() & 0xFFFFFFFC
end_addr = AskAddr(0, "Enter end address of CODE segment.")
analyze_functions(curr_addr, end_addr)
