# rename functions loading addresses using nm

import idaapi
import idc
from subprocess import Popen, PIPE


def make_func(addr):
    idc.MakeCode(addr)
    idc.MakeFunction(addr)


if __name__ == "__main__":
    executable = idaapi.get_input_file_path()
    proc = Popen(
        "nm {}".format(executable),
        shell=True,
        stdout=PIPE,
        stderr=PIPE)

    out, err = proc.communicate()
    errcode = proc.returncode

    if errcode != 0:
        raise Exception("cannot get symbols!")

    proc = Popen(
        "nm -C {}".format(executable),
        shell=True,
        stdout=PIPE,
        stderr=PIPE)

    out_demangled, err = proc.communicate()
    errcode = proc.returncode

    if errcode != 0:
        raise Exception("cannot get demangled symbols!")

    symbols = {}

    for nlist, dlist in zip(out.splitlines(), out_demangled.splitlines()):
        a, t, name = nlist.split(" ")
        d = dlist.split(" ")
        ad = d[0]
        td = d[1]
        named = " ".join(d[2:])

        if a != ad:
            raise Exception("error processing %s/%s, %s != %s".format(
                name, named, a, ad))
        addr = int(a, 16)

        if t in ["t", "T"]:
            make_func(addr)
            if name.lstrip("_") != named.lstrip("_"):
                idc.SetFunctionCmt(addr, named, 0)

        idc.MakeNameEx(addr, name, idc.SN_NOWARN)
        if name.lstrip("_") != named.lstrip("_"):
            idc.MakeComm(addr, named)
