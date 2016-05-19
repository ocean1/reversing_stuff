import pefile
import pydot

from glob import glob
from string import lower


graph = pydot.Dot(graph_type='graph')

flist = glob('*.dll')
flist += glob('*.exe')

flist_lc = map(lower, flist)


for f in flist:
    print "processing {}".format(f)
    pe = pefile.PE(f)

    node = pydot.Node(
        lower(f), style="filled", fillcolor="#bebeff")
    graph.add_node(node)

    for entry in pe.DIRECTORY_ENTRY_IMPORT:

        dll_name = lower(entry.dll)
        if dll_name not in flist_lc or dll_name == 'wcetrace.dll':
            print "\t{} wince binary".format(entry.dll)
            continue
            node = pydot.Node(
                lower(dll_name), style="filled", fillcolor="#ffbebe")
            graph.add_node(node)

        print "\t{}".format(entry.dll)
        edge = pydot.Edge(lower(f), lower(entry.dll))
        graph.add_edge(edge)

graph.write_png('deps.png')
