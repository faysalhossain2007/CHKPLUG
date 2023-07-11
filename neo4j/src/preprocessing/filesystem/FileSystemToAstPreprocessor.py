from ..Preprocessor import Preprocessor

from py2neo import Graph, Relationship


class FileSystemToAstPreprocessor(Preprocessor):
    """Connects Filesystem nodes to AST_TOPLEVEL Nodes"""


    def process_graph(self, graph: Graph) -> Graph:
        # NB (nphair): the name field in AST_TOPLEVEL nodes is a path relative to the plugin directory.
        tl_match = graph.nodes.match('AST', type='AST_TOPLEVEL')
        tl_nodes = {node['name']: node for node in tl_match}
        fs_match = graph.nodes.match('Filesystem')
        fs_nodes = {node['rel_path']: node for node in fs_match}

        tx = graph.begin()
        for name, node in fs_nodes.items():
            try:
                tx.create(Relationship(node, 'FILE_OF', tl_nodes[name]))
            except KeyError:
                print(f'no AST_TOPLEVEL node for: {name}')
        graph.commit(tx)

        return graph

    def __init__(self, name):
        super().__init__(name)
