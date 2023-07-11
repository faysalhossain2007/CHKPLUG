from ..Preprocessor import Preprocessor
from ..utils.NodeIdGenerator import NodeIdGenerator

from py2neo import Graph
from py2neo.bulk import create_nodes, create_relationships

from pathlib import Path


class FileSystemPreprocessor(Preprocessor):
    """Model a plugin's directory structure as a graph."""

    SUFFIX_WHITELIST = [
        '.htm',
        '.html',
        '.php',
        '.js'
    ]

    def process_graph(self, graph: Graph) -> Graph:
        paths = [p.resolve() for p in self._plugin_dir.rglob('*') if FileSystemPreprocessor._is_valid_path(p)]
        paths.append(self._plugin_dir)
        paths = sorted(paths)

        props = [self._properties_from_path(p) for p in paths]
        create_nodes(graph.auto(), props, labels={"Filesystem"})
        rels = [self._rel_data_from_path(p) for p in paths]
        create_relationships(graph.auto(),
                             rels,
                             "DIRECTORY_OF",
                             start_node_key=("Filesystem", "path", "type"),
                             end_node_key=("Filesystem", "path"))

        return graph

    @staticmethod
    def _is_valid_path(path):
        return path.is_dir() or path.suffix.lower() in FileSystemPreprocessor.SUFFIX_WHITELIST

    def _rel_data_from_path(self, path):
        start_node = (str(path.parent), 'Directory')
        end_node = str(path)
        detail = {}
        return start_node, detail, end_node

    def _properties_from_path(self, path):
        props = {}
        props['filename'] = path.name
        props['path'] = str(path)
        props['type'] = 'directory' if path.is_dir() else 'file'

        stats = path.stat()
        props['mode'] = oct(stats.st_mode)
        props['uid'] = stats.st_uid
        props['gid'] = stats.st_gid
        props['size'] = stats.st_size
        props['atime'] = stats.st_atime
        props['mtime'] = stats.st_mtime
        props['ctime'] = stats.st_ctime

        # NB (nphair): Properties formatted to be backwards compatible with old version.
        props['name'] = path.name
        props['type'] = 'Directory' if path.is_dir() else 'File'
        props['rel_path'] = str(path.relative_to(self._plugin_dir))
        props['id'] = NodeIdGenerator.generate_id()

        return props

    def __init__(self, name, plugin_dir):
        super().__init__(name)
        self._plugin_dir = Path(plugin_dir).resolve(strict=True)
