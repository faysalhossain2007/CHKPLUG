import networkx as nx
import sys
import csv
import io

class Graph:

    def __init__(self):
        self.graph = nx.MultiDiGraph()

        csv.field_size_limit(2 ** 31 - 1)
        class joern_dialect(csv.excel_tab):
            def __init__(self):
                super().__init__(self)
                self.escapechar = '\\'
        self.csv_dialect = joern_dialect

        self.exported_func_params = []
        self.exported_func_names = []
        self.vul_paths = []
        self.sink_funcs = []
        self.file_paths = []

    # node

    def _get_new_nodeid(self):
        """
        return a nodeid
        """
        self.cur_id += 1
        return str(self.cur_id - 1)

    def add_node(self, node_for_adding, attr={}):
        self.graph.add_node(node_for_adding, **attr)
        return node_for_adding

    def set_node_attr(self, node_id, attr):
        """
        attr should be a tuple like (key, value)
        will be added to a node id
        """
        self.graph.nodes[node_id][attr[0]] = attr[1]

    def get_node_attr(self, node_id):
        """
        this function will return a dict with all the attrs and values
        """
        assert node_id is not None
        return self.graph.nodes[node_id]

    # edges

    def add_edge(self, from_ID, to_ID, attr):
        """
        insert an edge to graph
        attr is like {key: value, key: value}
        """
        assert from_ID is not None, "Failed to add an edge, from_ID is None."
        assert to_ID is not None, "Failed to add an edge, to_ID is None."
        assert from_ID != 'string' and to_ID != 'string'
        # self.graph.add_edges_from([(from_ID, to_ID, attr)])
        self.graph.add_edge(from_ID, to_ID, None, **attr)
    
    def add_edge_if_not_exist(self, from_ID, to_ID, attr):
        """
        insert an edge to the graph if the graph does not already has the same edge
        """
        assert from_ID is not None, "Failed to add an edge, from_ID is None."
        assert to_ID is not None, "Failed to add an edge, to_ID is None."
        if not self.graph.has_edge(from_ID, to_ID):
            self.add_edge(from_ID, to_ID, attr)
        else:
            for key, edge_attr in self.graph[from_ID][to_ID].items():
                if edge_attr == attr:
                    self.logger.warning("Edge {}->{} exists: {}, {}. Duplicate edge "
                    "will not be created.".format(from_ID,to_ID,key,edge_attr))
                    return
            self.add_edge(from_ID, to_ID, attr)

    def set_edge_attr(self, from_ID, to_ID, edge_id, attr):
        self.graph[from_ID][to_ID][attr[0]][edge_id] = attr[1]

    def get_edge_attr(self, from_ID, to_ID, edge_id = None):
        if edge_id == None:
            return self.graph.get_edge_data(from_ID, to_ID)
        return self.graph[from_ID][to_ID][edge_id]

    def add_edges_from_list(self, edge_list):
        return self.graph.add_edges_from(edge_list)
    
    def get_out_edges(self, node_id, data = True, keys = True, edge_type = None):
        assert node_id is not None
        if edge_type is None:
            return self.graph.out_edges(node_id, data = data, keys = keys)
        edges = self.graph.out_edges(node_id, data = data, keys = keys)
        idx = 1
        if keys == True:
            idx += 1
        if data == True:
            idx += 1
        return [edge for edge in edges if 'type:TYPE' in edge[idx] and edge[idx]['type:TYPE'] == edge_type]

    def get_in_edges(self, node_id, data = True, keys = True, edge_type = None):
        assert node_id is not None
        if edge_type == None:
            return self.graph.in_edges(node_id, data = data, keys = keys)
        edges = self.graph.in_edges(node_id, data = data, keys = keys)
        idx = 2
        if keys == True:
            idx = 3
        return [edge for edge in edges if 'type:TYPE' in edge[idx] and edge[idx]['type:TYPE'] == edge_type]

    # high-level

    def _get_childern_by_childnum(self, node_id):
        """
        helper function, get the childern nodeid of the node_id
        return a dict, with {childnum: node_id}
        """
        edges = self.get_out_edges(node_id, edge_type = "PARENT_OF")
        res = {}
        for edge in edges:
            node_attr = self.get_node_attr(edge[1])
            if 'childnum:int' not in node_attr:
                continue
            res[node_attr['childnum:int']] = edge[1]
        return res

    def get_ordered_ast_child_nodes(self, node_id):
        """
        return AST children of a node in childnum order
        """
        children = sorted(self._get_childern_by_childnum(node_id).items(),
                            key=lambda x: int(x[0]))
        if children:
            children = list(zip(*children))[1]

        return children
    
    def find_nearest_upper_CPG_node(self, node_id):
        """
        Return the nearest upper CPG node of the input node.
        
        A CPG node is defined as a child of a block node
        (AST_STMT_LIST).
        """
        # follow the parent_of edge to research the stmt node
        while True:
            assert node_id is not None
            parent_edges = self.get_in_edges(node_id, edge_type = "PARENT_OF")
            if parent_edges is None or len(parent_edges) == 0:
                return None
            parent_node = parent_edges[0][0]
            parent_node_attr = self.get_node_attr(parent_node)
            if parent_node_attr.get('type') in ["AST_STMT_LIST"]:
                return node_id 
            node_id = parent_node

    def get_name_from_child(self, nodeid, max_depth = None):
        """
        try to find the name of a nodeid
        we have to use bfs strategy
        """
        bfs_queue = []
        visited = set()
        bfs_queue.append((nodeid, 0))

        while(len(bfs_queue)):
            cur_node, cur_depth = bfs_queue.pop(0)
            if max_depth and cur_depth > max_depth: break

            # if visited before, stop here
            if cur_node in visited:
                continue
            else:
                visited.add(cur_node)

            cur_attr = self.get_node_attr(cur_node)

            if 'type' not in cur_attr:
                continue
            if cur_attr['type'] == 'string':
                if cur_attr.get('name'):
                    return cur_attr['name']
                if cur_attr.get('code'):
                    return cur_attr['code']
            elif cur_attr['type'] == 'integer':
                return str(cur_attr['code'])

            out_edges = self.get_out_edges(cur_node, edge_type = 'PARENT_OF')
            out_nodes = [(edge[1], cur_depth + 1) for edge in out_edges]
            bfs_queue += out_nodes

        return None

    def count(self):
        ast_num, cf_num, df_num, cg_num = 0, 0, 0, 0
        for e in self.graph.edges(data=True, keys=True):
            if e[3].get('type:TYPE') == 'PARENT_OF':
                ast_num += 1
            elif e[3].get('type:TYPE') == 'FLOWS_TO':
                cf_num += 1
            elif e[3].get('type:TYPE') == 'REACHES':
                df_num += 1
            elif e[3].get('type:TYPE') == 'CALLS':
                cg_num += 1
        return ast_num, cf_num, df_num, cg_num

    # import/export

    def import_from_CSV(self, nodes_file_name, rels_file_name, cpg_edges_file_name):
        with open(nodes_file_name) as fp:
            reader = csv.DictReader(fp, dialect=self.csv_dialect)
            for row in reader:
                cur_id = row['id:ID']
                self.add_node(cur_id)
                for attr, val in row.items():
                    if attr == 'id:ID': continue
                    self.set_node_attr(cur_id, (attr, val))

        with open(rels_file_name) as fp:
            reader = csv.DictReader(fp, dialect=self.csv_dialect)
            edge_list = []
            for row in reader:
                attrs = dict(row)
                del attrs['start:START_ID']
                del attrs['end:END_ID']
                edge_list.append((row['start:START_ID'], row['end:END_ID'], attrs))
            self.add_edges_from_list(edge_list)

        with open(cpg_edges_file_name) as fp:
            reader = csv.DictReader(fp, dialect=self.csv_dialect)
            edge_list = []
            for row in reader:
                attrs = dict(row)
                del attrs['start:START_ID']
                del attrs['end:END_ID']
                edge_list.append((row['start:START_ID'], row['end:END_ID'], attrs))
            self.add_edges_from_list(edge_list)
        # print("Finished Importing")

        self.cur_id = self.graph.number_of_nodes()

    def export_to_CSV(self, nodes_file_name, rels_file_name):
        """
        export to CSV to import to neo4j
        """
        with open(nodes_file_name, 'w') as fp:
            headers = ['id:ID','labels:label','type','flags:string[]','lineno:int','code','childnum:int','funcid:int','classname','namespace','endlineno:int','name','doccomment']
            writer = csv.DictWriter(fp, dialect=self.csv_dialect, fieldnames=headers, extrasaction='ignore')
            writer.writeheader()
            nodes = list(self.graph.nodes(data = True))
            nodes.sort(key = lambda x: int(x[0]))
            for node in nodes:
                node_id, attr = node
                row = dict(attr)
                row['id:ID'] = node_id
                writer.writerow(row)

        with open(rels_file_name, 'w') as fp:
            headers = ['start:START_ID','end:END_ID','type:TYPE','var','taint_src','taint_dst']
            writer = csv.DictWriter(fp, dialect=self.csv_dialect, fieldnames=headers, extrasaction='ignore')
            writer.writeheader()
            light_edge_type = ['FLOWS_TO', 'REACHES', 'OBJ_REACHES', 'ENTRY', 'EXIT']
            edges = list(self.graph.edges(data = True, keys = True))
            for edge in edges:
                edge_from, edge_to, _, attr = edge
                row = dict(attr)
                row['start:START_ID'] = edge_from
                row['end:END_ID'] = edge_to
                writer.writerow(row)

        print("Finished Exporting to {} and {}".format(nodes_file_name, rels_file_name))