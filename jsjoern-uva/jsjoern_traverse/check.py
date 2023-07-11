#!/usr/bin/env python3
import graph
import os
import argparse

def check(path, sinks=['exec', 'spawn', 'execSync', 'spawnSync', 'execFile']):
    g = graph.Graph()
    g.import_from_CSV(os.path.normpath(path + '/nodes.csv'),
                      os.path.normpath(path + '/rels.csv'),
                      os.path.normpath(path + '/cpg_edges.csv'))
    g.sink_funcs = sinks
    for node in g.graph.nodes:
        if next(g.graph.predecessors(node), None) is None:
            mark_input_func(g, node)
    for node in g.graph.nodes:
        if next(g.graph.predecessors(node), None) is None:
            traversal(g, node, 0, monitor=lambda node: check_sink(g, node))
    return g.vul_paths

def get_nearest_statement(g, node):
    """
    return the nearest statement node
    """
    return g.find_nearest_upper_CPG_node(node)

def find_exports_1(g, node):
    if g.get_node_attr(node).get('type') == 'AST_ASSIGN':
        children = g.get_ordered_ast_child_nodes(node)
        if len(children) != 2:
            return
        left, right = children[:2]
        flag = False
        if g.get_name_from_child(left) == 'exports':
            flag = True
        elif g.get_node_attr(left).get('type') == 'AST_PROP':
            parent, prop = g.get_ordered_ast_child_nodes(left)[:2]
            if g.get_name_from_child(parent) == 'module' and \
                g.get_name_from_child(prop) == 'exports':
                flag = True
        if flag:
            if g.get_node_attr(right).get('type') == 'AST_ARRAY':
                # module.exports = { foo: foo, ... }
                for elem in g.get_ordered_ast_child_nodes(right):
                    value = g.get_ordered_ast_child_nodes(elem)[0]
                    if g.get_node_attr(value).get('type') not in [
                        'AST_VAR', 'AST_FUNC_DECL', 'AST_CLOSURE']:
                        continue
                    name = g.get_name_from_child(value)
                    if name is None or name == '{closure}':
                        # module.exports = { foo: function() {...} }
                        key = g.get_ordered_ast_child_nodes(elem)[1]
                        name = g.get_name_from_child(key)
                    if name is not None:
                        g.exported_func_names.append(name)
            else:
                name = g.get_name_from_child(right)
                if name is not None:
                    g.exported_func_names.append(name)

def find_exports_2(g, node):
    func = None
    if g.get_node_attr(node).get('type') == 'AST_ASSIGN':
        children = g.get_ordered_ast_child_nodes(node)
        if len(children) != 2:
            return
        left, right = children[:2]
        if g.get_node_attr(right).get('type') in ['AST_FUNC_DECL', 'AST_CLOSURE']:
            name = g.get_name_from_child(left)
            if name is None or name == '{closure}':
                # var foo = function (){ ... }
                name = g.get_name_from_child(g.get_node_attr(left))
            if name in g.exported_func_names:
                func = right
    elif g.get_node_attr(node).get('type') in ['AST_FUNC_DECL', 'AST_CLOSURE']:
        name = g.get_name_from_child(node)
        if name in g.exported_func_names:
            func = node
    if func is not None:
        for e1 in g.get_out_edges(func, edge_type='PARENT_OF'):
            if g.get_node_attr(e1[1]).get('type') == 'AST_PARAM_LIST':
                for e2 in g.get_out_edges(e1[1], edge_type='PARENT_OF'):
                    if g.get_node_attr(e2[1]).get('type') == 'AST_PARAM':
                        # data flows start from parameters
                        g.exported_func_params.append(e2[1])

def mark_input_func(g, start_node='0'):
    """
    mark all the exported functions
    """
    traversal(g, start_node, 0, lambda node: find_exports_1(g, node))
    # print('exported functions:', g.exported_func_names)
    traversal(g, start_node, 0, lambda node: find_exports_2(g, node))
    # print('exported functions:', g.exported_func_params)

def traversal(g, node, level, monitor=None):
    """
    traversal a tree from the root
    Args:
        node: the node to start
        monitor: for each node, triger the monitor function
    """
    if node is None:
        return []
    path = [node]
    if monitor is not None:
        monitor(node)
    # print("\t" * level, node, g.get_node_attr(node))
    edges = g.get_out_edges(node, edge_type='PARENT_OF') \
            + g.get_out_edges(node, edge_type='DIRECTORY_OF') \
            + g.get_out_edges(node, edge_type='FILE_OF')
    for e in edges:
        child = e[1]
        path += traversal(g, child, level + 1, monitor)
    return path

def trace_up(g, node):
    """
    trace up from a node, follow the data flow edge
    """
    paths = []
    nodes = [node]
    for start in nodes:
        nodes_group = [e[0] for e in g.get_in_edges(node, edge_type='REACHES')]
        stack = [(start, iter(nodes_group))]
        while stack:
            # print(stack)
            parent, children = stack[-1]
            try:
                child = next(children)
                if child not in [s[0] for s in stack]:
                    nodes_group = [e[0] for e in 
                                    g.get_in_edges(child, edge_type='REACHES')]
                    stack.append((child, iter(nodes_group)))
                    if len(nodes_group) == 0:
                        # print(stack)
                        paths.append([node[0] for node in stack])
            except StopIteration:
                stack.pop()
    return paths

def check_sink(g, node):
    found = False
    if g.get_node_attr(node).get('type') in ['AST_CALL', 'AST_METHOD_CALL', 'AST_NEW']:
        # get the statement
        if g.get_name_from_child(node) in g.sink_funcs:
            found = True
        if not found:
            return False
        parent_node = get_nearest_statement(g, node) 
        paths = trace_up(g, parent_node)
        # print(paths)
        for path in paths:
            for n in path:
                if n in g.exported_func_params:
                    g.vul_paths.append(path)
                    break

def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-f', '--input_dir', default=os.path.normpath(__file__ + '/../..'))
    args = argparser.parse_args()
    input_dir_path = args.input_dir
    check(input_dir_path)

if __name__ == '__main__':
    main()
