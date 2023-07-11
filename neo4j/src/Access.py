# from HTMLParser import *
#
# from NeoGraph import *
#
#
# '''
# traverse parent of for the UI element until AST_ASSIGN found.
# Get that node number N, return N+2 node for the variable
# '''
# '''
# I will delete the following function as we don't need it now, but need to throughly check
# '''
# def get_start_node_from_variable(graph, keyword):
#     '''get the start node by finding the keyword in the UI elements'''
#     query = '''
#     MATCH (n)
#     WHERE exists(n.code) AND n.type='string' AND toLower(n.code) CONTAINS '%s'
#     return n.id
#     ''' % keyword
#
#     data = graph.run(cypher=query).data()
#     var_nodes = []
#
#     for d in data:
#         id = d["n.id"]
#         # print("Starting to explore for "+str(id))
#
#         '''get the parent node'''
#         query1 = '''
#             match (a)-[:PARENT_OF*1..]->(b) where b.id= %d and a.type = 'AST_ASSIGN'
#             return a.id
#         ''' % id
#         parent = graph.run(cypher=query1).data()
#
#         if parent:
#             parent_id = int(parent[0]["a.id"])
#             a_id = parent_id + 2
#             query2 = '''
#                    MATCH (n)
#                    WHERE n.id = %d
#                    return n.code, n.id limit 1
#                    ''' % a_id
#             var_node = graph.run(cypher=query2).data()
#             if len(var_node[0]["n.code"].split()) == 1:
#                 var_nodes.append(var_node[0]["n.code"])
#         else:
#             print("Not Found")
#
#     return var_nodes
#
#
# '''
# I will probably delete the following function. but need to check it throughly before that
# '''
# def get_end_node(graph, node):
#     # 4719	AST	string		80	"_POST"	0	4706	GDPR_Requests_Public	""
#     # 14150	AST	string		23	"</h2>
#     # 		<p>
#     # 		<form method=\"post\" class=\"frm-export-data\">
#     # 			"	0	14106		""
#
#     id = 4719
#
#     while(True):
#
#         query1 = '''
#                        match (a)-[:PARENT_OF]->(b) where b.id= %d
#                        return a.id, a.type, a
#                    ''' % id
#
#         parent = graph.run(cypher=query1).data()
#         # print(parent)
#
#         if parent:
#             p_type = parent[0]["a.type"]
#             parent_id = int(parent[0]["a.id"])
#
#             print("Now looking at = " + str(id))
#             print(parent)
#             print("parent id= " + str(parent_id))
#             print("parent type= "+str(p_type))
#             id = parent_id
#         else:
#             break
#
#
#     return 0
#
#
# '''
# logic:
# Step 1: find the POST/SQL/PUT/GET nodes
# Step 2: Get the corresponding variables
# Step 3: Make a decision that the plugin is sending those data to the server
#
#
# step 1: find esc_html with specific keyword ('data access' etc.)
# step 2: check the same funcid contains post or not
# step 3: if step 2 is yes then the website has data access privilege, otherwise not
#
#
# Goal: Find mapping between the following code in the end node:
# keywords = ['download my data', 'data about a user', 'access my data']
# '''
# def get_end_node_from_html() -> dict:
#
#     keywords = ['download my data', 'data about a user', 'access my data']
#
#     html_keyword = 'esc_html_'
#     query = '''
#     MATCH (n)
#     WHERE exists(n.code) AND n.type='string' AND toLower(n.code) CONTAINS '%s'
#     return n.id
#     ''' % html_keyword
#
#     graph = getGraph()
#     nodes = graph.run(cypher=query).data()
#     ui_element_dict: Dict[int, List[str]] = {}
#     for node in nodes:
#         id = node["n.id"]
#         query = f'''
#         MATCH (n)
#         WHERE n.`id`= {id + 2}
#         return n.code, n.funcid
#         '''
#
#         elem_node = graph.run(cypher=query).data()
#         if elem_node[0]["n.funcid"] not in ui_element_dict:
#             ui_element_dict[ elem_node[0]["n.funcid"] ] = []
#         ui_element_dict[ elem_node[0]["n.funcid"] ].append(elem_node[0]["n.code"]) #it will indiciate the ui element name
#
#
#     query = f'''
#         match (a) where a.`type` = "string"
#         return  a.id, a.code, a.funcid
#         '''
#     graph = getGraph()
#     string_nodes = graph.run(cypher=query).data()
#
#     func_dict: Dict[int, List[str]] = {}
#
#     for node in string_nodes:
#         code = node["a.code"]
#         id = node["a.id"]
#         funcid = node["a.funcid"]
#         '''
#         store the variables by categorizing with function id
#         '''
#
#         if code:
#             '''
#             logic:
#             step 1: find the nodes which has post/get/put in its code
#             step 2: append that tag as the first element of that funcid list
#             step 3: append all the input variables categorizing with the function id
#
#             by exploring the funcid dictionary we can see that which function relates to POST/ PUT/ GET request and
#             the variables associated with those
#             '''
#             result_code, result, variable_name = parse_html_form_code(code)
#
#             if result_code == TAG_SUCCESS:
#                 if result == TAG_POST:
#                     if funcid not in func_dict:
#                         ui_element_dict[funcid] = []
#                     ui_element_dict[funcid].append(TAG_POST)
#
#     for k,vals in ui_element_dict.items():
#         # print(k,"->",vals)
#         for v in vals:
#             for key in keywords:
#                 if key.lower() in v.lower():
#                     print('Found: '+key+' -> '+ v)
#
#     return ui_element_dict
#
# '''
# collect all the string type node to check the corresponding code
# code can be of two types - variable name , html code
# all the time we will first look at the html code -> map the corresponding variable with it
# '''
# def get_start_node_from_html() -> dict:
#
#     query = f'''
#     match (a) where a.`type` = "string"
#     return  a.id, a.code, a.funcid
#     '''
#     graph = getGraph()
#     string_nodes = graph.run(cypher=query).data()
#
#     func_dict: Dict[int, List[str]] = {}
#     ui_elements = []
#
#     for node in string_nodes:
#         code = node["a.code"]
#         id = node["a.id"]
#         funcid = node["a.funcid"]
#         '''
#         store the variables by categorizing with function id
#         '''
#
#         if code:
#
#             '''
#             logic:
#             step 1: find the nodes which has post/get/put in its code
#             step 2: append that tag as the first element of that funcid list
#             step 3: append all the input variables categorizing with the function id
#
#             by exploring the funcid dictionary we can see that which function relates to POST/ PUT/ GET request and
#             the variables associated with those
#             '''
#             result_code, result, variable_name = parse_html_form_code(code)
#
#             if result_code == TAG_SUCCESS:
#                 if result == TAG_POST:
#                     if funcid not in func_dict:
#                         func_dict[funcid] = []
#                     func_dict[funcid].append(TAG_POST)
#
#                 if result == TAG_GET:
#                     if funcid not in func_dict:
#                         func_dict[funcid] = []
#                     func_dict[funcid].append(TAG_GET)
#
#                 if result == TAG_INPUT:
#                     if funcid in func_dict:
#                         func_dict[funcid].append(variable_name)
#             else:
#                 '''
#                 logic:
#                 step 1: get all the values of table in the html code, when found collect the node id
#                 step 2: then traverse all the node after that specific node
#                 step 3: if AST_VAR is found stop there, mark this node as N
#                 step 4: N+2 node indicates the variable associate with the UI element that we found in step 1
#
#                 map the variables between step 1 and step 4
#                 we can finetune the output variables name with the personal information type variables.
#                 so thus ignore the other unnecessary variables.
#                 '''
#                 result_code, result, variable_name = parse_html_td_code(code)
#                 if result_code == TAG_SUCCESS:
#                     if funcid not in func_dict:
#                         func_dict[funcid] = []
#                     func_dict[funcid].append(TAG_TD)
#                     while(True):
#                         type = __get_type(graph, id)
#                         if type == 'AST_VAR':
#                             id += 2
#                             var = __get_code(graph, id)
#
#                             if var:
#                                 func_dict[funcid].append(var)
#
#                                 elem = {}
#                                 elem [TAG_VARIABLE] = var
#                                 elem [TAG_UI_ELEMENT] = variable_name
#                                 elem [TAG_ID] = id
#                                 ui_elements.append(elem)
#
#                             break
#                         id += 1
#
#     for k,v in func_dict.items():
#         print(k,'->', v)
#
#     print("Printing mapping")
#     for elem in ui_elements:
#         print(elem)
#
#     return func_dict
#
# def __get_type(graph, id):
#     query = f'''
#     match (a) where a.`id`={id}
#     return a.type
#     '''
#     node = graph.run(cypher=query).data()
#
#     return node[0]["a.type"]
#
# def __get_code(graph, id):
#     query = f'''
#     match (a) where a.`id`={id}
#     return a.code
#     '''
#     node = graph.run(cypher=query).data()
#
#     return node[0]["a.code"]
#
# '''
# it will return the name of the file which contains a particular node given as id
# '''
# def __get_file_name(graph, id):
#
#     query = f'''
#     match (a) where a.`id` = {id}
#     match (b)-[*]->(a) where b.type =~ "AST_TOPLEVEL"
#     return b limit 1
#     '''
#     top_level_node = graph.run(cypher=query).evaluate()
#     name = top_level_node["name"]
#     return name
#
# def execute_query():
#     graph = getGraph()
#
#     query_keywords = [
#         'username', 'first name'
#     ]
#
#     var_nodes = get_start_node_from_variable(graph, query_keywords[1])
#     print(var_nodes)
#
#     # get_end_node(graph, "")
#
#
#
# def __run():
#     # execute_query()
#     # __get_file_name(15994)
#
#     # get_start_node_from_html()
#     get_end_node_from_html()
#     # print(__get_code(getGraph(), 21638))
#     return 0
#
#
# if __name__ == '__main__':
#     __run()
