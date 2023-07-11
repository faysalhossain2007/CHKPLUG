
import os
import time
from joern.all import JoernSteps

j = JoernSteps()

j.setGraphDbURL('http://localhost:7474/db/data/')

#j.addStepsDir('/home/abeer/python-joern-0.3.1/joern/joernsteps/')

j.connectToDatabase()
#query = "g.V.has('type', 'AST_TOPLEVEL').code"

#static-test
#query =  file(os.path.join(os.path.dirname(__file__), "static-test.groovy")).read() + "\n"
#query1= "match (n:AST)-[:PARENT_OF]->()-[:PARENT_OF]->(m:AST) where n.type = 'AST_CALL' AND m.code IN ['mysql_query', 'pg_query', 'sqlite_query'] return n.id"
query = """g.V('url', 'http://localhost/mybloggie/admin.php?mode=adduser')
.findNavigationSeq('http://localhost/mybloggie/index.php').dedup().path()"""
#filter{it.type == 'AST_INCLUDE_OR_EVAL'}.sideEffect{filename = it.toFileAbs().next().name}.children().filter{it.type == 'string'}.transform{[filename, it.code]}"
#query = """sql_query_funcs = ["mysql_query", "pg_query", "sqlite_query"]
#g.V().filter{ sql_query_funcs.contains(it.code)  && isCallExpression(it.nameToCall().next()) }.callexpressions().id""" 

"""MATCH (node:AST)-[:PARENT_OF]->()-[:PARENT_OF]->(m:AST)
USING INDEX node:AST(type)
WHERE node.type = 'AST_CALL' AND m.code IN ['mysql_query', 'pg_query', 'sqlite_query'] 
RETURN node.id;"""
query="""g.V().includeMap()"""
query = """os_command_funcs = [
               "backticks", "exec" , "expect_popen","passthru","pcntl_exec",
               "popen","proc_open","shell_exec","system", "mail", "mysql_query"     
               ]\n; m=[]; hasExit= false;\n"""
query += """g.V().filter{ "header" == it.code  && isCallExpression(it.nameToCall().next()) }.callexpressions()
                  .ithChildren(1).astNodes()
                 .filter{it.code != null && it.code.startsWith("Location")}
                 .callexpressions()
                 
                 .as('call')
                 .out('FLOWS_TO')
                 .filter{it.type != "AST_EXIT" && it.type != "NULL" }
                  

                 .or(
                        _().filter{it.type == "AST_CALL"}
                           .sideEffect{n = jumpToCallingFunction(it)}
                           .filter{n.type != "AST_EXIT" && n.type != "NULL" && n.type != "AST_RETURN"} 
                    ,
                       _().filter{it.type == "AST_CALL"}
                           .sideEffect{n = jumpToCallingFunction(it)}
                           .filter{n.type == "AST_RETURN"}
                           .out('FLOWS_TO')
                           .filter{n.type != "AST_EXIT" && n.type != "NULL" } 
                    ,
                       _().filter{it.type != "AST_CALL"}

                    ,
                    _().as('b')
                 .filter{it.type == "AST_CALL"}
                        
                        .astNodes()
                        .filter{it.code != null &&
                                 it.code != "/home/abeer/log/codeCoverage.txt"}
                         .back('b')

                    )
                 .back('call')
                 .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'ear', '1')}
                 .transform{warnmessage}

                 //.transform{earStart(it)}
                 //.transform{m}
        
                          """
query = """g.V().filter{ "header" == it.code  && isCallExpression(it.nameToCall().next()) }.callexpressions()
                  .ithChildren(1).astNodes()
                 .filter{it.code != null && it.code.startsWith("Location")}
                 .callexpressions()
                 
                 """

query = """g.V().filter{ "mysql_query" == it.code  && isCallExpression(it.nameToCall().next()) }.callexpressions()
                """

query = """g.v(4).out("PARENT_OF")
           .loop(1){it.loops < 10}
           .path(){it.code}"""               

query = """visited = [] ; g.v(50).as('parent')
                  .in("PARENT_OF")
                  .as('children')
                  .children()
                  .loop('children'){it.loops <5}{true}
                  .filter{it.code != null}
                  .sideEffect{visited.add(it.id)}
                  .back('parent')
                  .in("PARENT_OF")
                  .loop('parent'){ !visited.contains(it.object.id ) && it.loops <5}
                  .dedup()
                  .path(){it.id}
                 
             
           """

#this will traverse beckward until it reaches an AST stmt list
query = """visited = [] ; root = g.v(50).as('parent')

                  .sideEffect{last = it}
                  .in("PARENT_OF")
                  .loop('parent'){it.object.type != ("AST_STMT_LIST")}
                  .transform{last}
                  
                   root.astNodes()
                  .filter{it.code != null}
                 
             
           """
query= """g.v(10).statements().astNodes()
         .filter{it.code != null}
         .parents()"""  

#testing db constraints construction for insert/update queries


query = """ m=[:]; g.V().filter{"mysql_query" == (it.code)  && isCallExpression(it.nameToCall().next()) }.callexpressions()
        .as("all")
        .copySplit(
          _().callToArgumentsNew()
           
           .match{ it.code != null }
           .dedup()
           ,


            _().statements()
               .in('REACHES')
               .statements()
               .astNodes()
                .match{ it.code != null }
          
          .dedup()
         )

 .fairMerge
           .as('query')
           .filter{it.code.toLowerCase().contains("insert into") or it.code.toLowerCase().contains("update")}
           //save the query
           .dedup()
           .back('query')
           .sideEffect{query = it.parents()}
           //.transform{query}
           //get all query parts and order them for parsing 

           
           .back("all")

           .astNodes()
           .filter{it.type == "string"}
           .groupCount.cap.orderMap(T.decr) //this is to order the nodes based on thier id
           //.ifThenElse{it.parents().next().type == "AST_VAR"}
             //{it.sideEffect{query_str = '$'.concat(it.code)}}
             //{it.sideEffect{query_str = it.code}}
            //.sideEffect{m=[it.id, query_str]}

            //.transform {m}
            
            .or(
             _().filter{it.parents().next().type == "AST_VAR" }
                .sideEffect{query_str = '$'.concat(it.code)}
              ,
             _().filter{it.parents().next().type == "AST_DIM" && it.type == "string" }
               .sideEffect{query_str = '['.concat(it.code).concat(']')}
             , 
              _().sideEffect{query_str = it.code}      
             )
             .transform{query_str}
             //**** end getting the query the string in order 
             //*****start invoking the sql parser
             //.in('PARENT_OF').loop(1){true}{it.object.getProperty("type") == 'AST_TOPLEVEL'}
             // .filter{(it.flags.contains("TOPLEVEL_FILE")) }
             //.toFile().in(DIRECTORY_EDGE)
             //.dedup()
      
           
        """

query= """ edgeVar = []; varsInSink = []; queryTypes=['Insert', 'Update', 'Delete', 'Select', 'insert', 'update', 'delete', 'select', 'INSERT', 'UPDATE', 'DELETE', 'SELECT'];
           //g.V().filter{"mysql_query" == (it.code)  && isCallExpression(it.nameToCall().next()) }.callexpressions()



         g.V().filter{it.id == 42347}
         
          .statements()
          .as('gettingEdgeVar')
            .inE(DATA_FLOW_EDGE).var.aggregate(edgeVar)
           //.sideEffect{ it.inE(DATA_FLOW_EDGE).var.aggregate(edgeVar)}
           .back('gettingEdgeVar')
           //.transform{edgeVar}
           .as('inspect')
         
           .astNodes()
           .dedup()
           .filter{it.type == "string"}
           .sideEffect{str = it.code}
           //.transform{str}
           
           .sideEffect{check = containsInList(queryTypes, str)}
           .sideEffect{it= it.statements()
                          .in(DATA_FLOW_EDGE)
                          .sideEffect{varinEdge = it.var}
                       }
           
           .loop('inspect'){!check }
           .statements()//root of the query string node
           
           
          // .parents()
           //get the vars in that node 

           .ifThenElse{it.type == TYPE_ASSIGN}
               {it.ithChildren(1)} // right hand side
               {it}

           .astNodes()
           .filter{it.type == "AST_VAR" }
           .dedup()
           .sideEffect{varNodeChildNum = it.id}
           .sideEffect{context = it.parents().astNodes()
                              .filter{it.type == "string"}.code
                              //.filter{!it.contains("'") && !it.contains('"') }
                                //   .transform{context = "NO_QUOTES"}

                             // }

                            .or(
                                   _().filter{it.contains("'")}
                                   .sideEffect{context = "SINGLE_QUOTES"}
                                    ,
                                   _().filter{it.contains('"')}
                                   .sideEffect{context = "DOUBLE_QUOTES"}
                                   ,
                                   _().filter{!it.contains("'") && !it.contains("'") }
                                   .sideEffect{context = "NO_QUOTES"}
                                  )
                              .transform {context}     
                              }

           
           //.transform{context}
           .as('removingDuplicateVars')
           .out.code
           //.except(edgeVar)
           .back('removingDuplicateVars')
           .ifThenElse{it.parents().next().type == "AST_DIM"}
           {varsInSink = ('$'.concat(it.parents().ithChildren(0).out.next().code).concat('[').concat(it.parents().ithChildren(1).astNodes().filter{it.type== "string"}.next().code).concat(']'))}
           {varsInSink = ('$'.concat(it.out('PARENT_OF').next().code))}

          //.transform{varsInSink}
          .transform{tacFormula2(varsInSink, '', 'sinkVars', context.next(), 0)}
          

       """   

    # query that searches the graph based on the info extracted from CVE reports
    # e.g.: the category parameter in add.php, (2) the cat_desc parameter in addcat.php, (3) the level and user parameters in adduser.php, (4) the post_id parameter in del.php, (5) the cat_id parameter in delcat.php, (6) the comment_id parameter in delcomment.php, (7) the id parameter in deluser.php, (8) the post_id and category parameter in edit.php, (9) the cat_id and cat_desc parameters in editcat.php, and (10) the id, level, and user parameters in edituser.php        
          
query= """ g.V().filter {it.code == "category"}  //MAY: vulnerable variables
           .sideEffect{vuln_variable_name = it.code}
           .parents()
           .filter {it.type == "AST_DIM"}
           .as('variables')
           .toFileAbs()
           .filter {it.name.contains("/add.php")} // MUST: File name 
           .sideEffect{fileName = it.name}
           .back('variables')
           .sideEffect{vuln_variable_id = it.id}
           
           //.transform{vuln_variable_name}
           .statements()
           .as('stmt')
           .out()

           .loop('stmt'){it.object.out(DATA_FLOW_EDGE).id.toList().size() == 0}
           .dedup()
           .as('pathToSinks')

        """

    # query that searches the graph based on the info extracted from CVE reports
    # e.g.: the category parameter in add.php, (2) the cat_desc parameter in addcat.php, (3) the level and user parameters in adduser.php, (4) the post_id parameter in del.php, (5) the cat_id parameter in delcat.php, (6) the comment_id parameter in delcomment.php, (7) the id parameter in deluser.php, (8) the post_id and category parameter in edit.php, (9) the cat_id and cat_desc parameters in editcat.php, and (10) the id, level, and user parameters in edituser.php        
          
query= """ vuln_variable_list = [];  g.V().filter {it.code == "category"}  //MAY: vulnerable variables
           .sideEffect{vuln_variable_name = it.code}
           .parents()
           .filter {it.type == "AST_DIM"}
           .as('variables')
           .toFileAbs()
           .filter {it.name.contains("/add.php")} // MUST: File name 
           .sideEffect{fileName = it.name}
           .back('variables')
           .sideEffect{vuln_variable_list = it.ithChildren(1).code.toList()}
           
           //.transform{vuln_variable_list}
           .statements()
           .sideEffect{varnames = getUsedVariablesNew(it)}
           .out()  // special case: there has to be two out becuase AST_IF is of "statements" type 
           .out()
           .sideEffect{varnames = getUsedVariablesNew(it)}
           .as('stmt')
          
           .outE(DATA_FLOW_EDGE).filter{it.var in varnames}.inV()
          //.transform{it.var}
           .astNodes()
           
          .loop('stmt'){it.object.type != TYPE_CALL  && it.object.type != TYPE_METHOD_CALL && it.object.type != TYPE_STATIC_CALL}
          .dedup()
          //.out(CALLS_EDGE)
          //.dedup()
          //.path{it.id}{it.lineno}{it.type}
          // .as('pathToSinks')
           //.out(DATA_FLOW_EDGE)
           //.loop('pathToSinks'){it.object. != "mysql_query"}
           //ithChildren(0).out().code
        """

       
"""
filter{"add.php" == (it.name) && it.type== "File"}
           .as('children')
           .out()
           .loop('children'){it.object.code != "category"}
           .filter{it.in().type == "AST_VAR"}

"""
"""//.sideEffect{nodeBeforeVar = it.parents().ithchildren(varNodeChildNum-1).astNodes()
                              .filter{it.type == "string"}
                              .or(
                                   _().filter{it.code.contains("'")}
                                   .transform{context = "SINGLE_QUOTES"}
                                    ,
                                   _().filter{it.code.contains('"')}
                                   .transform{context = "DOUBLE_QUOTES"}
                                   ,
                                   _().filter{!it.contains("'") && !it.code.contains("'") }
                                   .transform{context = "NO_QUOTES"}
                                  ) }"""

#query =  file("/home/abeer/python-joern-0.3.1/joern/phpjoernsteps/chainsawsteps/test.groovy").read() + "\n"

"""     //.id.order    
                  //.loop('root'){it.object.type != "AST_STMT_LIST" && it.loops < 5 }
                 .filter{it.code != null}
             //.path(){it.code}
                  //.loop('root'){it.object.type != "AST_STMT_LIST" }
                  .filter{it.code != null}
           //.path(){it.code}"""
start = time.time()
res = None

try:
	res =  j.runGremlinQuery(query)
  #res = query
  #print (res)

except Exception as err:
            print "Caught exception:", type(err), err
        


i =0 # index starts form 1
for node in res:
   		 print (node)
   		


CHUNK_SIZE = 256
#for chunk in j.chunks(res, CHUNK_SIZE):

   
 #  query = """ idListToNodes(%s)""" % (chunk)
  # print (query)
  
   #for r in j.runGremlinQuery(query):
   	   #print (r)
    #   query = """init(%s)""" % (r)
     #  print (query)
   
       #for m in j.runGremlinQuery(query):
        #   print(m)

#for node in res:
 #    query = """ init(%s) """ % (node[i])
  #   print (query)
   #  i= i+1
    # for r in j.runGremlinQuery(query):
     #     print(r)

 		 
elapsed = time.time() - start

print "Query done in %f seconds." % (elapsed)

