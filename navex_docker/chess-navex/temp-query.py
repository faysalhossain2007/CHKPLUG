from old.dynamicAnalysis import DynamicAnalysis
import sys

"""
  Author: Abeer Alhuzali
"""

def main(argv):
    #TraceMap_def = "TraceMap = ["+ newMap+"]\n"
    #print(TraceMap_def)
    attackType = argv[1].strip()

    sa =DynamicAnalysis(7474)

    query = """
	g.v(""" + attackType + """).toFileAbs()
    """

    print('the query is ')
    print(query)
    result, elapsed_time =sa.runTimedQuery(query)
    
    i = 2

    if i == 1:
	for r in result:
		if r and isinstance(r, list):
			for l in r:
				print (l)
				print "\n"
			print "\n\n"
    else:
	print result
	print "\n\n\n"

	for r in result:
		print(r)
		print "\n\n"

    #writeToFile(result, elapsed_time, attackType)

    

    #result, elapsed_time =sa.runTimedQuery("g.V().includeMap()")
    #writeIncludeMapToFile(result, elapsed_time)


def writeToFile(result, elapsed_time, attackType):
    #print(attackType)
    if attackType == "sql":
       f= open('/home/user/navex/results/static_analysis_results_sql.txt', 'w') 
    elif attackType =="xss":
       f= open('/home/user/navex/results/static_analysis_results_xss.txt', 'w') 
    elif attackType =="code":
       f= open('/home/user/navex/results/static_analysis_results_code.txt', 'w') 
    elif attackType =="os-command":
       f= open('/home/user/navex/results/static_analysis_results_os-command.txt', 'w') 
    elif attackType =="file-inc":
       f= open('/home/user/navex/results/static_analysis_results_file-inc.txt', 'w') 
    elif attackType =="ear":
       f= open('/home/user/navex/results/static_analysis_results_ear.txt', 'w') 
    
    for node in result:
        print (node)
        print>>f, node 
    print>>f, elapsed_time    

    f.close() 

def writeIncludeMapToFile(result, elapsed_time):
    f= open('/home/user/navex/results/include_map_results.txt', 'w') 
    for node in result:
        print (node)
        print>>f, node 
    print>>f, elapsed_time    

    f.close()   

def calculateAnalysisCost(path, graphHandle):

	enclosingConditions = 0;

	for node in path:

		if getEnclosingTrueCond(node, graphHandle):
			enclosingConditions = enclosingConditions + 1;
		

	return enclosingConditions * 10 + len(path);


def getEnclosingTrueCond(node, graphHandle):

	query = """def childMap = ["AST_IF_ELEM" : 0, "AST_WHILE" : 0, "AST_FOR" : 1];
	""" + "g.v(" + str(node["id"]) + """)
	.statements()
	.parents()
	.filter{it.type == "AST_STMT_LIST"}
	.parents()
	.filter{it.type in childMap.keySet().collect()}
	.transform{it.ithChildren(childMap[it.type]).next()}.hasNext()
	"""

	res, time = graphHandle.runTimedQuery(query)

	return res


if __name__ == '__main__':
    main(sys.argv)


	
