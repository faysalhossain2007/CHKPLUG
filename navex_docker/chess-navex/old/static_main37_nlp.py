from DynamicAnalysis import DynamicAnalysis
from messageManager import MessageManager
from StaticResults import staticResults
import time
import sys
from EnhancedAnalysis import VulnerablePath
from collections import deque
import json

#argv[1] can be xss sql
#argv[2] is an integer greater or equal to 0. It controls the level of recursion when building control flow paths from data flow paths.
def main(argv):

    appName = argv[1].strip()
    fileName = argv[2].strip()
    attackType = argv[3].strip()
    vulVar = arvg[4].strip
    deepeningParam = int(argv[5].strip())

    sa = DynamicAnalysis(7474)
    VulnerablePath.graphHandle = sa
    VulnerablePath.attackType = attackType

    #broker = MessageManager("192.168.56.101", "searchToTAC")

    #result, elapsed_time = sa.runTimedQuery(prepareDDGAnalysisQuery(attackType), True)

    result, elapsed_time = sa.runTimedQuery(sa.prepareParamtrizedQuery(appName,fileName,attackType,vulVar))

    ddgPaths = []
    conditions = deque()
    nextDepthConds = deque()
    for r in result:
        if r and isinstance(r, list):
            for l in r:
                ddgPaths.append(VulnerablePath(l))
                if ddgPaths[-1].analyzeFunctionCalls():
                    nextDepthConds.extend(ddgPaths[-1].openDeps)
                else:
                    return
                    #ddgPaths.pop()
                    #solution found

                    


   #  #for p in ddgPaths:
        # print p.cost
        # print "\n------------------\n"
        # print p.conditions
        # print "\n------------------\n"
        # print json.dumps(p.pathInTAC)
        # print "\n\n"
    # return
    # for p in ddgPaths:
    #     for q in p.getPaths({}):
    #         msg = {}
    #         msg["header"] = p.TACHeader
    #         msg["tac"] = q
    #         broker.sendMessage(json.dumps(msg))
    #
    # broker.closeConnection()


#    for p in ddgPaths:
#	print "SINK " + str(p.path[0]["id"])
#	print "Tot paths: " + str(len(p.getPaths({})))
#	print "Conditions: " + str(p.conditions)
#	print "###########################\n"
#
 #   return


#    for p in ddgPaths:
#	for q in p.getPaths({}):
#		print "\n------------------\n"
#		print json.dumps(p.TACHeader)
#		print json.dumps(q)
#		print "\n\n" 
#	print "###########################\n"

#    for p in ddgPaths:
#	print p.cost
#	print "\n------------------\n"
#	print p.conditions
#	print "\n------------------\n"
#	print json.dumps(p.pathInTAC)
#	print "\n\n"

 #   print "CONDITION CACHE"
#    for (k, l) in VulnerablePath.conditionsCache.iteritems():
#	print "------------------------\n"
#	print k
#	print "\n------------------------\n"
#	for p in l:
#		print p.cost
#		print "\n------------------\n"
#		print p.conditions
#		print "\n------------------\n"
#		print p.pathInTAC
#		print "\n\n"
#	print "\n"


    return


def prepareDDGAnalysisQuery(attackType):

    if attackType == 'xss':
        query = """
            g.V().filter{it.type == TYPE_ECHO || it.type == TYPE_PRINT}
            .sideEffect{m = getDDGpaths(it, [], 0, 'xss', false, [], true)}
            .transform{m}
            """
        #
    elif attackType == 'sql':
        query = """
            def sql_funcs = ["mysql_query", "mysqli_query", "pg_query", "sqlite_query"];

            g.V().filter{it.code in sql_funcs  && isCallExpression(it.nameToCall().next())}.callexpressions()
            .sideEffect{m = getDDGpaths(it, [], 0, 'sql', false, [], true)}
            .transform{m}
            """

    return query


def prepareDDgAnalysisForNodeQuery(nodeID, attackType):
    query = """
        g.v(""" + str(nodeID) + """)
        .sideEffect{m = getDDGpaths(it, [], 0, '""" + attackType + """', false, [], false)}
        .transform{m}
        """

    return query


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

if __name__ == '__main__':
    main(sys.argv)



