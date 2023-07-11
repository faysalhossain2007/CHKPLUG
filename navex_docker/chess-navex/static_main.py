from DynamicAnalysis import DynamicAnalysis

import sys
from EnhancedAnalysis import VulnerablePath
from integration.MsgDispatcher import MsgDispatcher
import os


def startUserInteraction(vPath):
    msgDispatcher  = MsgDispatcher()
    for f in  vPath.z3Utils.functionsWithNoModel:
        response = msgDispatcher.main_message(f)
        vPath.addInputFromUser(response)
        solution = vPath.solve(vPath.pathInTAC)
        print(solution)


#argv[1] can be xss or sql
#argv[2] can be ddg or cfg
#argv[3] is the directory where the php  code is. It must be the same as the one in the Neo4j database.
def main(argv):

    attackType = argv[1].strip()
    pathType = argv[2].strip()
    codeDirectory = argv[3].strip()

    sa = DynamicAnalysis(7474)
    VulnerablePath.graphHandle = sa
    VulnerablePath.attackType = attackType

    #broker = MessageManager("192.168.56.101", "searchToTAC")
    #this query explores only the data dependency graphs
    if pathType == "ddg":
        result, elapsed_time = sa.runTimedQuery(prepareDDGAnalysisQuery(attackType), True)
        for r in result:
            if r and isinstance(r, list):
                for l in r: #each l is a path
                    #printPath(l)
                    vPath = VulnerablePath(l);
                    solution = vPath.solve(vPath.pathInTAC)
                    if solution != "":
                        print(vPath.TACHeader)
                        print(solution)
                    else:
                        print(vPath.TACHeader)
                        print("No Solution")
                        result = startUserInteraction(vPath)



    elif pathType == "cfg": #path explosion problem with cfg
        final_score = []
        for file in os.listdir(codeDirectory):
            if file[-4:] == '.php':
                print(file)
                #get number of loops,  number of conditional statements, number of function calls, number of includes for every file
                #1st and 2nd arguments are the start and end line for which we are computing the cyclomatic scores
                #3rd arg is the file
                loop_num, if_num, call_num, require_num = count_complex_constructs(0, 1000000, file, sa.j)
                cyclomaticScore = computeCyclomaticScore(len(loop_num), len(if_num), len(call_num), len(require_num))
                final_score.append((file, cyclomaticScore))
        final_score.sort(key=takeSecond, reverse=False)
        print(final_score)
        for file in final_score:
            CFGpaths = getCFGPaths(file[0], 0, 1000000, sa.j) #queries can be very expensive over the whole application. Localized queries needed.
            # print(CFGpaths[0])
            testpath = VulnerablePath(CFGpaths[0])
            # for path in testpath.pathInTAC:
            #    print(path)
            result = testpath.solve(testpath.pathInTAC)
            print(result)
        else:
            print("invalid argument")
    return

def getNode(nodeID, j):
    query =  "g.V().filter{it.id == " + str(nodeID)+"}.transform{it}"
    node = j.runGremlinQuery(query);
    return node


#returns the range of node ids in the CPG that belong to the file 'filename'
def getIDRange(filename,j):
    #query to find id range of the input file
    query = "g.V().filter{it.type == 'File' && it.name =='"+filename+"'}.transform{it.id}"
    startid = j.runGremlinQuery(query)[0]
    query = "g.V().filter{it.type == 'File'}.transform{it.id}"
    fileids = j.runGremlinQuery(query)
    endid = startid
    for x in fileids:
        if x>startid:
            endid = x
            break
    if startid == endid:
        endid+=100000
    return startid, endid


def count_complex_constructs(startline, endline, filename, j):
    startid, endid = getIDRange(filename, j)
    #query to find loops
    query = "g.V().filter{ it.id>="+str(startid)+"&&it.id<"+str(endid)+"&&it.lineno >="+str(startline)+" && it.out('FLOWS_TO').count()>0}"
    query +=".sideEffect{m = getLoops(it, "+str(endline)+", 'sql')}.transform{m.id}"
    #query = "g.V().filter{it.lineno == 4}"
    #find number of loops
    res =  j.runGremlinQuery(query)
    print(len(res))
    #query to find num of if statement
    query = "g.sideEffect{m = getIfStatement(it,"+str(startid)+","+str(endid)+","+str(startline)+","+str(endline)+")}.transform{m.id}"
    if_num = j.runGremlinQuery(query)[0]
    #query to find num of calls wo do not have code
    query = "g.sideEffect{m = getCallWithoutCode(it,"+str(startid)+","+str(endid)+","+str(startline)+","+str(endline)+")}.transform{m.id}"
    call_num = j.runGremlinQuery(query)[0]
    """for call_id in call_num:
        node = getNode(call_id, j)
        print(node)"""
    #query to find require num
    query = "g.sideEffect{m = getRequireNode(it,"+str(startid)+","+str(endid)+","+str(startline)+","+str(endline)+")}.transform{m.id}"
    require_num = j.runGremlinQuery(query)[0]
    result = []
    for j in range(len(res)):
        r = res[j]
        print(r)
        if r!=[]:
            if result == []:
                result.append(r[0])
            for k in range(len(r)):
                if_insert = True
                for i in range(len(result)):
                    if set(r[k])<set(result[i]):
                        if not str(r[k])[1:-1] in str(result[i]):
                            if_insert = False
                            break
                    elif set(r[k])==set(result[i]):
                        if_insert = False
                        break
                    elif set(result[i])<set(r[k]):
                        result[i] = []
                if if_insert:
                    result.append(r[k])
    result = [value for value in result if value!=[]]
    return result,if_num,call_num,require_num

def dedupPath(CFGPaths):
    final_path = []
    for paths in CFGPaths:
        for path in paths:
            if_insert = True
            for exist_path in final_path:
                if str(path)[1:-1] in str(exist_path):
                     if_insert = False
                     break
            if if_insert:
                final_path.append(path)
    return final_path

def getCFGPaths(startline, endline, filename, j):
    startid, endid = getIDRange(filename, j)
    query = "g.V().filter{it.id>="+str(startid)+"&&it.id<"+str(endid)+"&&it.lineno >="+str(startline)+" && it.out('FLOWS_TO').count()>0}.sideEffect{m = getCFGpaths(it, "+str(endline)+", 'sql')}.transform{m}"
    #query = "g.V().filter{it.lineno == 4}"
    CFGpaths =  dedupPath(j.runGremlinQuery(query))
    return CFGpaths

#l:number of loops, i: number of if statements, c: number of function calls with no code, r: number of php file inclusions (require,  include)
def computeCyclomaticScore(l,i,c,r):
    w_l = 4
    w_i = 2
    w_c = 20
    w_r = 40
    return l*w_l + i*w_i + c*w_c + r*w_r

def takeSecond(elem):
    return elem[1]


def printPath(path):
    for n in path:
        print(n)

def printVulnerablePath(vulnerablePath):
    vpTAC = vulnerablePath.pathInTAC
    for n in vpTAC:
        print(n)

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


def prepareCFGQuery(attackType):
    if attackType == 'sql':
        query = """
            g.V().filter{it.lineno ==24 && it.out('FLOWS_TO').count()>0}
            .sideEffect{m = getCFGpaths(it, 24, 'sql')}
            .transform{m.id}
            """
    elif attackType == 'xss':
        query = """
            g.V().filter{it.lineno ==24 && it.out('FLOWS_TO').count()>0}
                .sideEffect{m = getCFGpaths(it, 24, 'xss')}
                .transform{m.id}
                """

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



