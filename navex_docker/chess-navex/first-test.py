from DynamicAnalysis import DynamicAnalysis
from EnhancedAnalysis import VulnerablePath
from joern.all import JoernSteps
import sys
import os

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

def evaluate_code(startline, endline, filename, j):
    startid, endid = getIDRange(filename, j)
    #query to find loops
    query = "g.V().filter{ it.id>="+str(startid)+"&&it.id<"+str(endid)+"&&it.lineno >="+str(startline)+" && it.out('FLOWS_TO').count()>0}"
    query +=".sideEffect{m = getLoops(it, "+str(endline)+", 'sql')}.transform{m.id}"
    #query = "g.V().filter{it.lineno == 4}"
    res =  j.runGremlinQuery(query)
    #query to find num of if statement
    query = "g.sideEffect{m = getIfStatement(it,"+str(startid)+","+str(endid)+","+str(startline)+","+str(endline)+")}.transform{m.id}"
    if_num = j.runGremlinQuery(query)[0]
    #query to find num of calls wo do not have code
    query = "g.sideEffect{m = getCallWithoutCode(it,"+str(startid)+","+str(endid)+","+str(startline)+","+str(endline)+")}.transform{m.id}"
    call_num = j.runGremlinQuery(query)[0]
    #query to find require num
    query = "g.sideEffect{m = getRequireNode(it,"+str(startid)+","+str(endid)+","+str(startline)+","+str(endline)+")}.transform{m.id}"
    require_num = j.runGremlinQuery(query)[0]
    result = []
    for j in range(len(res)):
        r = res[j]
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

def formula(l,i,c,r):
    w_l = 4
    w_i = 2
    w_c = 20
    w_r = 40
    return l*w_l + i*w_i + c*w_c + r*w_r

def takeSecond(elem):
    return elem[1]

#Prepare database connection
j = JoernSteps()
j.setGraphDbURL('http://localhost:7474/db/data/')
j.connectToDatabase()

sa = DynamicAnalysis(7474)
VulnerablePath.graphHandle = sa
VulnerablePath.attackType = 'sql'

"""
CFGpaths = getCFGPaths(sys.argv[2],sys.argv[3],sys.argv[1],j)
#print(CFGpaths[0])
testpath = VulnerablePath(CFGpaths[0])
for path in testpath.pathInTAC:
    print(path)
result = testpath.solvePartialTAC(testpath.pathInTAC)
print(result)
#vp = VulnerablePath(l) convert to 3 address path
#printVulnerablePathInTAC(vp) just print
#vp.solve(vp.pathInTAC) convert to z3 and solve it
#print(CFGpaths)
#print(len(CFGpaths))
"""
#rank the file according to formula
final_score = []
for file in os.listdir(sys.argv[1]):
    if file[-4:] == '.php':
        print(file)
        loop_num,if_num,call_num,require_num = evaluate_code(0,1000000,file,j)
        score = formula(len(loop_num),len(if_num),len(call_num),len(require_num))
        final_score.append((file,score))
final_score.sort(key=takeSecond,reverse=False)
print(final_score)

for file in final_score:
    CFGpaths = getCFGPaths(0,1000000,file[0], j)
    #print(CFGpaths[0])
    testpath = VulnerablePath(CFGpaths[0])
    #for path in testpath.pathInTAC:
    #    print(path)
    result = testpath.solvePartialTAC(testpath.pathInTAC)
    print(result)

"""
result,if_num,call_num,require_num = evaluate_code(0,1000000,'AddTerm.php')
print("The number of loops: " + str(len(result)))
print(result)
print("The num of IF statement: " + str(len(if_num)))
print(if_num)
print("The num of calls without source code: "+str(len(call_num)))
print(call_num)
print("The num of required files: " + str(len(require_num)))
print(require_num)

"""