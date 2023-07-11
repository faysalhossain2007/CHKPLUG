from old.dynamicAnalysis import DynamicAnalysis
from readCodeCoverage import CodeCoverage
import sys


"""
  Author: Abeer Alhuzali
"""

def main(argv):
    cc = CodeCoverage()
    TraceMap = cc.readCodeCoverageFile()
	# we have to covert python dictionary to groovy map!!
    newMap= ''.join('\'{}\': {}, '.format(key, val) for key, val in TraceMap.items())
    k = newMap.rfind(",")
    newMap = newMap[:k] + "" + newMap[k+1:]

    TraceMap_def = "TraceMap = ["+ newMap+"]\n"
    #print(TraceMap_def)

    dm =DynamicAnalysis(7474)
    query = dm.prepareQuery(TraceMap_def)
    #print('the query is ')
    #print(query)
    result, elapsed_time =dm.runTimedQuery(query)
    writeToFile(result,elapsed_time)


def writeToFile(result, elapsed_time):
    f= open('/home/user/navex/formulaMapping.txt', 'w') 
    for node in result:
        print (node)
        print>>f, node 
    print>>f, elapsed_time 
    f.close() 


if __name__ == '__main__':
    main(sys.argv)


	
