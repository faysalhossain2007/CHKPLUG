from old.dynamicAnalysis import DynamicAnalysis
import sys

"""
  Author: Abeer Alhuzali
"""

def main(argv):
    #TraceMap_def = "TraceMap = ["+ newMap+"]\n"
    #print(TraceMap_def)
    appName = argv[1].strip()
    fileName = argv[2].strip()
    attackType = argv[3].strip()
    vulnVar = argv[4].strip()

    sa =DynamicAnalysis(7474)
    query = sa.prepareParamtrizedQuery(appName, fileName, attackType, vulnVar)
    print('the query is ')
    print(query)
    result, elapsed_time =sa.runTimedQuery(query)
    print (result)
    print (elapsed_time)
    #writeToFile(result, elapsed_time, attackType)

    

    #result, elapsed_time =sa.runTimedQuery("g.V().includeMap()")
    #writeIncludeMapToFile(result, elapsed_time)


     


if __name__ == '__main__':
    main(sys.argv)


	