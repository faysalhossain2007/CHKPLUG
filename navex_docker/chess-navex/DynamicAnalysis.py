'''
@Author: Abeer Alhuzali
'''

from joern.all import JoernSteps
import time
from ExploitSeed import ExploitSeed
#from configurator import Configurator

class DynamicAnalysis(object):
    '''
    classdocs
    '''
    UNTRUSTED_DATA = """attacker_sources = [
                "_GET", "_POST", "_COOKIE",
                "_REQUEST", "_ENV", "HTTP_ENV_VARS"
                ]\n"""
    
    SQL_FUNCS = """sql_funcs = [
                "mysql_query", "mysqli_query", "pg_query", "sqlite_query"
                ]\n"""



    XSS_FUNCS = """xss_funcs = [
                "print", "echo"
                ]\n"""

    OS_COMMAND_FUNCS = """os_command_funcs = [
               "backticks", "exec" , "expect_popen","passthru","pcntl_exec",
               "popen","proc_open","shell_exec","system", "mail"     
               ]\n"""
    
    # Gremlin operations
    ORDER_LN = ".order{it.a.lineno <=> it.b.lineno}" # Order by linenumber
    
    def __init__(self, port):
        '''
        Constructor
        '''
        self.j = JoernSteps()
        self.j.setGraphDbURL('http://localhost:%d/db/data/' % (int(port)))
#         self.j.addStepsDir(
#                         Configurator.getPath(Configurator.KEY_PYTHON_JOERN) + 
#                         "/joern/phpjoernsteps"
#                         )
        
        #self.j.addStepsDir(Configurator.getPath(Configurator.KEY_BASE_DIR) +"/phpjoernsteps"  )
        self.j.connectToDatabase()
        
#         self.QUERIES_DIR = Configurator.getPath(Configurator.BASE_DIR) + \
#                         "/gremlin_queries" 


    def reSendCustomSteps(self):
        self.j.initCommandSent = False
        
    def searchCCOne(self):
       
        query = "g.V"

        return query
    
    def prepareQuery(self, TraceMap):
        query = self.UNTRUSTED_DATA + self.SQL_FUNCS + TraceMap
        
        query += open("failur.groovy", 'r').read()
    
        return query


    def prepareQueryStatic(self, attackType):
        query = self.XSS_FUNCS + self.SQL_FUNCS + self.OS_COMMAND_FUNCS
        #query += "m =[]; "
        #query += open("static-helper.groovy", 'r').read()
      

   
        query += "  m =[]; "
        if attackType == "sql":
    
            query += """ queryMapList =[]; g.V().filter{sql_funcs.contains(it.code)  && isCallExpression(it.nameToCall().next()) }.callexpressions()
                           // .ithChildren(1).astNodes().filter{it.type == "string"}.toList()
                            .sideEffect{m = getDDGpaths(it, [], 0, 'sql', false, queryMapList, true)}
                            .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'sql', '1')}
                            .sideEffect{ reportmessage = report(it.toFileAbs().next().name, it.lineno, it.id)}
                            //.ifThenElse{m.isEmpty()}
                              //{it.transform{reportmessage}}
                              //{it.transform{findSinkLocation(m, warnmessage, 'sql', queryMapList, it)}}
                              //{it.transform{findSinkLocation2(m, warnmessage,  queryMapList, it)}}

                            .transform{m} 
                           
        
                      """
        elif attackType == "xss":
            query += """ queryMapList = []; g.V().filter{it.type == TYPE_ECHO || it.type == TYPE_PRINT}
                
                            .sideEffect{m = getDDGpaths(it, [], 0, 'xss', false, queryMapList, true)}
                            .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'xss', '1')}
                            .sideEffect{ reportmessage = report(it.toFileAbs().next().name, it.lineno, it.id)}
                            //.ifThenElse{m.isEmpty()}
                              //{it.transform{reportmessage}}
                              //{it.transform{convertToTAC(m, warnmessage, 'xss', queryMapList, it)}}
			    .transform{m}
        
        """

        elif attackType == "code":
            query += """queryMapList =[]; g.V().filter{it.type == TYPE_INCLUDE_OR_EVAL && it.flags.contains(FLAG_EXEC_EVAL) }
                
                            .sideEffect{m = init(it, [], 0, 'code', false, queryMapList )}
                            .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'code', '1')}
                            .sideEffect{ reportmessage = report(it.toFileAbs().next().name, it.lineno, it.id)}
                            .ifThenElse{m.isEmpty()}
                              {it.transform{reportmessage}}
                              {it.transform{findSinkLocation(m, warnmessage, 'code', queryMapList, it)}}
        
        """
        # command execution : sinks considered are :
        #[backticks, exec,expect_popen,passthru,pcntl_exec,popen,proc_open,shell_exec,system,mail]     
        elif attackType == "os-command":
            query += """queryMapList =[] g.V().filter{os_command_funcs.contains(it.code)  && isCallExpression(it.nameToCall().next()) }.callexpressions()
                            .filter{os_command_funcs.contains(it.ithChildren(0).out.code.next())}
                
                            .sideEffect{m = init(it, [], 0, 'os-command', false, queryMapList )}
                            .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'os-command', '1')}
                            .sideEffect{ reportmessage = report(it.toFileAbs().next().name, it.lineno, it.id)}
                            .ifThenElse{m.isEmpty()}
                              {it.transform{reportmessage}}
                              {it.transform{findSinkLocation(m, warnmessage, 'os-command', queryMapList, it)}}
        
        """

        elif attackType == "file-inc":
            query += """queryMapList =[]; g.V().filter{it.type == TYPE_INCLUDE_OR_EVAL && !(it.flags.contains(FLAG_EXEC_EVAL)) }
                
                            .sideEffect{m = init(it, [], 0, 'file-inc', false, queryMapList)}
                            .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'file-inc', '1')}
                            .sideEffect{ reportmessage = report(it.toFileAbs().next().name, it.lineno, it.id)}
                            .ifThenElse{m.isEmpty()}
                              {it.transform{reportmessage}}
                              {it.transform{findSinkLocation(m, warnmessage, 'file-inc', queryMapList, it)}}
        
        """
        elif attackType =="ear":
            query+=""" g.V().filter{ "header" == it.code  && isCallExpression(it.nameToCall().next()) }.callexpressions()
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
                    
                    , _().as('b')
                 .filter{it.type == "AST_CALL"}
                        
                        .astNodes()
                        .filter{it.code != null &&
                                 it.code != "/home/user/log/codeCoverage.txt"}
                         .back('b')
                    )
                 .back('call')
                 .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'ear', '1')}
                 .transform{warnmessage}

        """
        """
        .sideEffect{m = init(it, [], 0, 'xss')}
                            .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'xss', '1')}
                            .sideEffect{ reportmessage = report(it.toFileAbs().next().name, it.lineno, it.id)}
                            .ifThenElse{m.isEmpty()}
                              {it.transform{reportmessage}}
                              {findSinkLocation(m, warnmessage, 'xss')}
        """

        #query += open("static-test.groovy", 'r').read()

        #ids = self.j.runGremlinQuery(query)
        #print (res)

       
    
        return query

    # def prepareParamtrizedQuery (self, appName, fileName, attackType, vulVar ):
    
    #     query = self.XSS_FUNCS + self.SQL_FUNCS + self.OS_COMMAND_FUNCS+"fileName='"+ str(fileName)+"';\n"+"appName='"+ str(appName)+"';\n" +"vulVar='"+ str(vulVar)+"';\n"+"attackType='"+ str(attackType)+"';\n"
        
    #     query += """ m=[]; queryMapList=[]; g.V().filter{sql_funcs.contains(it.code)  && isCallExpression(it.nameToCall().next()) }.callexpressions()
    #                         //to filter out only sinks in a particular appName 
    #                         .as('app')
    #                         .toFileAbs()
    #                         .filter {it.name.contains(appName)} // MUST: App Name
    #                         .back('app') 
    #                          //end
    #                        // .ithChildren(1).astNodes().filter{it.type == "string"}.toList()
    #                         .sideEffect{m = startSearch(it,attackType, fileName, vulVar)}
    #                         .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'sql', '1')}
    #                         //.sideEffect{ reportmessage = report(it.toFileAbs().next().name, it.lineno, it.id)}
    #                         //.ifThenElse{m.isEmpty()}
    #                           //{it.transform{"Not Found"}}//{it.transform{reportmessage}}
    #                          // {it.transform{findSinkLocation2(m, warnmessage,queryMapList, it)}}
    #                          .transform{m} 
                           
                           
        
    #                   """
    #     return query 

    def prepareParamtrizedQuery (self, appName, fileName, attackType, vulVar ):
    
        query = self.XSS_FUNCS + self.SQL_FUNCS + self.OS_COMMAND_FUNCS+"fileName='"+ str(fileName)+"';\n"+"appName='"+ str(appName)+"';\n" +"vulVar='"+ str(vulVar)+"';\n"+"attackType='"+ str(attackType)+"';\n"
        
        query += """ m=[]; queryMapList=[]; g.V().filter{"""+attackType+"""_funcs.contains(it.code)  && isCallExpression(it.nameToCall().next()) }.callexpressions()
                            //to filter out only sinks in a particular appName 
                            .as('app')
                            .toFileAbs()
                            .filter {it.name.contains(appName)} // MUST: App Name
                            .back('app') 
                             //end
                            .sideEffect{m = (startSearch(it, '"""+attackType+"""', fileName, vulVar))}
                            .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, '"""+attackType+"""', '1')}
                            .ifThenElse{m == []}
                              {it.transform{"Not Found"}}//{it.transform{reportmessage}}
                              //{it.transform{warnmessage}}
                              //{it.transform{findSinkLocation2(m, warnmessage,queryMapList, it)}}
                              //{it.transform{findSinkLocation3(m, warnmessage, '"""+attackType+"""', queryMapList, it)}}
                              {it.transform{m}}
                            //.transform{m} 
                            //.transform{findSinkLocation3(m, warnmessage, '"""+attackType+"""', queryMapList, it)}
                            //.transform{findSinkLocation2(m, warnmessage, queryMapList, it)}
                           
        
                      """
        return query 


    def prepareFinalQuery(self, seed):
        get = []
        for g in seed.get:
            if '=' in g:
                t= g[0:g.find('=')]
                get.append('?'+t+'=')
                get.append('&'+t+'=')

        params = []
        for p in seed.params:
            if '=' in p:
                params.append(p[0:p.find('=')]+'=')        

        query = """g.V('url', '%s')
                .findNavigationSeq(%s, %s, %s).dedup().path""" % (seed.src, seed.dst, get, params)
        print (query)
        #{it.url}
    
        return query    
    
    def runQuery(self, query):
        return query
    
    def runTimedQuery(self, query, retryOnError = False):
        start = time.time()

        res = None
        try:
            if query:
               res = self.j.runGremlinQuery(query)

        except Exception as err:
            if retryOnError:
                self.reSendCustomSteps()
                return self.runTimedQuery(query)
            else:
                print("Caught exception:", type(err), err)

        
        elapsed = time.time() - start

        timestr= "Query done in %f seconds." % (elapsed)

        return (res,timestr) 


    def runChunkedQuery(self, query):
        
        start = time.time()
        #print('the query inside run timed query \n')
        #print(query)
        res = []
        try:
            if query:
               CHUNK_SIZE = 100
               for chunk in self.j.chunks(query, CHUNK_SIZE):
                    q = self.XSS_FUNCS + self.SQL_FUNCS
                    q += "  m =[]; "
                    q += """idListToNodes(%s)
                            .sideEffect{m = init(it, [], 0)}
                            .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'sql', '1')}
                            .sideEffect{ reportmessage = report(it.toFileAbs().next().name, it.lineno, it.id)}
                            .ifThenElse{m.isEmpty()}
                              {it.transform{reportmessage}}
                              {findSinkLocation(m, warnmessage)}
                              
                       """ % (chunk)
                          
                          
                            
                          
                    """.ifThenElse{m.isEmpty()}
                              {it.transform{reportmessage}}
                              {findSinkLocation(m, warnmessage)}"""

                    print (q)
                    for r in self.j.runGremlinQuery(q):
                         #print(r)
                         res.append(r)

        except Exception as err:
            print("Caught exception:", type(err), err)
        
        elapsed = time.time() - start

        timestr= "Query done in %f seconds." % (elapsed)

        
        print(timestr)
        #result = []
        #for node in res:
       # print (res)

        return (res,timestr)

    def readExploitSeedsFile(self, attackType): 
        if attackType == "sql":
          print ('Reading Exploit Seeds File in /home/user/navex/results/include_map_resolution_results_sql.txt')
          file= '/home/user/navex/results/include_map_resolution_results_sql.txt'
        elif attackType == "xss":    
          file='/home/user/navex/results/include_map_resolution_results_xss.txt'
          print ('Reading Exploit Seeds File in /home/user/navex/results/include_map_resolution_results_xss.txt')
        elif attackType == "code":    
          file='/home/user/navex/results/include_map_resolution_results_code.txt'
          print ('Reading Exploit Seeds File in /home/user/navex/results/include_map_resolution_results_code.txt')
        elif attackType == "os-command":    
          file='/home/user/navex/results/include_map_resolution_results_os-command.txt'
          print ('Reading Exploit Seeds File in /home/user/navex/results/include_map_resolution_results_os-command.txt')
        elif attackType == "file-inc":    
          file='/home/user/navex/results/include_map_resolution_results_file-inc.txt'
          print ('Reading Exploit Seeds File in /home/user/navex/results/include_map_resolution_results_file-inc.txt')
        elif attackType == "ear":    
          file='/home/user/navex/results/include_map_resolution_results_ear.txt'
          print ('Reading Exploit Seeds File in /home/user/navex/results/include_map_resolution_results_ear.txt')
        
        with open(file, 'r') as f:
             lines = [line.strip() for line in f]
            
        return  lines

    
#old forward search
    """m=[]; g.V().filter {it.code == "category"}  //MAY: vulnerable variables
           .sideEffect{vuln_variable_name = it.code}
           .parents()
           .filter {it.type == "AST_DIM"}
           .as('variables')
           .toFileAbs()
           .filter {it.name.contains("/add.php")} // MUST: File name 
           .sideEffect{fileName = it.name}
           .back('variables')
           .statements()
           .sideEffect{m = startSearch(it, 'sql')}
                            .sideEffect{ warnmessage = warning(it.toFileAbs().next().name, it.lineno, it.id, 'sql', '1')}
                            .sideEffect{ reportmessage = report(it.toFileAbs().next().name, it.lineno, it.id)}
                            //.ifThenElse{m.isEmpty()}
                              //{it.transform{reportmessage}}
                              //{it.transform{findSinkLocation(m, warnmessage, 'code', queryMapList, it)}}
                            .transform{m}
         """
