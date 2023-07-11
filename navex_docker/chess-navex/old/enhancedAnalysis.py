import random
from userInterfaceManager import UItoTACConverter
from old import z3Converter
import re
import os





class VulnerablePath: #represents a single DDG path augmented with certain CFG subpaths

    graphHandle = None
    conditionsCache = {}
    idGenerator = 0
    attackType = ""
    
    
    def __init__(self, path):
        self.path = path
        self.foundCandidatePath = False
        self.pathInTAC = []
        self.TACHeader = None
        self.operandForTACAssertion = ""

        self.openDeps = []
        self.solvedDeps = []
        self.conditions = {}
        self.cost = 0
        self.badPath = False
        self.uid = VulnerablePath.idGenerator
        VulnerablePath.idGenerator += 1

        self.findConditions(self.path)
        self.calculateAnalysisCost()
        self.executeConversionToTAC()


    def analyzeFunctionCalls(self):

        length = len(self.pathInTAC)

        i = length - 1
        while i >= 0:
            n = self.pathInTAC[i]

            if n["formula"]["type"] == "AST_CALL" and not self.isModelAvailable(n["formula"]["op"]):
                info = self.extractInfoFromCallSite(n["formula"]["node_id"])
                if info is not None:  #for functions like sprintf info is none
                    if info["filename_callsite"] == "/var/www/html/oscommerce/catalog/admin/languages.php" and n["formula"]["op"] == "tep_draw_button":#and info["lineno_callsite"] == "185"
                        print info["filename_callsite"]
                        print info["lineno_callsite"]
                        print "     " + n["formula"]["op"]
                        print "PATH:"
                        print self.pathInTAC
                        self.foundCandidatePath = True
                    if "tracking" in n:
                        info["tracking"] = n["tracking"]
                else:
                    i=i-1
                    continue;
                if self.foundCandidatePath is True:
                    output = self.solve(self.pathInTAC);
                    self.foundCandidatePath = False
                # ui = UserInterface(info, VulnerablePath.attackType)
                #
                # response = ui.startConversation()
                #
                # if response == UserInterface.SOLVE:
                #     output = self.solvePartialTAC(self.pathInTAC[i:])
                #     input_val = ui.requestInput(output)
                #
                #     if input_val is None:
                #         return False
                #
                #     temp = self.pathInTAC[:i]
                #     temp.append(UItoTACConverter.generateFormula(self.pathInTAC[i]["formula"]["right"][len(self.pathInTAC[i]["formula"]["right"]) - self.pathInTAC[i]["tracking"][0]], "\"" + input_val + "\"", "AST_CONTAINS", "AST_CONTAINS", None, "string", "string"))
                #     self.pathInTAC = temp
                #
                # else:
                #     ui2tac = UItoTACConverter(n)
                #     tac = ui2tac.executeConversion(response)
                #
                #     if tac is not None:
                #         temp = self.pathInTAC[:i]
                #         temp.extend(tac)
                #         temp.extend(self.pathInTAC[i+1:])
                #         self.pathInTAC = temp
                #         i = i + 1
                #
                #     else:
                #         return False

            i = i - 1

        return True


    def extractInfoFromCallSite(self, node_id):
        query = "g.v(" + str(node_id) + """)
        .transform{extractInfoFromCallSite(it)}
        """

        res, time = VulnerablePath.graphHandle.runTimedQuery(query, True)
        if res is not None:
            ret = res[0]
        else:
            ret = None
        return ret

        
    def findConditions(self, path):
        tempConds = []

        for n in path:
            cond = self.getEnclosingTrueCond(n)
            if cond:
                if cond[0]["type"] == "NULL":
                    falseConds = self.getConditionsFromFalseBranch(cond[0])
                    for falseCond in falseConds:
                        if falseCond["id"] not in self.conditions:
                            self.conditions[falseCond["id"]] = 0
                            tempConds.append(falseCond)

                            if falseCond["id"] not in VulnerablePath.conditionsCache:
                                self.openDeps.append(falseCond)
                            else:
                                self.solvedDeps.append(falseCond)

                else:
                    if cond[0]["id"] not in self.conditions:
                        self.conditions[cond[0]["id"]] = 1
                        tempConds.append(cond[0])

                        if cond[0]["id"] not in VulnerablePath.conditionsCache:
                            self.openDeps.append(cond[0])
                        else:
                            self.solvedDeps.append(cond[0])

        if tempConds:
            self.findConditions(tempConds)



    def getEnclosingTrueCond(self, node):

        query = "g.v(" + str(node["id"]) + """)
        .transform{getEnclosingTrueCond(it)}
        """

        res, time = VulnerablePath.graphHandle.runTimedQuery(query, True)

        return res[0]


    def getConditionsFromFalseBranch(self, node):

        query = "g.v(" + str(node["id"]) + """)
        .transform{getConditionsFromFalseBranch(it).toList()}
        """

        res, time = VulnerablePath.graphHandle.runTimedQuery(query, True)

        return res[0]


    def calculateAnalysisCost(self):

        self.cost = len(self.conditions) * 10 + len(self.path)


    def executeConversionToTAC(self):

        query = "p = ["
        first = True
        for n in self.path:
            if first:
                first = False
            else:
                query = query + ", "

            query = query + str(n["id"])

        query = query + """]

        path = recoverNodes(p)

        return convertToTAC(path, '""" + VulnerablePath.attackType + "', " + str(self.uid) + ")"

        res, time = VulnerablePath.graphHandle.runTimedQuery(query, True)

        if res is not None:#sometimes the query above fails.
            self.operandForTACAssertion = res[0]
            self.pathInTAC = res[1]
            self.TACHeader = res[2]
        else:
            self.badPath=True


    def getPaths(self, visited):
        completePaths = []

        for (cond, val) in self.conditions.iteritems():
            if (cond in VulnerablePath.conditionsCache) and (cond not in visited):
                visited[cond] = 1
                for index in self.oracle(len(VulnerablePath.conditionsCache[cond])):
                    q = VulnerablePath.conditionsCache[cond][index]
                    for p in q.getPaths(visited):
                        tempCopy = self.pathInTAC[:]
                        if val == 1:
                            tempCopy.extend(p)
                            tempCopy.append(q.getConditionAssertionNode(True))
                            completePaths.append(tempCopy)
                        else:
                            tempCopy.extend(p)
                            tempCopy.append(q.getConditionAssertionNode(False))
                            completePaths.append(tempCopy)

                del visited[cond]


        if completePaths:
            return completePaths
        else:
            return [self.pathInTAC]


    def oracle(self, maxIndex):
        return range(maxIndex)
        if maxIndex == 0:
            return []
        elif maxIndex < 6:
            range(maxIndex)
        else:
            return random.sample(xrange(maxIndex), 5)

        return range(maxIndex)


    def getConditionAssertionNode(self, assertionType):
        result = {}
        result["formula"] = {}
        result["formula"]["left"] = self.operandForTACAssertion
        result["formula"]["right"] = assertionType
        result["formula"]["op"] = "AST_ASSIGN"
        result["formula"]["type"] = "AST_ASSIGN"
        result["formula"]["node_id"] = None

        result["types"] = {}
        result["types"]["left"] = "boolean"
        result["types"]["right"] = "boolean"
        return result


    def isModelAvailable(self, function):
        models = {
            "mysql_query" : True,
            "intval" : True,
            "empty" : True,
            "isset" : True,
            "echo" : True,
            "htmlspecialchars" : True,
            "htmlentities" : True,
            "trim" : True,
            "rtrim" : True,
            "ltrim" : True,
            "stripslashes" : True,
            "strip_tags" : True,
            "str_replace" : True
            }

        return (function in models)


    def solvePartialTAC(self, partialTAC):
        partialTAC[0] = UItoTACConverter.generateFormula(partialTAC[0]["formula"]["left"], "$_GET[funcoutput]", "AST_ASSIGN", "AST_ASSIGN", None,partialTAC[0]["types"]["left"], "string")

        decl_vars = {}
        assertions = []

        for n in partialTAC:
            assertions.append(z3Converter.manageGenericNode(n, decl_vars, VulnerablePath.attackType))



        fileName = "temporary_path_partially_solved"

        with open(fileName, "w") as f:
            f.write(z3Converter.generateFinalModel(decl_vars, assertions))

        os.system("../Z3-str3/build/z3 -T:10 " + fileName + " > " + fileName + ".model")

        contents = ""
        with open(fileName + ".model") as f:
            line = f.readline()
            if line[0:3] == "sat":
                contents = f.read()


        os.remove(fileName)
        os.remove(fileName + ".model")

        if contents == "":
            return None
        else:
            m = re.search(r'define-fun \$_GET_funcoutput_0 \(\) String\n    \"(.*)\"', contents)
            if m == None:
                return None
            else:
                return m.group(1)

    def getSourceVariableName(self, node, decl_vars):
        if node["formula"]["type"] == 'AST_ASSIGN':
            op = z3Converter.manageGenericOperandDecl(node["formula"]["right"], node["types"]["right"], decl_vars)
        else:
            op = ""
        return op

    def solve(self, partialTAC):
        #partialTAC[0] = UItoTACConverter.generateFormula(partialTAC[0]["formula"]["left"], "$_GET[funcoutput]", "AST_ASSIGN", "AST_ASSIGN", None, partialTAC[0]["types"]["left"], "string")


        decl_vars = {}
        assertions = []

        sourceVariableName = self.getSourceVariableName(partialTAC[0], decl_vars) #assuming the first instruction is the assignment to a variable from a source such as _GET

        for n in partialTAC:
            assertions.append(z3Converter.manageGenericNode(n, decl_vars, VulnerablePath.attackType))

        fileName = "temporary_path_partially_solved"

        with open(fileName, "w") as f:
            f.write(z3Converter.generateFinalModel(decl_vars, assertions))

        os.system("../Z3-str3/build/z3 -T:10 " + fileName + " > " + fileName + ".model")

        contents = ""
        with open(fileName + ".model") as f:
            line = f.readline()
            if line[0:3] == "sat":
                contents = f.read()

        os.remove(fileName)
        os.remove(fileName + ".model")

        if contents == "":
            return None
        else:
            #searchVar =
            m = re.search(r'define-fun \$HTTP_GET_VARS_page_0 \(\) String\n    \"(.*)\"', contents)
            if m == None:
                return None
            else:
                return "HTTP_GET_VARS_page_0 = " + m.group(1)


