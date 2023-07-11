from Utls import progress_bar
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple, Union
from NeoGraph import getGraph
from DataFlows import DataNode
from NeoHelper import *
from DataFlowTracking import reverseTrackDataFlowToParamORAssignNoRecord
import signal

#source: https://stackoverflow.com/questions/25027122/break-the-function-after-certain-time
class TimeoutException(Exception):   # Custom exception class
    print("Timeout in running neo4j query")

def timeout_handler(signum, frame):   # Custom signal handler
    raise TimeoutException

# Change the behavior of SIGALRM
signal.signal(signal.SIGALRM, timeout_handler)
class ASTClass:
    def __init__(self, nodeID, classname, parentClass = None, interfaces = []):
        self.id = nodeID
        self.classname = classname
        #the class can be a normal class, abstract class, and interface
        self.classType = "Normal"
        self.parentClass = parentClass
        self.isAbstract = False
        self.interfaces = interfaces
        self.isInterface = False
        #key: variable name. value: DataNode object
        self.classVariables = {}
        #key: method name. value: ASTMethod object
        self.classMethods = {}

class ASTMethod:
    def __init__(self,nodeID):
        self.nodeID = nodeID
        #key:parameter name. value: type name(in string)
        self.parameterType = {}
        #Assume there is only one valid return type
        self.returnType = ''


class ClassHierarchy:
    def __init__(self):
        #key: classname. value: ASTClass object
        self.classes = {}
        #key: func ID. value: ASTMethod object. Used for storing functions not within any class. 
        #note: the key is funcID instead of func name, because there may be functions with duplicated name.
        self.functions = {}
    def addClass(self,classObj:ASTClass):
        self.classes[classObj.classname] = classObj
    
    def lookUpParamType(self,className,funcName,paramName):
        """
        Returns a parameter's type as documented in the function documentation
        """
        if className in self.classes:
            tempClass = self.classes[className]
            if funcName in tempClass.classMethods:
                tempMethod = tempClass.classMethods[funcName]
                if paramName in tempMethod.parameterType:
                    return tempMethod.parameterType[paramName]
        return None
    def lookUpParentClass(self,childrenClass):
        if childrenClass in self.classes:
            tempClass = self.classes[childrenClass]
            return tempClass.parentClass
    def lookUpParamTypeNoClass(self,funcID,paramName):
        if funcID in self.functions:
            tempFunc = self.functions[funcID]
            if paramName in tempFunc.parameterType:
                return tempFunc.parameterType[paramName]
        return None
    def lookUpReturnType(self,className,funcName):
        """
        Returns a parameter's type as documented in the function documentation
        """
        if className in self.classes:
            tempClass = self.classes[className]
            if funcName in tempClass.classMethods:
                tempMethod = tempClass.classMethods[funcName]
                return tempMethod.returnType
        return None
    def lookUpReturnTypeNoClass(self,funcID):
        if funcID in self.functions:
            return self.functions[funcID].returnType
        return None
    def lookUpFunction(self,typeName,funcName):
        """
        Given an object's type name and a function name, get the respective function ID.
        Put interface and abstract class into consideration.
        """
        if isinstance(typeName,str) and typeName in self.classes:
            tempClass = self.classes[typeName]
            if tempClass.isInterface:
                possibleMethodID = []
                #find classes that implements the interface
                classList = self.lookUpInterfaceImplementation(tempClass.classname)
                for possibleClass in classList:
                    if funcName in self.classes[possibleClass].classMethods:
                        possibleMethodID.append(self.classes[possibleClass].classMethods[funcName].nodeID)
                return possibleMethodID
            # elif tempClass.isAbstract:
            #     possibleMethodID = []
            #     #find classes that extend the class
            #     classList = self.lookUpChildrenClass(tempClass.classname)
            #     for possibleClass in classList:
            #         if funcName in self.classes[possibleClass].classMethods:
            #             possibleMethodID.append(self.classes[possibleClass].classMethods[funcName].nodeID)
            #     return possibleMethodID
                
            else:
                if funcName in tempClass.classMethods:
                    return [tempClass.classMethods[funcName].nodeID]
                #inheritance from parent class
                else:
                    if not tempClass.parentClass==tempClass.classname:
                        # print(f"current class: {tempClass.classname}. parent class: {tempClass.parentClass}")
                        return self.lookUpFunction(tempClass.parentClass,funcName)
            
        return []
    def lookUpInterfaceImplementation(self,interface):
        classList = []
        for tempClass in self.classes:
            tempClassobj = self.classes[tempClass]
            if interface in tempClassobj.interfaces:
                classList.append(tempClassobj.classname)
        return classList
    def lookUpChildrenClass(self,parentClass):
        classList = []
        for tempClass in self.classes:
            tempClassobj = self.classes[tempClass]
            if parentClass == tempClassobj.parentClass:
                classList.append(tempClassobj.classname)
        return classList
    def lookUpClassVarID(self,className,varname):
        if className in self.classes:
            tempClass = self.classes[className]
            if varname in tempClass.classVariables:
                return tempClass.classVariables[varname].id
        return None
    def lookUpClassVarType(self,className,varname):
        if className in self.classes:
            tempClass = self.classes[className]
            if varname in tempClass.classVariables:
                return tempClass.classVariables[varname].type
        return None
    def lookUpClassVarValue(self,className,varname):
        if className in self.classes:
            tempClass = self.classes[className]
            if varname in tempClass.classVariables and tempClass.classVariables[varname].value:
                return tempClass.classVariables[varname].value
        return None
    def fillClassHierarchy(self):
        print("Start filling class hierarchy information")
        graph = getGraph()
        #This query gets the class's interface, abstract class, class methods and class variables.
        classQuery = """
        MATCH (n:AST)-[:PARENT_OF]->(toplevel)
        WHERE n.type = 'AST_CLASS' AND toplevel.type = 'AST_TOPLEVEL'
        OPTIONAL MATCH (n)-[:PARENT_OF]->(m:AST)-[:PARENT_OF]->(astname:AST)-[:PARENT_OF]->(str)
        WHERE m.type = 'AST_NAME_LIST'
        OPTIONAL MATCH (n)-[:PARENT_OF]->(astname2:AST)-[:PARENT_OF]->(str2)
        WHERE astname2.type = 'AST_NAME'
        OPTIONAL MATCH (vars)
        WHERE vars.funcid = toplevel.id AND vars.type = 'AST_PROP_DECL'
        OPTIONAL MATCH (method)
        WHERE method.classname = n.name AND method.type = 'AST_METHOD'
        RETURN n,COLLECT(str.code) AS interfaces, COLLECT(str2.code) AS parent, COLLECT(vars.id) AS classVars, COLLECT(method) AS methods
        """
        classResult = graph.run(cypher = classQuery).data()
        for classObj in progress_bar(classResult):
            classInfo = classObj['n']
            interfaces = list(classObj['interfaces'])
            parentClass = list(classObj['parent'])
            classVars = list(classObj['classVars'])
            classMethods = list(classObj['methods'])
            classFlag = classInfo['flags']
            newClass = ASTClass(classInfo['id'],classInfo['name'])
            #handle interfaces
            if interfaces:
                newClass.interfaces = interfaces
            #handle abstract classes
            if parentClass:
                #There should just be one abstract class that a class implements
                newClass.parentClass = parentClass[0]
            #flag whether a class is an interface or an abstract class.
            if classFlag:
                if 'CLASS_INTERFACE' in classFlag:
                    newClass.isInterface = True
                elif 'CLASS_ABSTRACT' in classFlag:
                    newClass.isAbstract = True
            #handle class variables
            for var in classVars:
                varQuery = f"""
                MATCH (n:AST{{id:{var}}})-[:PARENT_OF]->(m)-[:PARENT_OF]->(x)
                RETURN x ORDER BY x.childnum ASC
                """
                varResult = graph.run(cypher = varQuery).data()
                
                if varResult:
                    #This contains the variable name of a class variable
                    tempNode = DataNode(var,varResult[0]['x']['code'])
                    #if the length of the result is more than 1, it means that the variable is assigned a value. We store the nodeID of the 
                    #value and will later make a data flow edge between them
                    if len(varResult)>1:
                        tempNode.value = varResult[1]['x']['id']
                    
                    #try to get the type of the class variable as written in the comment.
                    varCommentQuery = f"""
                    MATCH (n:AST{{id:{var}}})-[:PARENT_OF]->(m)
                    RETURN m.doccomment
                    """
                    varCommentResult = graph.run(cypher = varCommentQuery).data()
                    if varCommentResult and varCommentResult[0]['m.doccomment']:
                        
                        commentString = varCommentResult[0]['m.doccomment'].splitlines()
                        for string in commentString:
                            if '@var' in string:
                                varType = string.split()
                                if len(varType)>=3:
                                    varType = varType[2]
                                    tempNode.type = varType
                    newClass.classVariables[varResult[0]['x']['code']] = tempNode 
            for method in classMethods:
                tempMethod = ASTMethod(method['id'])
                #If the method has comments, try to parse it using the PHPDoc format: 
                # reference: https://docs.phpdoc.org/3.0/guide/references/phpdoc/tags/param.html,
                # https://docs.phpdoc.org/3.0/guide/references/phpdoc/tags/return.html
                if method['doccomment']:
                    typeInfo = parseMethodComments(method['doccomment'])
                    if 'return' in typeInfo:
                        tempMethod.returnType = typeInfo['return']
                    if 'param' in typeInfo:
                        tempMethod.parameterType = typeInfo['param']
                    
                #if the document is absent, then try to see if the func is strong typed and use that to get the types.
                else:
                    #get the strong type return type
                    returnQuery = f"""
                    MATCH (n:AST{{id:{method['id']}}})-[:PARENT_OF]->(m:AST{{childnum:3,type:'AST_NAME'}})-[:PARENT_OF]->(x:AST)
                    RETURN x.code
                    """
                    returnResult = graph.run(cypher= returnQuery).data()
                    if returnResult:
                        tempMethod.returnType = returnResult[0]['x.code']
                    #get the strong type param types
                    paramQuery = f"""
                    MATCH (x:AST)<-[:PARENT_OF]-(paramType:AST{{childnum:0,type:'AST_NAME'}})<-[:PARENT_OF]-(n:AST{{type:'AST_PARAM',funcid:{method['id']}}})-[:PARENT_OF]->(paramName:AST{{childnum:1}})
                    RETURN paramName.code,x.code
                    """
                    paramQuery = graph.run(cypher = paramQuery).data()
                    if paramQuery:
                        for param in paramQuery:
                            paramName = param['paramName.code']
                            typeName = param['x.code']
                            tempMethod.parameterType[paramName] = typeName
                newClass.classMethods[method['name']] = tempMethod
                
            self.addClass(newClass)
        print("Finished filling class hierarchy information")
    def fillFunctions(self):
        """
        Get the type information of param and returns for functions not within a class
        """
        print("Start filling function information")
        graph = getGraph()
        funcQuery = f"""
        MATCH (n{{type:'AST_FUNC_DECL'}})
        RETURN n
        """
        funcResult = graph.run(cypher = funcQuery).data()
        for result in progress_bar(funcResult):
            
            funcNode = result['n']
            tempMethod = ASTMethod(funcNode['id'])
            if funcNode['doccomment']:
                typeInfo = parseMethodComments(funcNode['doccomment'])
                if 'return' in typeInfo:
                    tempMethod.returnType = typeInfo['return']
                if 'param' in typeInfo:
                    tempMethod.parameterType = typeInfo['param']
                
            else:
                pass
            self.functions[funcNode['id']] = tempMethod
        print("Finished filling function information")

def parseMethodComments(commentStr):
    typeInfo  = {}
    commentLines = commentStr.splitlines()
    parameterType = {}
    for string in commentLines:
        if '@return' in string:
            returnType = string.split()
            if len(returnType)<=2:
                continue
            else:
                returnType = returnType[2]
            if '|' in returnType:
                #assume that only one of the return types matter
                returnType = returnType.split("|")
                temp = stripUselessTypes(returnType)
                if temp:
                    returnType = temp
            typeInfo['return'] = returnType
            
            
        elif '@param' in string:
            param = string.split()
            if len(param)>=4:
                paramType = param[2]
                paramName = param[3][1:]
                parameterType[paramName] = paramType
    typeInfo['param'] = parameterType
    return typeInfo
def stripUselessTypes(typeList):
    for type in typeList:
        if type in ['false','true','null']:
            typeList.remove(type)
    if len(typeList)==1:
        return typeList[0]
    return None

global __HIERARCHY
__HIERARCHY: ClassHierarchy = None


def getClassHierarchy() -> ClassHierarchy:
    """get the class hierarchy object that contains the class information of the current plugin.
    """
    global __HIERARCHY
    if __HIERARCHY:
        return __HIERARCHY
    else:
        print("Analzying PHP class hierarchy...")
        __HIERARCHY = ClassHierarchy()
        __HIERARCHY.fillClassHierarchy()
        __HIERARCHY.fillFunctions()
        return __HIERARCHY

def determineObjectType(obj):
    """This function tries to determine the class type of a node object
    Input:
        dictionary, at minimum with keys: 'type', 'id'
    Output:
        string: the classname of the object / None: if the object's type cannot be found
    """
    graph = getGraph()
    classHierarchy = getClassHierarchy()

    #this is what we want to know: the class which the given object is an instance of
    objClassType = None

    #this is the AST type
    objType = obj['type']
    #if this is a var, we backtrace. We try to backtrace either to an AST param or to AST assign, whichever is closer to traverse to.
    if objType=='AST_VAR':
        #first check if the var is $this
        varName = getVarName(obj['id'])
        if varName == 'this':
            objClassType = obj['classname']
        else:
            resultType = ''
            signal.alarm(60)
            try:
                resultType,resultNode = reverseTrackDataFlowToParamORAssignNoRecord(obj['id'])
            except TimeoutException:
                return objType
            else:
                signal.alarm(0)
                #if we backtrace to a param, we try to look up the return type of the param
                if resultType=='Param':
                    #get classname, func name, and param names
                    tempQuery = f"""
                    MATCH (n)-[:PARENT_OF]->(m)
                    WHERE n.id = {resultNode['id']} AND m.childnum = 1
                    MATCH (func{{id:n.funcid}})
                    RETURN m.code,n.classname,func.name, func.id
                    """
                    tempResult = graph.run(cypher = tempQuery).data()
                    
                    if tempResult:
                        paramName = tempResult[0]['m.code']
                        paramType = None
                        
                        if not 'n.classname' in tempResult[0]:
                            funcID = tempResult[0]['func.id']
                            paramType = classHierarchy.lookUpParamTypeNoClass(funcID,paramName)
                        else:
                            className = tempResult[0]['n.classname']
                            funcName = tempResult[0]['func.name']
                            paramType = classHierarchy.lookUpParamType(className,funcName,paramName)
                            
                        if paramType:
                            objClassType = paramType
                elif resultType=='Assign':
                    #handle the case where the assigner is a NEW or a traceable function call.
                    assignerNodeType = resultNode['type']
                    #if the assigner is a function call
                    if assignerNodeType in ['AST_METHOD_CALL','AST_STATIC_CALL','AST_CALL']:
                        #get the func definition
                        funcDefQuery = f"""
                        MATCH (n{{id:{resultNode['id']}}})-[:CALLS]->(m)
                        RETURN m.name,m.classname
                        """
                        funcDefResult = graph.run(cypher=funcDefQuery).data()
                        if funcDefResult:
                            returnType = classHierarchy.lookUpReturnType(funcDefResult[0]['m.classname'],funcDefResult[0]['m.name'])
                                
                            if returnType:
                                objClassType = returnType
                    #if the assigner is an ast new
                    elif assignerNodeType == 'AST_NEW':
                        ASTNewTypeQuery = f"""
                        MATCH (n{{id:{resultNode['id']}}})-[:PARENT_OF]->({{childnum:0}})-[:PARENT_OF]->(code)
                        RETURN code.code
                        """
                        ASTNewTypeResult = graph.run(cypher=ASTNewTypeQuery).data()
                        if ASTNewTypeResult:
                            newType = ASTNewTypeResult[0]['code.code']
                            objClassType = newType
    #if this is something like $a->b, we should also backtrace. In case the var is a class property, we simply look up the type
    elif objType == 'AST_PROP':
        #first check if this is a class property (e.g. $this->property)
        classPropertyQuery = f"""
        MATCH (var:AST{{childnum:1}})<-[:PARENT_OF]-(n:AST{{id:{obj['id']}}})-[:PARENT_OF]->({{childnum:0}})-[:PARENT_OF]->({{code:'this'}})
        RETURN n.classname,var.code
        """
        classPropertyResult = graph.run(cypher = classPropertyQuery).data()
        if classPropertyResult:
            classname = classPropertyResult[0]['n.classname']
            propertyName = classPropertyResult[0]['var.code']
            returnType = classHierarchy.lookUpClassVarType(classname,propertyName)
            if returnType:
                objClassType = returnType
        #(WIP) backtrace the AST_PROP to determine type
                
        
    #if this is a returned result from a function call, we trace the type of the function return
    elif objType in ['AST_METHOD_CALL','AST_STATIC_CALL','AST_CALL']:

        #first, we trace to the function definition.
        funcDefQuery = f"""
        MATCH (n{{id:{obj['id']}}})-[:CALLS]->(m)
        RETURN m.name,m.classname,m.id
        """
        funcDefResult = graph.run(cypher=funcDefQuery).data()
        if funcDefResult:
            returnType = None
            if not funcDefResult[0]['m.classname']:
                returnType = classHierarchy.lookUpReturnTypeNoClass(funcDefResult[0]['m.id'])
            else:
                returnType = classHierarchy.lookUpReturnType(funcDefResult[0]['m.classname'],funcDefResult[0]['m.name'])
        
            if returnType:
                objClassType = returnType
        #handle special case where it's a get_class(), get_parent_class()
        else:
            funcName = getCallName(obj['id'])
            if funcName=='get_class':
                args = getCallArguments(obj['id'])
                objClassType = determineObjectType(args[0])
            elif funcName=='get_parent_class':
                args = getCallArguments(obj['id'])
                objClassType = classHierarchy.lookUpParentClass(determineObjectType(args[0]))
    elif objType=='AST_MAGIC_CONST':
        #handle case where class is represented through __CLASS__
        if 'MAGIC_CLASS' in obj['flags']:
            objClassType = obj['classname']
    return objClassType

if __name__ == "__main__":
    classHierarchy = ClassHierarchy()
    classHierarchy.fillClassHierarchy()
    pass