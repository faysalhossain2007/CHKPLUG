import json

def manageGenericNode(node, decl_vars, attackType):
	if node["formula"]["type"] == "AST_CALL":
		return manageFunctionCall(node, decl_vars, attackType)
	elif node["formula"]["type"] == 'AST_CONST':
		return manageGenericConstant(node, decl_vars)
	elif node["formula"]["type"] == 'AST_BINARY_OP':
		return manageBinaryOperation(node, decl_vars)
	elif node["formula"]["type"] == 'AST_UNARY_OP':
		return manageUnaryOperation(node, decl_vars)
	elif node["formula"]["type"] == 'AST_ASSIGN':
		return manageAssignmentOperation(node, decl_vars)
	elif node["formula"]["type"] == 'AST_CONTAINS':
		return manageContainmentOperation(node, decl_vars)




def manageBinaryOperation(node, decl_vars):

	op1 = manageGenericOperandDecl(node["formula"]["right"][0], node["types"]["right"][0], decl_vars)
	op2 = manageGenericOperandDecl(node["formula"]["right"][1], node["types"]["right"][1], decl_vars)
	res = manageGenericOperandDecl(node["formula"]["left"], node["types"]["left"], decl_vars, True)

	if node["formula"]["op"] == "BINARY_CONCAT":
		operator = "str.++"

	elif node["formula"]["op"] == 'BINARY_IS_SMALLER':
		operator = "<"

	elif node["formula"]["op"] == 'BINARY_IS_SMALLER_OR_EQUAL':
		operator = "<="

	elif node["formula"]["op"] == 'BINARY_IS_GREATER':
		operator = ">"

	elif node["formula"]["op"] == 'BINARY_IS_GREATER_OR_EQUAL':
		operator = ">="

	elif node["formula"]["op"] == 'BINARY_BOOL_AND':
		operator = "and"

	elif node["formula"]["op"] == 'BINARY_BOOL_OR':
		operator = "or"

	elif node["formula"]["op"] == 'BINARY_BOOL_XOR':
		operator = "xor"

	elif node["formula"]["op"] == 'BINARY_ADD':
		operator = "+"

	elif node["formula"]["op"] == 'BINARY_SUB':
		operator = "-"

	elif node["formula"]["op"] == 'BINARY_MUL':
		operator = "*"

	elif node["formula"]["op"] == 'BINARY_DIV':
		operator = "div"

	elif node["formula"]["op"] == 'BINARY_MOD':
		operator = "mod"

	elif node["formula"]["op"] == 'BINARY_POW':
		operator = "^"

	elif node["formula"]["op"] == 'BINARY_IS_EQUAL' or node["formula"]["op"] == 'BINARY_IS_IDENTICAL':
		operator = "="

	elif node["formula"]["op"] == 'BINARY_IS_NOT_EQUAL' or node["formula"]["op"] == 'BINARY_IS_NOT_IDENTICAL':
		return "(assert (= " + res + " (not (= " + op1 + " " + op2 + "))))"

	
	return "(assert (= " + res + " (" + operator + " " + op1 + " " + op2 + ")))"



def manageUnaryOperation(node, decl_vars):

	op = manageGenericOperandDecl(node["formula"]["right"], node["types"]["right"], decl_vars)
	res = manageGenericOperandDecl(node["formula"]["left"], node["types"]["left"], decl_vars, True)

	if node["formula"]["op"] == "UNARY_BOOL_NOT":
		return "(assert (= " + res + " (not " + op + ")))"

	elif node["formula"]["op"] == "UNARY_MINUS":
		return "(assert (= " + res + " (- 0 " + op + ")))"




def manageAssignmentOperation(node, decl_vars):

	op = manageGenericOperandDecl(node["formula"]["right"], node["types"]["right"], decl_vars)
	res = manageGenericOperandDecl(node["formula"]["left"], node["types"]["left"], decl_vars, True)

	return "(assert (= " + res + " " + op + "))"




def manageContainmentOperation(node, decl_vars):

	op = manageGenericOperandDecl(node["formula"]["right"], node["types"]["right"], decl_vars)
	res = manageGenericOperandDecl(node["formula"]["left"], node["types"]["left"], decl_vars, True)

	return "(assert (str.contains " + res + " " + op + "))"



def manageFunctionCall(node, decl_vars, attackType):

	model = getFunctionModel(node, decl_vars, attackType)
	
	if model != "":
		return model
	else:
#		raise Exception()
		res = manageGenericOperandDecl(node["formula"]["left"], node["types"]["left"], decl_vars, True)
		assertion = "(assert (or "

		if len(node["formula"]["right"]) == 0:
			assertion = assertion + "(= " + res + " \"\")\n"
	
		for arg in node["formula"]["right"]:
			op = manageGenericOperandDecl(arg, node["types"]["left"], decl_vars)
			assertion = assertion + "(= " + res + " " + op + ")\n"

		assertion = assertion + "))"
		return assertion




def manageGenericConstant(node, decl_vars):

	op = manageGenericOperandDecl(node["formula"]["right"], node["types"]["right"], decl_vars)
	res = manageGenericOperandDecl(node["formula"]["left"], node["types"]["left"], decl_vars, True)

	return "(assert (= " + res + " " + op + "))"



def manageGenericOperandDecl(opName, opGuessedType, decl_vars, setAssigned = False):

	if opGuessedType == "":
		opGuessedType = "string"
    #was basestring instead of str
	if isinstance(opName, str) and len(opName) > 0 and (opName[0] != "\"" or opName[-1] != "\""):

		opName = opName.replace("[", "_")
		opName = opName.replace("]", "")

		if opName not in decl_vars:
			decl_vars[opName] = Variable(opName, opGuessedType)
			decl_vars[opName].setAssignment(setAssigned)
			return decl_vars[opName].getCompleteName()
		else:
			if setAssigned:
				if decl_vars[opName].assigned:
					return getOperandWithConversion(decl_vars[opName].type, opGuessedType, decl_vars[opName].getCompleteName(True))
				else:
					decl_vars[opName].setAssignment(True)
					return getOperandWithConversion(decl_vars[opName].type, opGuessedType, decl_vars[opName].getCompleteName())
			
			else:
				return getOperandWithConversion(decl_vars[opName].type, opGuessedType, decl_vars[opName].getCompleteName())

	if isinstance(opName, str):
		opName =  "\"" + opName[1:(len(opName)-1)].replace("\"", "\"\"") + "\""
		
		return getOperandWithConversion("string", opGuessedType, opName)

	if isinstance(opName, bool):
		if opName:
			return getOperandWithConversion("boolean", opGuessedType, "true")
		else:
			return getOperandWithConversion("boolean", opGuessedType, "false")

	return getOperandWithConversion("number", opGuessedType, str(opName))


def getFunctionModel(node, decl_vars, attackType):
	if node["formula"]["op"] == "mysql_query" and attackType == "sql":
		res = manageGenericOperandDecl(node["formula"]["left"], node["types"]["left"], decl_vars, True)
		query = manageGenericOperandDecl(node["formula"]["right"][-1], "string", decl_vars)

		assertion = "(assert (= " + res + " \"\"))\n(assert (str.contains " + query + " \"1 OR 1=1 #\"))"

		return assertion

	elif node["formula"]["op"] == "intval":
		res = manageGenericOperandDecl(node["formula"]["left"], "number", decl_vars, True)
		op = manageGenericOperandDecl(node["formula"]["right"][-1], "number", decl_vars)

		assertion = "(assert (= " + res + " " + op + "))"

		return assertion

	elif node["formula"]["op"] == "empty" or node["formula"]["op"] == "isset":
		res = manageGenericOperandDecl(node["formula"]["left"], "boolean", decl_vars, True)
		op = manageGenericOperandDecl(node["formula"]["right"], "boolean", decl_vars)

		assertion = "(assert (= " + res + " " + op + "))"

		return assertion

	elif node["formula"]["op"] == "echo" and attackType == "xss":
		op = manageGenericOperandDecl(node["formula"]["right"], "string", decl_vars)

		assertion = "(assert (str.contains " + op + " \"<SCRIPT>alert(1)</SCRIPT>\"))"

		return assertion

	elif node["formula"]["op"] in ["htmlspecialchars", "htmlentities"]:
		res = manageGenericOperandDecl(node["formula"]["left"], "string", decl_vars, True)
		op = manageGenericOperandDecl(node["formula"]["right"][-1], "string", decl_vars)

		assertion = "(assert (not (str.contains " + op + " \"&\")))\n"
		assertion = assertion + "(assert (not (str.contains " + op + " \"<\")))\n"
		assertion = assertion + "(assert (not (str.contains " + op + " \">\")))\n"
		assertion = assertion + "(assert (not (str.contains " + op + " \"\"\"\")))\n"

		if len(node["formula"]["right"]) > 1 and node["formula"]["right"][-2] == "ENT_QUOTES":
			assertion = assertion + "(assert (not (str.contains " + op + " \"'\")))\n"

		assertion = assertion + "(assert (= " + res + " " + op + "))"

		return assertion

	elif node["formula"]["op"] in ["trim", "rtrim", "ltrim"]:
		res = manageGenericOperandDecl(node["formula"]["left"], "string", decl_vars, True)
		op = manageGenericOperandDecl(node["formula"]["right"][-1], "string", decl_vars)

		assertion = "(assert (= " + res + " " + op + "))"

		return assertion

	elif node["formula"]["op"] == "stripslashes":
		res = manageGenericOperandDecl(node["formula"]["left"], "string", decl_vars, True)
		op = manageGenericOperandDecl(node["formula"]["right"][-1], "string", decl_vars)

		assertion = "(assert (not (str.contains " + op + " \"\\\")))\n"
		assertion = assertion + "(assert (= " + res + " " + op + "))"

		return assertion

	elif node["formula"]["op"] == "strip_tags":
		res = manageGenericOperandDecl(node["formula"]["left"], "string", decl_vars, True)
		op = manageGenericOperandDecl(node["formula"]["right"][-1], "string", decl_vars)

		assertion = "(assert (not (str.contains " + op + " \"<\")))\n"
		assertion = assertion + "(assert (= " + res + " " + op + "))"

		return assertion

	elif node["formula"]["op"] == "str_replace":
		res = manageGenericOperandDecl(node["formula"]["left"], "string", decl_vars, True)
		search = manageGenericOperandDecl(node["formula"]["right"][-1], "string", decl_vars)
		subject = manageGenericOperandDecl(node["formula"]["right"][-3], "string", decl_vars)

		assertion = "(assert (not (str.contains " + subject + " " + search + ")))\n"
		assertion = assertion + "(assert (= " + res + " " + subject + "))"

		return assertion

	

	return ""


def getOperandWithConversion(fromType, toType, opName):
	
	if fromType == toType:
		return opName

	if fromType == "string":
		if toType == "number":
			return "(str.to.int " + opName + ")"
		elif toType == "boolean":
			return "(stringToBool " + opName + ")"
	elif fromType == "number":
		if toType == "string":
			return "(int.to.str " + opName + ")"
		elif toType == "boolean":
			return "(intToBool " + opName + ")"
	elif fromType == "boolean":
		if toType == "string":
			return "(boolToString " + opName + ")"
		elif toType == "number":
			return "(boolToInt " + opName + ")"


def generateFinalModel(decl_vars, assertions):
	res = ""
	#was iteritems() for python2
	for (v, o) in decl_vars.items():
		for i in range(o.suffix + 1):
			if o.type == "string":
				ty = "String"
			elif o.type == "number":
				ty = "Int"
			elif o.type == "boolean":
				ty = "Bool"

			res = res + "(declare-const " + o.getCompleteName(forceSuffix = i) + " " + ty + ")\n"

	res = res + "(define-fun stringToBool ((str String)) Bool (ite (= str \"\") false true))\n"
	res = res + "(define-fun intToBool ((i Int)) Bool (ite (= i 0) false true))\n"
	res = res + "(define-fun boolToString ((b Bool)) String (ite (= b true) \"true\" \"false\"))\n"
	res = res + "(define-fun boolToInt ((b Bool)) Int (ite (= b true) 1 0))\n"

	res = res + "\n\n"

	for a in assertions:
		res = res + a + "\n"

	for (v, o) in decl_vars.items():
		if (not o.assigned) and o.type == "string" and not containsSource(v):
			res = res + "(assert (= " + o.getCompleteName() + " \"\"))\n"


	res = res + "\n\n(check-sat)\n\n(get-model)"

	return res


def containsSource(name):
	sources = ["_GET", "_POST", "_COOKIE", "_REQUEST", "_ENV", "HTTP_ENV_VARS", "HTTP_POST_VARS", "HTTP_GET_VARS"]

	for s in sources:
		if name.find(s) >= 0:
			return True

	return False


class Variable:

	def __init__(self, varName, varType):
		self.name = varName
		self.type = varType
		self.assigned = False
		self.suffix = 0

	def setAssignment(self, assignment):
		if assignment:
			self.assigned = True

	def getCompleteName(self, increment = False, forceSuffix = -1):
		if increment:
			self.suffix = self.suffix + 1

		if forceSuffix == -1:
			return self.name + "_" + str(self.suffix)

		return self.name + "_" + str(forceSuffix)



