import json

class UserInterface:

	EQUAL = 1
	CONTAINS = 2
	SOLVE = 3
	NOT_RELATED = 4
	JSONTAC = 5

	def __init__(self, info, attackType):
		self.info = info
		self.attackType = attackType

	def startConversation(self):

		question = self.buildInitialQuery()

		result = raw_input(question)

		if int(result) == 1:
			return self.notModifiedStep()
		elif int(result) == 2:
			return self.modifiedStep()
		else:
			return UserInterface.NOT_RELATED

	def notModifiedStep(self):

		question = self.buildNotModifiedQuery()

		result = raw_input(question)

		if int(result) == 1:
			return UserInterface.EQUAL
		elif int(result) == 2:
			return UserInterface.CONTAINS
		else:
			return UserInterface.NOT_RELATED

	def modifiedStep(self):

		question = self.buildModifiedQuery()

		result = raw_input(question)

		if int(result) == 1:
			return UserInterface.JSONTAC
		elif int(result) == 2:
			return UserInterface.SOLVE
		else:
			return UserInterface.NOT_RELATED


	def requestInput(self, output):

		if output is None:
			print "Cannot provide an output value for the function. Moving to the next path.\n\n"
			return None

		question = self.buildInputOutputQuery(output)

		result = raw_input(question)

		if result == "No":
			return None

		return result
		


	def buildInitialQuery(self):
		
		s = "Given the function call in file " + str(self.info["filename_callsite"]) + " at line " + str(self.info["lineno_callsite"])

		if self.info["filename_defsite"] is not None:
			s = s + " (function definition in file " + str(self.info["filename_defsite"]) + " at line " + str(self.info["lineno_defsite"]) + ")"

		if "tracking" in self.info:
			s = s + ", knowing that the user controllable input for an " + self.attackType + " attack will flow through input parameter " + str(self.info["tracking"][0])

		s = s + ", what can you state about the function operation?\n1) The input parameter flows to the output without modifications\n2) The input parameter flows to the output and is modified in the process\n3) The input parameter does not flow to the output\n\n> "

		return s


	def buildNotModifiedQuery(self):
	
		s = "Given that the user input is not modified while flowing to the output, is one of the following true?\n1) The output is equal to the input parameter\n2) The output contains (more generally) the input parameter\n\n> "

		return s


	def buildModifiedQuery(self):
	
		s = "Given that the user input is modified while flowing to the output, can you do one of the following?\n1) Provide a JSON TAC formula representation of the operations that are performed\n2) Find an input assignment to the parameter that will produce a given output\n\n> "

		return s


	def buildInputOutputQuery(self, output):
	
		s = "Can you provide an input for parameter " + str(self.info["tracking"][0]) + " to the function such that the output contains " + output + "? (Type No if not possible)\n\n> "

		return s



class UItoTACConverter:

	def __init__(self, formula):
		self.formula = formula

	def executeConversion(self, UIresult):

		if UIresult == UserInterface.EQUAL:
			return [UItoTACConverter.generateFormula(self.formula["formula"]["left"], self.formula["formula"]["right"][len(self.formula["formula"]["right"]) - self.formula["tracking"][0]], "AST_ASSIGN", "AST_ASSIGN", self.formula["formula"]["node_id"], self.formula["types"]["left"], self.formula["types"]["right"][len(self.formula["types"]["right"]) - self.formula["tracking"][0]])]

		elif UIresult == UserInterface.CONTAINS:
			return [UItoTACConverter.generateFormula(self.formula["formula"]["left"], self.formula["formula"]["right"][len(self.formula["formula"]["right"]) - self.formula["tracking"][0]], "AST_CONTAINS", "AST_CONTAINS", self.formula["formula"]["node_id"], self.formula["types"]["left"], self.formula["types"]["right"][len(self.formula["types"]["right"]) - self.formula["tracking"][0]])]

		elif UIresult == UserInterface.JSONTAC:
			correct = False

			while not correct:
				try:
					tac = raw_input("Input the JSON TAC formula representing the operations that are performed\n> ")
					tac = json.loads(tac)
					correct = True
				except:
					print "The JSON syntax is not correct\n"

			return tac
		
		else:
			return None



	@staticmethod
	def generateFormula(left, right, op, node_type, node_id, ltype, rtype):
		result = {}
		result["formula"] = {}
		result["formula"]["left"] = left
		result["formula"]["right"] = right
		result["formula"]["op"] = op
		result["formula"]["type"] = node_type
		result["formula"]["node_id"] = node_id

		result["types"] = {}
		result["types"]["left"] = ltype
		result["types"]["right"] = rtype

		return result

