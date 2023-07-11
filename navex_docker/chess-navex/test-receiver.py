from messageManager import MessageManager
import os
from old.z3Converter import *

broker = MessageManager("192.168.56.101", "searchToTAC")

body = broker.receiveMessage()
paths = {}

sat = 0

while body is not None:
	msg = json.loads(body)

	decl_vars = {}
	assertions = []

	formula = msg["tac"]

	if msg["header"]["unique_id"] not in paths:
		paths[msg["header"]["unique_id"]] = 0
	else:
		paths[msg["header"]["unique_id"]] = paths[msg["header"]["unique_id"]] + 1

	attackType = msg["header"]["sinkType"]

	try:
		for n in formula:
			try:
				assertions.append(manageGenericNode(n, decl_vars, attackType))
			except Exception as e:
				print json.dumps(n)
				print "skipped " + msg["header"]["file"] + "__" + str(msg["header"]["line"]) + "\n"
				raise
	except Exception as e:
		body = broker.receiveMessage()
		continue
		
		

	fileName = "staticAnalysisSpec" + msg["header"]["file"] + "__" + str(msg["header"]["line"]) + "__" + str(msg["header"]["node_id"]) + "__" + msg["header"]["sinkType"] + "__" + str(msg["header"]["unique_id"]) + "-" + str(paths[msg["header"]["unique_id"]])
	dirs = os.path.dirname(fileName)

	if not os.path.exists(dirs):
		os.makedirs(dirs)

	with open(fileName, "w") as f:
		f.write(generateFinalModel(decl_vars, assertions))

	os.system("../Z3-str3/build/z3 -T:10 " + fileName + " > " + fileName + ".model")

	with open(fileName + ".model") as f:
		line = f.readline()
		if line[0:3] == "sat":
			sat = sat + 1
#			print "\n\n############ " + fileName + " ############"
#			print f.read()
			print msg["header"]["file"] + "__" + str(msg["header"]["line"])

	body = broker.receiveMessage()

broker.closeConnection()

print "\n\n@@@@@@@@@@@@@@@@@ COMPLETE - SAT: " + str(sat) + " @@@@@@@@@@@@@@@@@\n" 
