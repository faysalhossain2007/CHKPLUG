import os
import sys, getopt

"""
  Author: Abeer Alhuzali
"""

class CodeCoverage:

 def readCodeCoverageFile(self):
   print ('Reading Code Coverage File ')
   fileMap ={}
	#codeCoverage.txt
   with open('/home/user/log/codeCoverage.txt', 'r') as f:
	 for line in f:
                line = line.rstrip('\n').strip()	
		if line.startswith('array ('):
			continue
		elif line.startswith('\'') and line.endswith('php\' =>'):
			            #  '/var/www/html/mybloggie/includes/template.php(141) : eval()\'d code' =>
                        phpFile= line.replace("\'", "").replace("=>", "").strip()
			fileLines =[]

		elif "=> 1," in line:
			lineno, _ = line.split('=> 1')
                        lineno=int(lineno.strip())
			fileLines.append(lineno)
		
		elif ")," in line and (phpFile is not None) and (len(fileLines) > 0):
			fileMap[phpFile] = fileLines
			
   return  fileMap
  		

