'''
@author: Tommi Unruh
@modified by : Abeer Alhuzali
'''
# not completed

from io import StringIO

class staticResults(object):
    """
    Class to save and analyze the output of the static analysis component of NAVEX.
    """


    def __init__(self, file="", line_no=-1, node_id=-1, formulas="", query_time=-1):
        '''
        Constructor
        '''
        self.file = file
        self.line_no = line_no
        self.node_id = node_id
        self.query_time = query_time
        self.formulas = formulas
        
    def stripDataFromOutput(self, output):
        """
        Extract the data from the static analysis output.
        Example output for a found vulnerbility:
        
        {u'[Vulnerable sink formula: file: /var/www/html/mybloggie/adduser.php, 
          ine:108, node id: 8488]': [[u'left: $result, right: $temp_8491, op: AST_ASSIGN, type: AST_ASSIGN, node_id: 8488', [u'left: [$sql], right: $temp_8491, op: db, type: AST_METHOD_CALL, node_id: 8491']], [u'left: $level, right: $temp_8279, op: AST_ASSIGN, type: AST_ASSIGN, node_id: 8276', [u'left: [$level], right: $temp_8279, op: trim, type: AST_CALL, node_id: 8279']], [u'left: $level, right: $temp_8279, op: AST_ASSIGN, type: AST_ASSIGN, node_id: 8276', [u'left: [$level], right: $temp_8279, op: trim, type: AST_CALL, node_id: 8279']], [u'left: $level, right: $temp_8246, op: AST_ASSIGN, type: AST_ASSIGN, node_id: 8243', [u'left: [$_POST[level]], right: $temp_8246, op: intval, type: AST_CALL, node_id: 8246']], [u'left: $level, right: $temp_8246, op: AST_ASSIGN, type: AST_ASSIGN, node_id: 8243', [u'left: [$_POST[level]], right: $temp_8246, op: intval, type: AST_CALL, node_id: 8246']]],
        
      OR 
      {u'Vulnerable sink formula: file: /var/www/html/mybloggie/adduser.php, 
          ine:108, node id: 8488]':


        AND for safe sinks : 
           Not A vulnerable sink: file: /var/www/html/mybloggie/includes/function.php, line:39, node id: 24032

        """
        buf = StringIO.StringIO(output)
        
        # Extract only the vuln sinks info 
        start_index = len("{u'[Vulnerable sink formula: file: ")
        end_index= len("]': ")
        allLine= buf.readline();
        
        filepath, line_no, node_id, rest = allLine[start_index:end_index].split(", ")
        line_no = line_no.split("line: ")
        node_id = node_id.split("node_id: ")

        # now we have to extract the formulas
        #[u'left: 

        self.file     = filepath.strip()
        self.line_no   = int(line_no)
        self.node_id = int(node_id)

    def setQueryFile(self, file):
        self.file = file

    def setQueryTime(self, qt):
        self.query_time = qt
        
    def getQueryTime(self):
        if self.query_time > 0:
            return self.query_time
        
        else:
            raise Exception(
                    "Query time value is wrong. Maybe "
                    "it was not set? Query time: %d" % (self.query_time)
                    )
    
    