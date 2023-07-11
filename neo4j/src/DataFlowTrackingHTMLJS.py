class DataNode:
    def __init__(self):
        self.id = 0
        self.labels = ""
        self.type = ""
        self.flags = ""  # no data
        self.lineno = 0  # no data
        self.code = ""
        self.childnum = 0
        self.funcid = 0  # no data
        self.lineno = 0
        self.classname = ""
        self.name = ""
        self.classname = ""  # no data
        self.namespace = ""  # no data
        self.endlineno = ""  # no data
        self.doccomment = ""  # no data


class DataFlowPath:
    def __init__(self):
        self.startNode = ""  # interface element id, for example - <input name='user_email'>. here, user_email will be source node.
        self.endNode = ""  # it will hold the class name information, for example, <form class='GDPR_REQUEST_DELETE'>. here, node containing 'form' will be stored at sinkNode
        self.PIIInfo = ""
        self.linkerKeyword = (
            ""  # it contains the class name of HTML we will find this name in JS Ajax Request class
        )
        self.requestType = "post"  # it can be either POST/GET/REQ
        self.path = []  # it will contain list of datanodes from source to sink in HTML + JS.
        self.violationOccur = False

    def print_path(self):
        print(
            "Complete Path--> Start Node:",
            self.startNode,
            "End Node:",
            self.endNode,
            "PII",
            self.PIIInfo,
            ",Linker Keyword",
            self.linkerKeyword,
            ",Request Type",
            self.requestType,
            ",Path",
            self.path,
            ",Violation Result",
            self.violationOccur,
        )
