from py2neo import Graph
from py2neo.ext.gremlin import Gremlin
from py2neo.packages.httpstream import http

import os

DEFAULT_GRAPHDB_URL = "http://localhost:7474/db/data/"
DEFAULT_STEP_DIR = os.path.dirname(__file__) + '/phpjoernsteps/'
#DEFAULT_STEP_DIR ='/home/abeer/python-joern-0.3.1/joern/phpjoernsteps/'


class JoernSteps:

    def __init__(self):
        self._initJoernSteps()
        self.initCommandSent = False

        # Bump the py2neo socket timeout from 30s, neo4j doesn't kill queries on timeout so might
        #  as well let the client pick when to stop.
        http.socket_timeout = 100000

    def setGraphDbURL(self, url):
        """ Sets the graph database URL. By default,
        http://localhost:7474/db/data/ is used."""
        self.graphDbURL = url
    
    def addStepsDir(self, stepsDir):
        """Add an additional directory containing steps to be injected
        into the server"""
        self.stepsDirs.append(stepsDir)
    
    def connectToDatabase(self):
        """ Connects to the database server."""
        self.graphDb = Graph(self.graphDbURL)
        self.gremlin = Gremlin(self.graphDb)

    def runGremlinQuery(self, query):

        """ Runs the specified gremlin query on the database. It is
        assumed that a connection to the database has been
        established. To allow the user-defined steps located in the
        phpjoernsteps directory to be used in the query, these step
        definitions are sent before the first query."""
        
        if not self.initCommandSent:
            self.gremlin.execute(self._createInitCommand())
            self.initCommandSent = True

        return self.gremlin.execute(query)
        
    def runCypherQuery(self, cmd):
        """ Runs the specified cypher query on the graph database."""
        return self.graphDb.cypher.execute(cmd)

    def getGraphDbURL(self):
        return self.graphDbURL
    
    """
    Create chunks from a list of ids.
    This method is useful when you want to execute many independent 
    traversals on a large set of start nodes. In that case, you
    can retrieve the set of start node ids first, then use 'chunks'
    to obtain disjoint subsets that can be passed to idListToNodes.
    """
    def chunks(self, idList, chunkSize):
        for i in xrange(0, len(idList), chunkSize):
            yield idList[i:i+chunkSize]

    def _initJoernSteps(self):
        self.graphDbURL = DEFAULT_GRAPHDB_URL
        self.stepsDirs = [DEFAULT_STEP_DIR]
	

    def _createInitCommand(self):
        
        initCommand = ""

        for stepsDir in self.stepsDirs:
            for (root, dirs, files) in os.walk(stepsDir, followlinks=True):
                files.sort()
                for f in files:
                    filename = os.path.join(root, f)
                    if not filename.endswith('.groovy'):
                        continue
                    theFile = open(filename, 'r')
                    initCommand += theFile.read() + "\n"
                    #print(filename)	    
        return initCommand
