1. execute `build-and-run-docker.sh` to generate nodes, edges and cpg_edges for plugin's php file
2. run `neo4j/src/HTMLParser.py` to generate nodes and edges for plugin's HTML code
2. run `neo4j/src/integration/integration.py` to generate nodes, edges and cpg_edges for plugin's js file and merge it with the corresponding php joern and html 
3. execute `load-integration-results-to-neo4j-desktop.sh` to load the integration results to neo4j