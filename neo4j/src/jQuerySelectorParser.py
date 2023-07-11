
from NeoGraph import getGraph
import re
import json
from Settings import SRC_DIR
from Naked.toolshed.shell import muterun_js
import os

def getSelectedHTMLFormInputs(selector_statement:str):
    """from the jquery selector statement, locate the node IDs for the HTML form inputs that are being selected.
    
    """

    parseResult = parseSelectorWithParsel(selector_statement)
    
    if not parseResult:
        # if we do not get any parse results for the jquery selector, return an empty list.
        return []
    
    graph = getGraph()
    query = f"""
MATCH (n:AST_HTML{{type:'tag',name:'input'}})
WHERE """
    allAttributeQuery = []
    for node in parseResult:
        attributeType = node['type']
        attributeName = node.get('name','')
        attributeValue = node.get('value','').replace("'","").replace('"','')
        operator = node.get('operator','=')
        if attributeType == 'attribute':
            if operator == '=':
                allAttributeQuery.append(f"""exists((n)-[:PARENT_OF]->(:AST_HTML{{type:'attribute',name:'{attributeName}'}})-[:PARENT_OF]->(:AST_HTML{{type:'string',code:'{attributeValue}'}}))""")
            elif operator == '~=' or operator == '*=':
                allAttributeQuery.append(f"""
EXISTS {{
MATCH (n)-[:PARENT_OF]->(attribute_name2:AST_HTML{{type:'attribute',name:'{attributeName}'}})-[:PARENT_OF]->(x2:AST_HTML{{type:'string'}})
WHERE x2.code CONTAINS '{attributeValue}'
                }}""")
            elif operator == '^=':
                allAttributeQuery.append(f"""
EXISTS {{
MATCH (n)-[:PARENT_OF]->(attribute_name2:AST_HTML{{type:'attribute',name:'{attributeName}'}})-[:PARENT_OF]->(x2:AST_HTML{{type:'string'}})
WHERE x2.code CONTAINS '{attributeValue}'
}}""")
            elif operator == '$=':
                allAttributeQuery.append(f"""
EXISTS {{
MATCH (n)-[:PARENT_OF]->(:AST_HTML{{type:'attribute',name:'{attributeName}'}})-[:PARENT_OF]->(x2:AST_HTML{{type:'string'}})
WHERE x2.code ENDS WITH '{attributeValue}'
}}""")
            elif operator == '|=':
                allAttributeQuery.append(f"""
EXISTS {{
MATCH (n)-[:PARENT_OF]->(:AST_HTML{{type:'attribute',name:'{attributeName}'}})-[:PARENT_OF]->(x2:AST_HTML{{type:'string'}})
WHERE x2.code = '{attributeValue}' OR x2.code = '{attributeValue+'-'}'
                }}""")
        elif attributeType == 'id':
            allAttributeQuery.append(f"""exists((n)-[:PARENT_OF]->(:AST_HTML{{type:'attribute',name:'id'}})-[:PARENT_OF]->(:AST_HTML{{type:'string',code:'{attributeName}'}}))""")
    if not allAttributeQuery:
        return []
    query += " AND \n".join(allAttributeQuery)
    query += f"""
RETURN n.id
    """
    
    # print(query)
    result = graph.run(cypher = query).data()
    if not result:
        return []
    else:
        return [r['n.id'] for r in result]
            
    
    
def parseJQuerySelector(selector_statement:str):
    """parse the selector statement to determine the attributes or classes of the selected inputs. 
    Refer to jquery documentation: https://api.jquery.com/category/selectors/
    """

    if 'input' not in selector_statement:
        # we only handle input selectors
        return []
    # the list allProperties contain a list of tuples in the format of (<attribute type>,<value>) (e.g., [('name','email')])
    allProperties = ()
    stripped_stmt = selector_statement.replace("input","", 1)
        
    if '[' in stripped_stmt:
        # selects elements that have attributes of certain value
        # first get the string between the first [ and ]
        temp_stmt = stripped_stmt[(stripped_stmt.index('[')+1):stripped_stmt.index(']')]
        attribute_name = temp_stmt[:temp_stmt.index('=')]
        value = temp_stmt[temp_stmt.index('=')+1:].replace("'","").replace('"','')
        if '|' in attribute_name:
            # Selects elements that have the specified attribute with a value either equal to a given string or starting with that string followed by a hyphen (-).
            allProperties = ('attribute_hyphen',attribute_name.replace('|',''),value)
        elif '*' in attribute_name:
            # Selects elements that have the specified attribute with a value containing a given substring.
            allProperties = ('attribute_contain',attribute_name.replace('*',''),value)
            
        elif '~' in attribute_name:
            # Selects elements that have the specified attribute with a value containing a given word, delimited by spaces.
            allProperties = ('attribute_contain',attribute_name.replace('~',''),value)
        elif '$' in attribute_name:
            # Selects elements that have the specified attribute with a value ending exactly with a given string. The comparison is case sensitive.
            allProperties = ('attribute_endwith',attribute_name.replace('$',''),value)
        elif '^' in attribute_name:
            # Selects elements that have the specified attribute with a value beginning exactly with a given string.
            allProperties = ('attribute_startwith',attribute_name.replace('^',''),value)
        else:
            allProperties = ('attribute',attribute_name,value)
    
    if '#' in stripped_stmt:
        # Selects a single element with the given id attribute.
        match = re.search(r'#\w+', stripped_stmt)
        if match:
            allProperties = ('attribute','id',match.group().replace('#',''))
        
    return allProperties

def parseSelectorWithParsel(selector:str):
    selectorString = selector.replace("'","\\'")
    selectorString = f"$'{selectorString}'"
    response = muterun_js(os.path.join(SRC_DIR,"selectorParser.js"), arguments=f"""{selectorString}""")
    response = response.stdout.decode("utf-8")
    if not response:
        return []
    nodeList = json.loads(response)
    return nodeList

print(getSelectedHTMLFormInputs("#foo > .bar + div.k1.k2 [id^='baz']:hello(2):not(:where(#yolo))::before"))