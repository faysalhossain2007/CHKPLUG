# GDPR Checker - PersonalData.py
# Patrick Thomas pwt5ca
# Created 210317

import re
from typing import Callable, Dict, Iterable, List

from Settings import *



class PersonalDataMatcher:

    NO_MATCH: List[str] = []  # Returned when there is no match to a string.
    _categories: Dict[str, Callable] = dict()
    REG_EX: List[str] = []
    # @staticmethod
    # def isNodePersonal(nodeID):
    #     """Check if a node is personal data by checking multiple metrics:
    #     1. if it flows from a source that has a personal data tag, it is personal
    #     2. if it is a direct retrieval call for personal info, it's personal
    #     3. if it is a dynamic wp function with sensitive input, it's also personal
    #     4. if the variable name is personal, it's potentially personal data.
    #     """
    #     nodeType = getNodeType(nodeID)
    #     if nodeType=='AST_CALL':
    #         finding = getFinding(nodeID)
    #         print(finding)
    #         if finding and finding.parent_name == "WordPressRetrievalDetector":
    #             callName = finding.get_call_name()


    @staticmethod
    def register_category(name: str, regex_pattern: str):
        """Register a category of personal data with the system.

        Args:
            name (str): Name to register. Should be human-friendly.
            regex_pattern (str): A pattern to match this category. Needs to be regex-compilable.
        """
        PersonalDataMatcher._categories[name] = re.compile(regex_pattern, re.IGNORECASE).match
        PersonalDataMatcher.REG_EX.append(regex_pattern)

    @staticmethod
    def determine_category(name: str) -> List[str]:
        """Determine the categories of a variable name.

        Args:
            name (str): Name of a variable or any string.

        Returns:
            str: The list of names of the category of personal data, or PersonalDataMatcher.NO_MATCH if no matches.
        """
        if not name:
            return []
        name = name.lower()
        categories = []
        for category, matcher in PersonalDataMatcher._categories.items():
            if matcher(name):
                categories.extend(list(category))

        if categories:
            return categories
        else:
            return PersonalDataMatcher.NO_MATCH

    @staticmethod
    def determine_categories_from_list(name_list: Iterable[str]) -> List[str]:
        """Given a list of strings, determine the PII matches for each string and return an
        aggregated list of all PII types in the passed strings

        Args:
            name_list (Iterable[str]): List of names

        Returns:
            List[str]: List of PII types
        """
        if not name_list:
            return []
        categories = []
        for name in name_list:
            for category, matcher in PersonalDataMatcher._categories.items():
                if matcher(name):
                    categories.extend(list(category))
        if categories:
            return categories
        else:
            return []

    @staticmethod
    def get_pii_list() -> List[str]:
        """Get a list of personal data categories.

        Returns:
            List[str]: Alphabetically-sorted list of personal data categories.
        """
        temp =  sorted(list(PersonalDataMatcher._categories.keys()))
        pii_list = []
        for i in temp:
            pii_list.extend(list(i))
        return pii_list
    @staticmethod
    def get_pii_list_regex() -> List[str]:
        return PersonalDataMatcher.REG_EX


PersonalDataMatcher.register_category(DATA_TYPE_EMAIL, ".*(email).*")
PersonalDataMatcher.register_category(DATA_TYPE_FIRST_NAME, ".*(first.*name).*")
PersonalDataMatcher.register_category(DATA_TYPE_LAST_NAME, ".*(last.*name).*")
PersonalDataMatcher.register_category(DATA_TYPE_PASSWORD, ".*([^a-zA-Z]pass).*")
PersonalDataMatcher.register_category(DATA_TYPE_ADDRESS, ".*(address).*")
PersonalDataMatcher.register_category(DATA_TYPE_COUNTRY, ".*(country).*")
PersonalDataMatcher.register_category(DATA_TYPE_STATE, ".*([^a-zA-Z]state).*")
PersonalDataMatcher.register_category(DATA_TYPE_ZIPCODE, ".*(zipcode).*")
PersonalDataMatcher.register_category(DATA_TYPE_POSTCODE, ".*(postcode).*")
PersonalDataMatcher.register_category(DATA_TYPE_CITY, ".*([^a-zA-Z]city).*")
PersonalDataMatcher.register_category(DATA_TYPE_BIRTHDAY, ".*([^a-zA-Z]birth).*")
# PersonalDataMatcher.register_category(DATA_TYPE_USER, ".*(user(.|)(name|)).*")
PersonalDataMatcher.register_category(DATA_TYPE_USER, ".*(user.*name).*")
PersonalDataMatcher.register_category(DATA_TYPE_IP, ".*([^a-zA-Z]ip(.*address.*|[^a-zA-Z]|.*addr.*)).*")
PersonalDataMatcher.register_category(DATA_TYPE_PHONE, ".*(phone).*")


def isPersonalString(string: str) -> List[str]:
    """Check if a string matches a known PII name description.

    Args:
        string (str): String to check if it is named in a similar pattern as other personal data.

    Returns:
        str: The name of the suspected PII category, otherwise "" if there is no match.
    """

    return PersonalDataMatcher.determine_category(string)


def isPersonalNodeInPath(path):
    """Return if the data we are tracking is personal data (deprecated)
    Argument:
            takes a path, and compares the last node to the previous node (if applicable).
    Output:
            Boolean: Does the node we are tracking represent/contain personal information?

    NOTE: need to check if data is just identifier (e.g. userID) through checking the parameter . Use callee (what API) and childnum (which parameter) to determine.
    """
    dataNodeList = path.toDataNodeList()
    lastNode = dataNodeList[-1]
    try:
        previous = dataNodeList[-2]
    except IndexError:
        return isPersonalString(lastNode.varName)

    previousIsPersonal = previous.personal
    if previousIsPersonal:
        if lastNode.varName == previous.varName:
            return previousIsPersonal
        else:
            return isPersonalString(lastNode.varName)
        # elif getNodeType(lastNode.id) == 'AST_ASSIGN':
        # 	graph = getGraph()
        # 	query = f"""MATCH (n)-[:PARENT_OF]->(m) WHERE n.id = {lastNode[0]} AND m.type = 'AST_ARRAY' RETURN m"""
        # 	result = graph.run(cypher = query).data()
        # 	if result:
        # 		return previousIsPersonal
    elif lastNode.varName == previous.varName:
        return False
    return isPersonalString(lastNode.varName)


def nameContainsPersonal(name: str) -> bool:
    """Return whether a name is probably PII or not.

    Args:
            name (str): The name to check

    Returns:
            bool: True if the name is likely personally identifying. False otherwise.
    """
    return PersonalDataMatcher.determine_category(name) != ""
