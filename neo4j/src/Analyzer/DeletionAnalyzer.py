from .Analyzer import AbstractAnalyzer, LawType, ComplianceScore
from typing import List
from Detectors.Runtime import SECURITY_DETECTOR_MANAGER
from PathAnalyzerHelper import *
from .ComplianceFinding import ComplianceFinding
from Detectors.Scores import ScoreType

class DeletionAnalyzer(AbstractAnalyzer):
    def __init__(self):
        """Detector intended to be a catch-all for various PHP functions that explicitly write to a file.

        Args:
            graph (py2neo.Graph): The PHP AST graph from Neo4j to check.
        """
        super().__init__(LawType.DELETION)
    def check_compliance(self):
        storageFindings = getPersonalDataStorageFindings()
        for finding,personalTypes in storageFindings:
            evidence = None
            complianceScore=ComplianceScore.INCOMPLIANT
            if finding.parent_name == "WordPressStorageDetector":
                pass
            elif finding.score.score_type == ScoreType.DATABASE:
                table_name = finding.score.categories.get("table_name", None)
                operations: List[str] = finding.score.categories.get("operations", None)
                # Operations contains with "AST_SQL_INSERT" or "AST_SQL_UPDATE", so if operations
                # is not empty, then the DB operation is inserting or updating information.
                if table_name and operations:
                    pass
            self.findings.append(ComplianceFinding(finding,evidence))
        tableCreationFindings = getTableCreationFindings()
        tableDeletionFindings = getTableDeletionFindings()
        for finding in tableCreationFindings:
            table_name = finding.score.categories.get("table_name", None)
            foundEvidence = False
            for f in tableDeletionFindings:
                table_name2 = f.score.categories.get("table_name", None)
                if table_name==table_name2:
                    self.findings.append(ComplianceFinding(finding,f,ComplianceScore.COMPLIANT))
                    foundEvidence = True
            if not foundEvidence:
                self.findings.append(ComplianceFinding(finding,None,ComplianceScore.INCOMPLIANT))
    