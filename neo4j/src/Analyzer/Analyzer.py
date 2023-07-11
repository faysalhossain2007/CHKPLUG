
from typing import List
from abc import ABC, abstractmethod
from .ComplianceFinding import ComplianceFinding
from traceback import print_exc
from enum import Enum

class AbstractAnalyzer(ABC):
    def __init__(self,lawType) -> None:
        #lawType is the type of law that is being analyzed
        self.lawType = lawType
        #finding stores a point of interest that requires a compliance, and the counterpart evidence to support compliance/incompliance
        #this finding generally uses pairs of Detector findings to show compliance/incompliance.
        self.findings:List[ComplianceFinding] = []
        #compliance is a general score as to whether the law is violated
        self.compliance = True

        self.recommendation = ''
    @abstractmethod
    def check_compliance(self):
        raise NotImplementedError("Not implemented.")
    
    def run(self) -> list:
        """Run the analyzer

        Returns:
            list of compliance findings for the currently checked law.
        """
        self.findings.clear()
        try:
            self.check_compliance()
        except Exception as e:
            print(f"Error in {type(self).__name__}:")
            print_exc()
        return self.findings

class ComplianceScore(Enum):
    INCOMPLIANT = "incompliant"
    CAN_BE_IMPROVE = 'compliant but can be improved'
    COMPLIANT = 'compliant'
class LawType(Enum):
    DELETION = "deletion"
    ACCESS = "access"
    CONSENT = "consent"
    THIRD_PARTY = "third_party"

