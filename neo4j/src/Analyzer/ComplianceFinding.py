from Detectors.Detectors import AbstractDetector
class ComplianceFinding():
    def __init__(self,finding,evidence,complainceScore, notes=None) -> None:
        self.finding:AbstractDetector.Finding = finding
        self.evidence:AbstractDetector.Finding = evidence
        self.complianceScore = complainceScore
        self.notes = notes