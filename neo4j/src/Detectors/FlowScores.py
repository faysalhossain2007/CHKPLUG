# GDPR Checker
# Patrick Thomas pwt5ca
# Sep 24 2020

from dataclasses import dataclass, field
from enum import IntEnum, auto, unique
from typing import *

TRUST_GENERIC = True


@unique
class FlowSecurity(IntEnum):
    NOT_SAVED = auto()
    NO_SECURITY_SAVED = auto()
    UNKNOWN_SECURITY_SAVED = auto()
    LOW_SECURITY_SAVED = auto()
    HIGH_SECURITY_SAVED = auto()

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    @staticmethod
    def create_from_finding(is_state_of_the_art: bool, is_maintained: bool, is_generic: bool):
        if is_generic:
            return FlowSecurity.UNKNOWN_SECURITY_SAVED
        elif is_state_of_the_art and is_maintained:
            return FlowSecurity.HIGH_SECURITY_SAVED
        elif is_state_of_the_art ^ is_maintained:
            return FlowSecurity.LOW_SECURITY_SAVED
        else:
            return FlowSecurity.NO_SECURITY_SAVED


@dataclass
class FlowScore:
    path_id: int
    flow_overall: FlowSecurity
    encryption: List[str] = field(default_factory=list)

    def calc_score(self) -> float:
        """Calculate the score of a data flow.

        ## Rubric

        -   flow_overall
            -   NOT_SAVED: -1.0 (doesn't count)
            -   NO_SECURITY_SAVED: 0.0 (strictly fails)
                -   security function used is not maintained or not state-of-the-art
            -   LOW_SECURITY_SAVED: 0.5 (not entirely secure, maybe stops some attacks or increases the complexity somehow)
                -   security function used to be state-of-the-art but is now outdated or deprecated
            -   HIGH_SECURITY_SAVED: 1.0 (most secure usage, up-to-date)
                -   security function used is both maintained or and state-of-the-art according to governmental standards like FIPS-140
            -   UNKNOWN_SECURITY_SAVED: 1.0 or 0.0 (depends on configuration)
                -   attempts to catch unrecognized cryptography methods

        Returns:
            float: The numerical score between 0.0 and 1.0.
        """

        criteria = {}

        # Calculate flow overall
        if self.flow_overall == FlowSecurity.NO_SECURITY_SAVED:
            criteria["flow_overall"] = 0.0
        elif self.flow_overall == FlowSecurity.LOW_SECURITY_SAVED:
            criteria["flow_overall"] = 0.5
        elif self.flow_overall == FlowSecurity.HIGH_SECURITY_SAVED:
            criteria["flow_overall"] = 1.0
        elif self.flow_overall == FlowSecurity.UNKNOWN_SECURITY_SAVED:
            criteria["flow_overall"] = 1.0 if TRUST_GENERIC else 0.0

        score = 0.0
        for s in criteria.values():
            score += s
        if len(criteria) > 0:
            score /= len(criteria)

        return score
