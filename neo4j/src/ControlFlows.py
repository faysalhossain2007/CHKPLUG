from typing import Any, Dict, List, Optional


class PropositionNode:
    def __init__(self, nodeID: int, expression, flag: List[str]):
        self.id: int = int(nodeID)
        # if the proposition is a variable that has dataflow, then the expression represents when the variable is first assigned (root of data flow)
        self.expression = expression
        self.lefthand: Optional[PropositionNode] = None
        self.righthand: Optional[PropositionNode] = None
        self.operator: Optional[str] = None

        # used in case the proposition is a call that wraps other propositions inside (e.g. upper($variable))
        self.wrappedNode: Optional[PropositionNode] = None

        self.flag: List[str] = flag
        # if the proposition is a variable that has dataflow and that the dataflow has relevant control flow, the condition list is recorded here.
        self.conditions = None

    def __repr__(self) -> str:
        ids = [self.id]
        expressions = [self.expression]
        lefthandIDs = []
        righthandIDs = []
        operators = [self.operator]
        wrappedNodes = []
        flags = [self.flag]
        conditions = [self.conditions]

        queue = []
        if self.lefthand:
            queue.append(self.lefthand)
            lefthandIDs.append(self.lefthand.id)
        else:
            lefthandIDs.append(-1)
        if self.righthand:
            queue.append(self.righthand)
            righthandIDs.append(self.righthand.id)
        else:
            righthandIDs.append(-1)
        if self.wrappedNode:
            queue.append(self.wrappedNode)
            wrappedNodes.append(self.wrappedNode.id)
        else:
            wrappedNodes.append(-1)

        while queue:
            current = queue.pop(0)

            ids.append(current.id)
            expressions.append(current.expression)
            operators.append(current.operator)
            flags.append(current.flag)
            conditions.append(current.conditions)
            if current.lefthand:
                queue.append(current.lefthand)
                lefthandIDs.append(current.lefthand.id)
            else:
                lefthandIDs.append(-1)
            if current.righthand:
                queue.append(current.righthand)
                righthandIDs.append(current.righthand.id)
            else:
                righthandIDs.append(-1)
            if current.wrappedNode:
                queue.append(current.wrappedNode)
                wrappedNodes.append(current.wrappedNode.id)
            else:
                wrappedNodes.append(-1)

        d = {
            "ID": ids,
            "Expression": expressions,
            "Left hand": lefthandIDs,
            "Right hand": righthandIDs,
            "Operator": operators,
            "Wrapped Node": wrappedNodes,
            "flag": flags,
            "conditions": conditions,
        }

        return str(d)


class ControlFlowNode:

    all_nodes: Dict[int, Any] = {}

    def __init__(
        self,
        nodeID: int,
        expression: str,
        value: str,
        flags: List[str] = [],
        rootPropositionNode: Optional[PropositionNode] = None,
        *args,
        **kwargs
    ):
        self.id: int = int(nodeID)
        self.expression: str = expression
        self.value: str = value
        self.flags: List[str] = flags
        self.rootPropositionNode: Optional[PropositionNode] = rootPropositionNode

    def __repr__(self) -> str:
        print("-" * 15)
        d = {
            "ID": [self.id],
            "Expression": [self.expression],
            "Value": [self.value],
            "Flags": [self.flags],
            "Root_proposition_node": [
                self.rootPropositionNode.id if self.rootPropositionNode else None
            ],
        }

        print(d)
        print("==<Proposition nodes below:>")

        print(self.rootPropositionNode)
        return ""


class ControlFlowPath:
    """Used to store information of the individual paths created by data flow traversals"""

    def __init__(self, path: List[ControlFlowNode] = []):
        self.id: int = -1
        self.path: List[ControlFlowNode] = path

    def insertNode(self, node: ControlFlowNode):
        """Insert a node into the path. The node is converted to a tuple and then self.insert is called.

        Args:
            node (DataNode): Node to append to the path.
        """
        assert isinstance(node, ControlFlowNode)
        self.path.append(node)

    def insertPath(self, path: List[ControlFlowNode]):
        """Append a path to the end of this path.

        Args:
            path (List[ControlFlowNode]): Path to append to the end of the current path.
        """
        self.path.extend(path)

    def __repr__(self) -> str:
        ids = []
        expressions = []
        # truthValues: List[str] = []
        flags = []
        for i in self.path:
            ids.append(i.id)
            expressions.append(i.expression)
            # truthValues.append(i.truthValue)
            flags.append(i.flags)
        d = {
            "ID": ids,
            "Expression": expressions,
            # "Truth Value": truthValues,
            "Flag": flags,
        }
        return str(d)

    def copy(self):
        """Return a deep copy of the path.

        Returns:
            ControlFlowPath: Copied path.
        """
        return ControlFlowPath(
            list(
                [
                    ControlFlowNode(n.id, n.expression, n.value, n.flags, n.rootPropositionNode)
                    for n in self.path
                ]
            )
        )

    def getFlags(self) -> List[str]:
        """Get all flags in the control flow path.

        Returns:
            List[str]: List of string flags.
        """
        flags = []
        for node in self.path:
            flags.extend(node.flags)
        return flags
