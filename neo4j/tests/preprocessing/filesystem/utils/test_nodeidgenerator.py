from src.preprocessing.utils.NodeIdGenerator import NodeIdGenerator


def test_generate_node():
    nid = NodeIdGenerator.generate_id()
    assert type(nid) is int
