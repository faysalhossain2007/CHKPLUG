import random


class NodeIdGenerator:

    @staticmethod
    def generate_id():
        return random.getrandbits(32)

