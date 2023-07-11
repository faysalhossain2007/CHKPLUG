from chess_integration_framework.msg_handler_interface import MsgHandlerInterface
 
 
class MsgHandler(MsgHandlerInterface):
    def __init__(self):
        self.my_type: type = str
 
    def serialize(self, msg_out: str) -> bytes:
        return msg_out.encode("utf-8")
     
    # Message bytes have to be consumed in this method
    def deserialize_and_handle_message(self, serialized_msg: bytes) -> bool:
        return self.handle_message(serialized_msg.decode("utf-8"))
 
    def get_message_class(self) -> type:
        return self.my_type
 
    def handle_message(self, msg_in: str) -> bool:
        print(msg_in)
        return True