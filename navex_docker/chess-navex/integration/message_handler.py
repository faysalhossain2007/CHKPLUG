from chess_integration_framework.proto_msg_handler import ProtoMsgHandler
import chess_messages.ar.chess_message_pb2 as chess_message
 
 
class MsgHandlerRequest(ProtoMsgHandler):
    def __init__(self, ss_name: str):
        super().__init__(chess_message.Request)
        self.ss_name = ss_name
     
    # Request message has to be consumed in this method
    def handle_message(self, msg_in) -> bool:
        print("{}: Message Received Type: {}, Source: {}, Send_Time: {}, Data: {}".
              format(self.ss_name, super().get_message_class(), msg_in.ssSource, msg_in.time, msg_in.msg))
        return True
 
class MsgHandlerResponse(ProtoMsgHandler):
    def __init__(self, ss_name: str):
        super().__init__(chess_message.Response)
        self.ss_name = ss_name
 
    # Response message has to be consumed in this method
    def handle_message(self, msg_in) -> bool:
        print("{}: Message Received Type: {}, Source: {}, Target: {}, Send_Time: {}, Data: {}".
              format(self.ss_name, super().get_message_class(), msg_in.ssSource, msg_in.ssTarget,
                     msg_in.time, msg_in.msg))
        return True
