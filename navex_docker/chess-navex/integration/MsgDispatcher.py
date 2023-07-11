from chess_integration_framework.connection_info import ConnectionInfo
from chess_integration_framework.publisher_info import PublisherInfo
from chess_integration_framework.proto_msg_handler import ProtoMsgHandler
import chess_messages.ar.chess_message_pb2 as chess_message
import chess_messages.ar.chess_message_pb2 as chess_message
from chess_integration_framework.ssti import SSTI
from chess_integration_framework.topic import Topic
import chess_messages.ar.chess_message_pb2 as chess_message
import logging
import sys
import time


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

class MsgDispatcher:

    def __init__(self):
        # Create information about my subsystem's publisher
        # Note: your publisher host should be on your machine as the framework will attempt to bind
        self.my_pub: PublisherInfo = PublisherInfo(pub_host="localhost", pub_port=5000)
        # Create information about other subsystems' publishers
        # Connect to yourself for this simple test so you see your own messages
        self.my_recv_1: PublisherInfo = PublisherInfo(pub_host="localhost", pub_port=5000)
        # Connect to another publisher (In this case we're connecting to another subsystem's publisher that's not there)
        self.my_recv_2: PublisherInfo = PublisherInfo(pub_host="localhost", pub_port=5001)

        # Specify the message classes on this topic (order matters)
        self.msg_classes = [chess_message.Request, chess_message.Response]
        # Create a topic
        self.request_reply_topic = Topic(name="test_topic", msg_classes=self.msg_classes)

        # Create a connection info object
        self.connection_info: ConnectionInfo = ConnectionInfo(my_pub=self.my_pub, other_pubs=[self.my_recv_1, self.my_recv_2])

        # Created Topic (from earlier)
        # request_reply_topic = Topic(name="test_topic", msg_classes=msg_classes)

        # Created ConnectionInfo (from earlier)
        # connection_info: ConnectionInfo = ConnectionInfo(my_pub=my_pub, other_pubs=[my_recv_1, my_recv_2])

        # Create a logger
        self.logger = logging.getLogger("logger")
        self.logger.setLevel(logging.DEBUG)
        self.formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        self.sh = logging.StreamHandler(sys.stdout)
        self.sh.setLevel(logging.NOTSET)
        self.sh.setFormatter(self.formatter)
        self.logger.addHandler(self.sh)

    def main_message(self, message):

        # Create an SSTI
        rr_ssti: SSTI = SSTI(topic=self.request_reply_topic, conn_info=self.connection_info, logger=self.logger)

        # Construct handlers
        request_handler = MsgHandlerRequest(ss_name="msghandlerrequest")
        response_handler = MsgHandlerResponse(ss_name="msghandlerresponse")

        # Add Message handlers to the SSTI
        # Note: when Message handlers are handed to the SSTI it should be assumed that
        #   these objects now belong to the SSTI
        rr_ssti.add_msg_handler(request_handler)
        rr_ssti.add_msg_handler(response_handler)

        # Get SSTI poll running in separate thread
        rr_ssti.start()

        # Send Messages with the SSTI
        req_send = chess_message.Request()
        req_send.ssSource = "uic"
        req_send.time = 123
        req_send.msg = "test Request"
        rr_ssti.send(msg_out=req_send)

        res_send = chess_message.Response()
        res_send.ssSource = "uic"
        res_send.ssTarget = "any"
        res_send.time = 124
        res_send.msg = "test Response"
        rr_ssti.send(msg_out=res_send)

        # Get SSTI poll running in separate thread
        """
        rr_ssti.start()
    
        # Send Messages with the SSTI
        req_send = chess_message.Request()
        req_send.ssSource = self.ss_name
        req_send.time = 123
        req_send.msg = "test Request"
        rr_ssti.send(msg_out=req_send)
        """
        # Note: we noticed that after the first send a slight delay (e.g. 200 ms is required)
        # Before sending future messages, after this first delay messages can be sent as frequently
        # As ZMQ supports plan to fix for 10/11 release

        res_send = chess_message.Response()
        res_send.ssSource = "response"
        res_send.ssTarget = "any"
        res_send.time = 124
        res_send.msg = "test Response"
        rr_ssti.send(msg_out=res_send)

        # Note may want to delay before stopping polling to ensure message received
        time.sleep(5)

        # Stop SSTI poll
        rr_ssti.stop_poll()
        rr_ssti.join()

        # Remove Message handlers from the SSTI
        rr_ssti.remove_msg_handler(request_handler)
        rr_ssti.remove_msg_handler(response_handler)
