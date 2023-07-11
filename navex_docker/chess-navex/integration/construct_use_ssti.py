import chess_messages.ar.chess_message_pb2 as chess_message
from chess_integration_framework.ssti import SSTI
import logging
 
 
# Created Topic (from earlier)
request_reply_topic = Topic(name="test_topic", msg_classes=msg_classes)
 
# Created ConnectionInfo (from earlier)
connection_info: ConnectionInfo = ConnectionInfo(my_pub=my_pub, other_pubs=[other_pub_1, other_pub_2])
 
# Create a logger
logger = logging.getLogger(ss_name)
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
sh = logging.StreamHandler(sys.stdout)
sh.setLevel(logging.NOTSET)
sh.setFormatter(formatter)
logger.addHandler(sh)
 
# Create an SSTI
rr_ssti: SSTI = SSTI(topic=request_reply_topic, conn_info=connection_info, logger=logger)
 
# Construct handlers
request_handler = MsgHandlerRequest(ss_name=ss_name)
response_handler = MsgHandlerResponse(ss_name=ss_name)
 
# Add Message handlers to the SSTI
# Note: when Message handlers are handed to the SSTI it should be assumed that
#   these objects now belong to the SSTI
rr_ssti.add_msg_handler(request_handler)
rr_ssti.add_msg_handler(response_handler)
 
# Get SSTI poll running in separate thread
rr_ssti.start()
 
# Send Messages with the SSTI
req_send = chess_message.Request()
req_send.ssSource = self.ss_name
req_send.time = 123
req_send.msg = "test Request"
rr_ssti.send(msg_out=req_send)
 
res_send = chess_message.Response()
res_send.ssSource = self.ss_name
res_send.ssTarget = "any"
res_send.time = 124
res_send.msg = "test Response"
rr_ssti.send(msg_out=res_send)
 
# Get SSTI poll running in separate thread
rr_ssti.start()
 
 
# Send Messages with the SSTI
req_send = chess_message.Request()
req_send.ssSource = self.ss_name
req_send.time = 123
req_send.msg = "test Request"
rr_ssti.send(msg_out=req_send)
 
# Note: we noticed that after the first send a slight delay (e.g. 200 ms is required)
# Before sending future messages, after this first delay messages can be sent as frequently
# As ZMQ supports plan to fix for 10/11 release
 
res_send = chess_message.Response()
res_send.ssSource = self.ss_name
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