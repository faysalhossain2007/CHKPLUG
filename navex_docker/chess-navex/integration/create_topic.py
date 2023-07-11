from chess_integration_framework.topic import Topic
import chess_messages.ar.chess_message_pb2 as chess_message
 
# Specify the message classes on this topic (order matters)
msg_classes = [chess_message.Request, chess_message.Response]
 
# Create a topic
request_reply_topic = Topic(name="test_topic", msg_classes=msg_classes)