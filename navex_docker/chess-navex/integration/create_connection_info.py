from chess_integration_framework.connection_info import ConnectionInfo
from chess_integration_framework.publisher_info import PublisherInfo
 
# Create information about my subsystem's publisher
# Note: your publisher host should be on your machine as the framework will attempt to bind
my_pub: PublisherInfo = PublisherInfo(pub_host="localhost", pub_port=5000)
# Create information about other subsystems' publishers
# Connect to yourself for this simple test so you see your own messages
my_recv_1: PublisherInfo = PublisherInfo(pub_host="localhost", pub_port=5000)
# Connect to another publisher (In this case we're connecting to another subsystem's publisher that's not there)
my_recv_2: PublisherInfo = PublisherInfo(pub_host="localhost", pub_port=5001)
 
# Create a connection info object
connection_info: ConnectionInfo = ConnectionInfo(my_pub=my_pub, my_recvs=[my_recv_1, my_recv_2])