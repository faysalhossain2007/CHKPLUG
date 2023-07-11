from chess_integration_framework.utils.topic_definitions_file import TopicDefinitionsFile, TopicDefinitionsFileBuilder
from chess_integration_framework.connection_info import ConnectionInfo
from chess_integration_framework.topic import Topic
 
 
subsystem_name = "ss_1"
topics_filename = "data/chess_topics.json"
 
# Parse Topic Configuration JSON
topic_definitions: TopicDefinitionsFile = TopicDefinitionsFileBuilder.parse_topics(ss_name=ss_name, topics_filename=topics_filename)
 
# Extract Topic and ConnectionInfo
topic_name = "Request_Response"
topic: Topic = topic_definitions.get_topic(topic_name=topic_name)
conn_info: ConnectionInfo = topic_definitions.get_connection_info(topic_name=topic_name)
 
# This information can now be used to construct an SSTI for this topic