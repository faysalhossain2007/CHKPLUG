# Specify the message classes on this topic (order matters)
str_classes = [str]
 
# Create a topic
str_topic = Topic(name="str_topic", msg_classes=str_classes)
 
# Constructed SSTI (use instructions from before to create connection_info and logger)
str_ssti: SSTI = SSTIBuilder.build(topic=str_topic, conn_info=connection_info, logger=logger)
 
# Construct handlers
str_msg_handler: MsgHandler = MsgHandler()
 
# Add Message handler to the SSTI
str_ssti.add_msg_handler(str_msg_handler)
 
# Get SSTI poll running
str_ssti.start()
 
# Send Messages with the SSTI
str_ssti.send(msg_out="test string message", msg_handler=str_handler)
 
# Stop SSTI poll
str_ssti.stop()
str_ssti.join()
 
# Remove Message handlers from the SSTI
str_ssti.remove_msg_handler(str_msg_handler)