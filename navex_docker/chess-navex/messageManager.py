import pika

class MessageManager:

	def __init__(self, host, queueName):
		self.host = host
		self.queueName = queueName
		self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=self.host))
		self.channel = self.connection.channel()

		self.channel.queue_declare(queue=self.queueName)

	def sendMessage(self, message):
		self.channel.basic_publish(exchange='', routing_key=self.queueName, body=message)

	def startReceiving(self, callback):
		self.channel.basic_consume(queue=self.queueName, on_message_callback=callback, auto_ack=True)

		self.channel.start_consuming()

	def receiveMessage(self):
		method_frame, headr_frame, body = self.channel.basic_get(queue = self.queueName)

		if method_frame is None or method_frame.NAME == "Basic.GetEmpty":
			return None

		self.channel.basic_ack(delivery_tag = method_frame.delivery_tag)
		return body

	def closeConnection(self):
		self.connection.close()
		

