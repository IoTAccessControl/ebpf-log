# coding: utf-8

# try to import C parser then fallback in pure python parser.
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

__author__ = "fripSide"

class HTTPLog:

	def __init__(self):
		pass

class HTTPHandler:
	
	def __init__(self):
		self.parser = HttpParser()
		self.body = []

	def process(self, tcp_endpoint, payload):
		p = self.parser
		recved = len(payload)
		nparsed = p.execute(payload, recved)
		assert(recved == nparsed)
		# print(recved, nparsed)
		# if p.is_headers_complete():
			# print(p.get_headers())

		if p.is_partial_body():
			# print("is_partial_body")
			self.body.append(p.recv_body())

		# if p.is_message_complete():
			# print("message is complete")
		return p.is_message_complete()

	def reset(self):
		self.parser = HttpParser()
		self.body = []

class PolicyMonitor:

	def __init__(self):
		self.http_handlers = {}
		self.http_requests = []

	def process_data(self, tcp_endpoint, payload):
		print(tcp_endpoint, payload)

	def append_http_data(self, tcp_endpoint, payload):
		# print("add data to ", tcp_endpoint, payload)
		if not tcp_endpoint in self.http_handlers:
			self.http_handlers[tcp_endpoint] = HTTPHandler()
		handler = self.http_handlers[tcp_endpoint]
		# print(payload)
		if handler.process(tcp_endpoint, payload):
			self.add_http_record(tcp_endpoint, handler)
			handler.reset()

	def add_http_record(self, tcp_endpoint, handler):
		print(tcp_endpoint, handler.body)

policy_monitor = PolicyMonitor()

