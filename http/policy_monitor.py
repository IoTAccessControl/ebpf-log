# coding: utf-8

# try to import C parser then fallback in pure python parser.
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

__author__ = "fripSide"

class HTTPHandler:
	
	def __init__(self):
		self.parser = HttpParser()
		self.body = []

	def process(self, tcp_endpoint, payload):
		p = self.parser
		recved = len(payload)
		nparsed = p.execute(payload, recved)
		assert(recved == nparsed)
		# if p.is_headers_complete():
		# 	print(p.get_headers())

		if p.is_partial_body():
			self.body.append(p.recv_body())

		if p.is_message_complete():
			return self.body

		return p.is_message_complete()

	def reset(self):
		self.body = []

class PolicyManager:

	def __init__(self):
		self.http_handlers = {}
		self.http_requests = []

	def append_http_data(self, tcp_endpoint, payload):
		# print("add data to ", tcp_endpoint, payload)
		if not tcp_endpoint in self.http_handlers:
			self.http_handlers[tcp_endpoint] = HTTPHandler()
		handler = self.http_handlers[tcp_endpoint]
		if handler.process(tcp_endpoint, payload):
			self.add_http_record(tcp_endpoint, handler)
			handler.reset()

	def add_http_record(self, tcp_endpoint, handler):
		print(tcp_endpoint, handler.body)

policy_manager = PolicyManager()

