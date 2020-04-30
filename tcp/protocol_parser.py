# coding: utf-8
import struct
# try to import C parser then fallback in pure python parser.
try:
	from http_parser.parser import HttpParser
except ImportError:
	from http_parser.pyparser import HttpParser

__author__ = "fripSide"

class RequestHandler:

	def process(self, tcp_endpoint, payload):
		print("No Handler: ", tcp_endpoint, payload)

class HTTPParser:
	
	def __init__(self):
		self.parser = HttpParser()
		self.body = []

	@staticmethod
	def is_http_pkt(payload):
		if ((payload[:3] == b'GET') or (payload[:4] == b'POST')
			or (payload[:4] == b'HTTP') or (payload[:3] == b'PUT')
			or (payload[:6] == b'DELETE') or (payload[:4] == b'HEAD')):
			return True
		return b"\r\n" in payload

	def parse(self, payload):
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

class WebSocketParser:

	def __init__(self):
		pass

	def parse(self, payload):
		"""
		https://zhuanlan.zhihu.com/p/72289051
		"""
		fin = payload[0] >> 7
		opcode = payload[0] & 0b1111 
		mask_flag = payload[1] >> 7
		data_length = payload[1] & 0b01111111

		data_offset = 2
		if data_length == 126:
			data_offset = 4     # 如果数据长度126，则之后的2个字节也是长度信息
		elif data_length == 127:
			data_offset = 10 	# 如果数据长度127，则之后的8个字节也是长度信息

		if mask_flag == 1:
			data = b""
			masks = payload[data_offset:data_offset+4]
			data_offset += 4
			raw_data = payload[data_offset:]
			i = 0
			for B in raw_data:
				tmp = B ^ masks[i % 4]         # 将数据的每个字节与掩码进行异或运算
				data += struct.pack('B', tmp)  # 然后将值打包为二进制
		else:
			data = payload[data_offset:]

		# print(mask_flag, data_length, data)
		return data.decode('utf8')

class MTQQParser:

	pass
