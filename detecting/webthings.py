# coding: utf-8
from conf import CONFIG
from detecting.log_context import LogEntry, JsonData, DataField
from tcp.protocol_parser import RequestHandler, HTTPParser, WebSocketParser, MTQQParser
import requests
import json
import logging
import pprint

__author__ = "fripSide"

"""
1. 从当前WebThings请求中提取数据，格式化成统一的log

2. 暂时只考虑最简单情况，一个tcp包就能发完一次操作的完整数据

3. 实现一个最简demo，保存log，并拦截异常请求，湿度 > thershold 时拦截全部请求
	a). 连接时保存设备信息
	b). 
"""

class WebThingsDevice(JsonData):

	node_addr = DataField("node_addr")
	dev_addr = DataField("dev_addr")
	title = DataField("title")
	description = DataField("description")
	properties = DataField("properties")

	def set_from_raw(self, url, raw_data):
		self.node_addr = url
		self.dev_addr = raw_data.get("base")
		self.description = raw_data.get("description")
		self.properties  = raw_data.get("properties")
		self.title = raw_data.get("title", "Unknow Device")
		return self.dev_addr 


class WebThingsLogParser:

	def __init__(self):
		pass

	def parse_http_log(self, tcp_endpoint, data):
		pass

	def __extract_device_addr(self, client_id):
		# "http---192.168.33.15-8888-1"
		# "http://192.168.33.15:8888/0"
		dev = client_id.replace("http---", "http://")
		dev = dev.split("-")
		dev_addr = "{}:{}/{}".format(*dev)
		return dev_addr

	def parse_things_node_json_log(self, tcp_endpoint, data):
		""" 
		1. things node 向 gateway server 同步数据
		2. gateway server 向 用户web同步数据
		"""
		log_entry = LogEntry()
		if tcp_endpoint.ip_src == CONFIG.host_ip:
			log_entry.host_addr = "{}:{}".format(tcp_endpoint.ip_src, tcp_endpoint.port_src)
			log_entry.target_addr = "{}:{}".format(tcp_endpoint.ip_dst, tcp_endpoint.port_dst)
		else: # tcp_endpoint.ip_dst == CONFIG.host_ip:
			log_entry.target_addr = "{}:{}".format(tcp_endpoint.ip_src, tcp_endpoint.port_src)
			log_entry.host_addr = "{}:{}".format(tcp_endpoint.ip_dst, tcp_endpoint.port_dst)
		client_id = data.get("id")
		if client_id:
			# print(self.__extract_device_addr(client_id))
			log_entry.target_device = self.__extract_device_addr(client_id)
		log_entry.action = data.get("messageType")
		log_entry.properties.update(data.get("data"))
		return log_entry


log_parser = WebThingsLogParser()

class WebThingsRequestHandler(RequestHandler):
	PROTO_HTTP = "http"
	PROTO_WS = "websocket"
	PROTO_MQTT = "MQTT"

	def __init__(self):
		self.http_parsers = {}
		self.ws_parser = WebSocketParser()
		self.parser_map = {}
		self.device_nodes = {}
		self.__init_parsers()
		self.__init_device_nodes()

	def __init_parsers(self):
		self.parser_map = {
			self.PROTO_HTTP : self.__process_http,
			self.PROTO_WS   : self.__process_websocket,
			self.PROTO_MQTT : self.__process_mqtt,
		}

	def __init_device_nodes(self):
		"""
		从node网关获取设备信息
		"""
		try:
			for addr in CONFIG.device_nodes:
				url = f"http://{addr}"
				r = requests.get(url)
				data = json.loads(r.text)
				for dev in data:
					webthing_device = WebThingsDevice()
					key = webthing_device.set_from_raw(url, dev)
					# print(key, webthing_device.to_json())
					self.device_nodes[key] = webthing_device
		except Exception as ex:
			logging.error(f"Failed to fetch device info from device nodes: {ex.args}")
		# exit(0)

	def process(self, tcp_endpoint, payload):
		proto = self.check_protocol_type(payload)
		parser = self.parser_map.get(proto)
		if parser:
			return parser(tcp_endpoint, payload)
		else:
			print("unsupport protocol", tcp_endpoint, payload)

	def check_protocol_type(self, payload):
		ws = int.from_bytes(b'\x81', CONFIG.byte_order)

		if payload[0] == ws:
			return self.PROTO_WS

		ws = b"WebSocket"
		if ws in payload:
			print("Is WebSocket")
		# http
		if HTTPParser.is_http_pkt(payload):
			return self.PROTO_HTTP
		return None

	def __process_http(self, tcp_endpoint, payload):
		print("parse http", payload)

	def __process_websocket(self, tcp_endpoint, payload):
		data = self.ws_parser.parse(payload)
		data = json.loads(data)
		# print("parse websocket", tcp_endpoint)
		log_entry = log_parser.parse_things_node_json_log(tcp_endpoint, data)
		# print(log_entry.to_json())
		return log_entry
	
	def __process_mqtt(self, tcp_endpoint, payload):
		pass
