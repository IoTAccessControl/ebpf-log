# coding: utf-8
from conf import CONFIG
from tcp.protocol_parser import RequestHandler
from detecting.log_context import LogWriter

__author__ = "fripSide"

"""
TODO:
1. 提取三种请求，写到log
2. 实时用决策树来判断log
3. 尝试xdp程序截断请求
"""

class BlockAction:

	def __init__(self):
		self.block = True
		self.device_addr = ""
		self.devcie_id = ""
		self.action = ""
		self.property = ""

class BlockRulesManager:

	def __init__(self):
		pass

	def block(self, rule):
		pass

	def unblock(self, rule):
		pass


class PolicyMonitor:

	def __init__(self):
		self.request_handler = RequestHandler()
		self.log_writer = LogWriter()
		self.__init_platform()

	def __init_platform(self):
		if CONFIG.platform == CONFIG.PLAT_WEBTHINGS:
			from detecting.webthings import WebThingsRequestHandler
			self.request_handler = WebThingsRequestHandler()

	def process_data(self, tcp_endpoint, payload):
		log_entry = self.request_handler.process(tcp_endpoint, payload)
		if log_entry:
			self.record_log(log_entry)
			self.anormal_detecting(log_entry)

	def record_log(self, log_entry):
		self.log_writer.append_log(log_entry)

	def anormal_detecting(self, log_entry):
		pass

block_rules = BlockRulesManager()
policy_monitor = PolicyMonitor()
