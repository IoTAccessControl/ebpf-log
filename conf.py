# coding: utf-8

__author__ = "fripSide"

"""

"""


class Config:
	PLAT_WEBTHINGS = "WebThings"
	PLAT_AZURE = "AzureIoT"
	PLAT_SMARTTHINGS = "SmartThings"

	def __init__(self):
		self.debug = True
		# ebpf config
		self.http_filter_ebpf = "ebpf/tcp_filter.c"
		self.http_ebpf_section = "handle_pkt"

		# net config
		self.platform = Config.PLAT_WEBTHINGS
		self.net_interface = "lo" # eth0
		self.byte_order = "big"

		# ip filters config
		self.host_ip = "192.168.33.10"
		self.gateway_addr = ["192.168.33.10:8080"]
		self.device_nodes = [
			"192.168.33.15:8888", # webthings node
		]
		self.target_servers = self.gateway_addr + self.device_nodes
		self.hy_debug()

	def hy_debug(self):
		self.net_interface = "eth1"

CONFIG = Config()