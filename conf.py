# coding: utf-8

__author__ = "fripSide"

"""

"""


class Config:
    
    def __init__(self):
        self.debug = True
        
        # http config
        self.http_filter_ebpf = "ebpf/tcp_filter.c"
        self.http_ebpf_section = "handle_pkt"
        self.net_interface = "lo" # eth0
        self.byte_order = "big"

        # self.hy_debug()

    def hy_debug(self):
        self.net_interface = "eth1"

CONFIG = Config()