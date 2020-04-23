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
        self.net_interface = "lo"
        self.byte_order = "big"

CONFIG = Config()