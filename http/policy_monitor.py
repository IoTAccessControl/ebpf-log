# coding: utf-8

__author__ = "fripSide"

def http_paser(data):
    pass

# convert a bin string into a string of hex char
# helper function to print raw packet in hex
def toHex(s):
    lst = ""
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0' + hv
        lst = lst + hv
    return lst


# print str until CR+LF
def printUntilCRLF(s):
    print(s.split(b'\r\n')[0].decode())

# cleanup function
def cleanup():
    # get current time in seconds
    current_time = int(time.time())
    # looking for leaf having:
    # timestap  == 0        --> update with current timestamp
    # AGE > MAX_AGE_SECONDS --> delete item
    for key, leaf in bpf_sessions.items():
        try:
            current_leaf = bpf_sessions[key]
            # set timestamp if timestamp == 0
            if (current_leaf.timestamp == 0):
                bpf_sessions[key] = bpf_sessions.Leaf(current_time)
            else:
                # delete older entries
                if (current_time - current_leaf.timestamp > MAX_AGE_SECONDS):
                    del bpf_sessions[key]
        except:
            print("cleanup exception.")
    return

def handle_pkt(packet_str, bpf_sessions):
	#convert packet into bytearray
	packet_bytearray = bytearray(packet_str)

	# ethernet header length
	ETH_HLEN = 14

	# IP HEADER
	# https://tools.ietf.org/html/rfc791
	# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |Version|  IHL  |Type of Service|          Total Length         |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#
	# IHL : Internet Header Length is the length of the internet header
	# value to multiply * 4 byte
	# e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
	#
	# Total length: This 16-bit field defines the entire packet size,
	# including header and data, in bytes.

	# calculate packet total length
	total_length = packet_bytearray[ETH_HLEN + 2]                 # load MSB
	total_length = total_length << 8                              # shift MSB
	total_length = total_length + packet_bytearray[ETH_HLEN + 3]  # add LSB

	# calculate ip header length
	ip_header_length = packet_bytearray[ETH_HLEN]     # load Byte
	ip_header_length = ip_header_length & 0x0F        # mask bits 0..3
	ip_header_length = ip_header_length << 2          # shift to obtain length

	# retrieve ip source/dest
	ip_src_str = packet_str[ETH_HLEN + 12: ETH_HLEN + 16]  # ip source offset 12..15
	ip_dst_str = packet_str[ETH_HLEN + 16:ETH_HLEN + 20]   # ip dest   offset 16..19

	ip_src = int(toHex(ip_src_str), 16)
	ip_dst = int(toHex(ip_dst_str), 16)

	# TCP HEADER
	# https://www.rfc-editor.org/rfc/rfc793.txt
	#  12              13              14              15
	#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# |  Data |           |U|A|P|R|S|F|                               |
	# | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
	# |       |           |G|K|H|T|N|N|                               |
	# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#
	# Data Offset: This indicates where the data begins.
	# The TCP header is an integral number of 32 bits long.
	# value to multiply * 4 byte
	# e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

	# calculate tcp header length
	tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  # load Byte
	tcp_header_length = tcp_header_length & 0xF0    # mask bit 4..7
	tcp_header_length = tcp_header_length >> 2      # SHR 4 ; SHL 2 -> SHR 2

	# retrieve port source/dest
	port_src_str = packet_str[ETH_HLEN + ip_header_length:ETH_HLEN + ip_header_length + 2]
	port_dst_str = packet_str[ETH_HLEN + ip_header_length + 2:ETH_HLEN + ip_header_length + 4]

	port_src = int(toHex(port_src_str), 16)
	port_dst = int(toHex(port_dst_str), 16)

	# calculate payload offset
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length

	# payload_string contains only packet payload
	payload_string = packet_str[(payload_offset):(len(packet_bytearray))]
	# CR + LF (substring to find)
	crlf = b'\r\n'
	print(packet_str)

	# current_Key contains ip source/dest and port source/map
	# useful for direct bpf_sessions map access
	current_Key = bpf_sessions.Key(ip_src, ip_dst, port_src, port_dst)
