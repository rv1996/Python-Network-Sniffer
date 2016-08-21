import textwrap
import struct
import socket

def main():
	con = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))

	while True:
		raw_data, addr = con.recvfrom(65535)
		dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
		print('Ethernet Frame:')
		print("Destination: {}, source: {}, protocol: {}, data :{}".format(dest_mac, src_mac, eth_proto,data))



#unpack ethernet frame
def ethernet_frame(data):
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H',data[:14])
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# return porperly formatted MAC address
# i.e AA:BB:CC:DD:EE
def get_mac_addr(bytes_addr):
	bytes_str = map('{:02x}'.format,bytes_addr)
	mac_addr = ':'.join(bytes_str).upper()
	return mac_addr


def ipv4_packet(data):
	pass


if __name__ == '__main__':
	main();
