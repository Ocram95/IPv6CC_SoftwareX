import random
import hashlib
import subprocess
import sys
import os

TITLE_APPEND_IP6TABLES = '##### APPENDING IP6TABLES RULE #####'
TITLE_DELETE_IP6TABLES = '##### DELETING IP6TABLES RULE #####'

PRESHARED_SEED = "SIMARGL"

BEGIN_RANGE_RANDOM_INT = 1
END_RANGE_RANDOM_INT = 10000

NETFILTER_QUEUE_NUMBER = 1

SOURCE_IPv6_ADDRESS = "" 
DESTINATION_IPv6_ADDRESS = ""


USED_INDICES_OF_HASH_FLOW_LABEL = [0,1,2,3,4]
USED_INDICES_OF_HASH_TRAFFIC_CLASS = [0,1]

PROTOCOL_HEADER_LENGTHS_IN_BITS = {
	"IPv4": 20, 
	"IPv6": 40, 
	"TCP": 20, 
	"UDP": 8, 
	"Ethernet": 14
}

PROTOCOL_IDS = {
	"IPv4": 4, 
	"TCP": 6, 
	"UDP": 17, 
	"IPv6": 41, 
	"Ethernet": 143 		#temporary, expires on 2021-01-31
}

IPv6_HEADER_FIELD_LENGTHS_IN_BITS = {
	"Version": 4, 
	"Traffic Class": 8, 
	"Flow Label": 20, 
	"Payload Length": 16, 
	"Next Header": 8, 
	"Hop Limit": 8, 
	"Source Address": 128, 
	"Destination Address": 128 
}

TCP_FLAGS = {
	"FIN": 1,
	"SYN": 2,
	"RESET": 4,
	"PUSH": 8,
	"ACK": 16,
	"URG": 32,
	"ECN": 64,
	"CONG": 128,
	"NONCE": 256
}

def read_binary_file_for_n_packets_and_return_chunks(path_to_binary_file, n, field_length_in_bits):

	content_in_bits = ''

	bits_read = 0
	bits_needed = n * field_length_in_bits
	
	st = os.stat(path_to_binary_file)
	bits_of_file = st.st_size * 8

	with open(path_to_binary_file, 'rb') as content_file:
		
		# if needed read the file multiple times complete
		for x in range(int(bits_needed/bits_of_file)):
			content = content_file.read()
			for k in content:
				content_in_bits += "{0:08b}".format(k)
			content_file.seek(0)
			bits_read += bits_of_file
		
		# read the rest whole bits of the file
		rest = bits_needed - bits_read

		content = content_file.read(int(rest/8))
		for k in content:
			content_in_bits += "{0:08b}".format(k)
		bits_read += int(rest/8) * 8

		# read the rest of the last needed byte
		rest = bits_needed - bits_read
		content_in_bits += format(int.from_bytes(content_file.read(1), byteorder='big'), '#010b')[2:rest+2]

	return [content_in_bits[i:i+field_length_in_bits] for i in range(0, len(content_in_bits), field_length_in_bits)]


def read_binary_file_and_return_chunks(path_to_binary_file, field_length, character_stuffing="false", escape_value=None):

	chunks = []

	with open(path_to_binary_file, 'rb') as content_file:
		content = content_file.read()
	content_in_bits = ""
	for k in content:
		content_in_bits += "{0:08b}".format(k)

	chunks = [content_in_bits[i:i+field_length] for i in range(0, len(content_in_bits), field_length)]

	if character_stuffing:
		tmp = []
		for x in chunks:
			tmp.append(x)
			if int(x,2) == escape_value:
				tmp.append(x)
		chunks = tmp

	return chunks

def character_unstuff(list_to_unstuff, escape_value):

	one_skipped = False

	tmp = []

	for k in range(len(list_to_unstuff)):
		if list_to_unstuff[k] == escape_value:
			if not one_skipped:
				one_skipped = True
				continue
			else:
				one_skipped = False
				tmp.append(list_to_unstuff[k])
		else:
			tmp.append(list_to_unstuff[k])

	return tmp 

def chunk_the_phrase(some_phrase, field_length):

	appended_binary_values = ''
	for k in some_phrase:
		appended_binary_values += format(ord(k), '08b')
	return [appended_binary_values[i:i+field_length] for i in range(0, len(appended_binary_values), field_length)]

def get_md5_signature_at_indices(signature_number, indices):

	signature = ''
	random.seed(PRESHARED_SEED)
	
	for x in range(signature_number):
		random.randint(BEGIN_RANGE_RANDOM_INT, END_RANGE_RANDOM_INT)
	hashed_random_integer = hashlib.md5(str(random.randint(BEGIN_RANGE_RANDOM_INT, END_RANGE_RANDOM_INT)).encode('utf-8')).hexdigest()
	
	for y in range(len(indices)):
		signature += hashed_random_integer[indices[y]]

	return int(signature, 16)

def append_ip6tables_rule(sender):
	print('')
	print(TITLE_APPEND_IP6TABLES)
	if sender:
		args = ['sudo', 'ip6tables', '-A', 'OUTPUT', '-s', SOURCE_IPv6_ADDRESS, '-d', DESTINATION_IPv6_ADDRESS, '-j', 'NFQUEUE', '--queue-num', str(NETFILTER_QUEUE_NUMBER)]
	else:
		args = ['sudo', 'ip6tables', '-A', 'INPUT', '-s', SOURCE_IPv6_ADDRESS, '-d', DESTINATION_IPv6_ADDRESS, '-j', 'NFQUEUE', '--queue-num', str(NETFILTER_QUEUE_NUMBER)]
	#p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	p = subprocess.Popen(args)
	stdout, stderr = p.communicate()
	print('')


def delete_ip6tables_rule(sender):
	print('')
	print(TITLE_DELETE_IP6TABLES)
	if sender:
		args = ['sudo', 'ip6tables', '-D', 'OUTPUT', '-s', SOURCE_IPv6_ADDRESS, '-d', DESTINATION_IPv6_ADDRESS, '-j', 'NFQUEUE', '--queue-num', str(NETFILTER_QUEUE_NUMBER)]
	else:
		args = ['sudo', 'ip6tables', '-D', 'INPUT', '-s', SOURCE_IPv6_ADDRESS, '-d', DESTINATION_IPv6_ADDRESS, '-j', 'NFQUEUE', '--queue-num', str(NETFILTER_QUEUE_NUMBER)]
	p = subprocess.Popen(args)
	stdout, stderr = p.communicate()
	print('')
