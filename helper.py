import random
import hashlib
import subprocess
import sys
import os

TITLE_APPEND_IP6TABLES = '##### APPENDING IP6TABLES RULE #####'
TITLE_DELETE_IP6TABLES = '##### DELETING IP6TABLES RULE #####'

SECRET_PHRASE1 = "SIMARGL is one of the greatest EU-Projects ever!"
SECRET_PHRASE2 = "SIMARGL is the best!"
SECRET_PHRASE3 = "We will conquer the world with our CCs!"

PRESHARED_SEED = "SIMARGL"

BEGIN_RANGE_RANDOM_INT = 1
END_RANGE_RANDOM_INT = 10000

NETFILTER_QUEUE_NUMBER = 1

SOURCE_IPv6_ADDRESS = "2a00:1620:80:8::a497" # CNR Server
DESTINATION_IPv6_ADDRESS = "2a01:4f8:140:51c1::2" # SIMARGL Server


USED_INDICES_OF_HASH_FLOW_LABEL = [0,1,2,3,4]
USED_INDICES_OF_HASH_TRAFFIC_CLASS = [0,1]

# Variable needed only for payload_length_CC
MAX_MTU_LENGTH_IN_BITS = 1500
MAX_PAYLOAD_LENGTH = 1480

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

#new line
def calculate_all_signature(packet_list):
	signature_list = []
	final_signature_list = []
	random.seed(PRESHARED_SEED)

	for x in range(len(packet_list)):
		signature_list.append(hashlib.md5(str(random.randint(BEGIN_RANGE_RANDOM_INT, END_RANGE_RANDOM_INT)).encode('utf-8')).hexdigest())
	for y in range(len(signature_list)):
		final_signature_list.append(int(signature_list[y][:2], 16))
	return final_signature_list

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

# def start_iperf3_server():
# 	args = ['iperf3', '-s', '-B', DESTINATION_IPv6_ADDRESS]
# 	p = subprocess.Popen(args, shell=False, stdout=DEVNULL)
	
# 	print("\n")
# 	for y in range(len('#' + IPERF3_START_MESSAGE + '(PID: ' + str(p.pid) + ')#')):
# 		print("#", end='')
# 	print('\n#' + IPERF3_START_MESSAGE + '(PID: ' + str(p.pid) + ')#')
# 	for y in range(len('#' + IPERF3_START_MESSAGE + '(PID: ' + str(p.pid) + ')#')):
# 		print("#", end='')
# 	print("\n")

# def kill_iperf3_server(pid):
# 	args = ['kill', str(pid)]
# 	subprocess.Popen(args, shell=False, stdout=DEVNULL)

# 	print("\n")
# 	for y in range(len('#' + IPERF3_KILL_MESSAGE + '(PID: ' + str(pid) + ')#')):
# 		print("#", end='')
# 	print('\n#' + IPERF3_KILL_MESSAGE + '(PID: ' + str(pid) + ')#')
# 	for y in range(len('#' + IPERF3_KILL_MESSAGE + '(PID: ' + str(pid) + ')#')):
# 		print("#", end='')
# 	print("\n")

# def start_iperf3_client(sending_time):
# 	args = ['iperf3', '-c', DESTINATION_IPv6_ADDRESS, '-t', str(sending_time)]
# 	subprocess.Popen(args)

# if __name__ == "__main__":

# 	filepath = sys.argv[1]
# 	number_of_packets = int(sys.argv[2])
# 	field_length_in_bits = int(sys.argv[3])
# 	print(read_binary_file_for_n_packets_and_return_chunks(filepath, number_of_packets, field_length_in_bits))

	# buf = read_binary_file_and_return_chunks(sys.argv[1], 10)
	# print(buf)
	# start_iperf3_server()
	# start_iperf3_client(10)
	# kill_iperf3_server(str(11323))
	# print(get_md5_signature_at_indices(2, [0,3]))
	# append_ip6tables_rule(sender=True)
	# delete_ip6tables_rule(sender=True)
