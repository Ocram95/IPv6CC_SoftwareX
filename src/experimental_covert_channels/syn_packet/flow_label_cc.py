from netfilterqueue import NetfilterQueue
from scapy.all import *
import optparse
import sys
import time
import csv
from pathlib import Path
sys.path.insert(1, '../../')
import helper

class Flow_Label_CC:

	def __init__(self, filepath, chunks, role):
		'''
		Constructor for sender and receiver of a Traffic Class Covert Channel
		:param list chunks: A list of strings in binary format, which shall be injected into the traffic class field.
		:param policy: injection policy: n stego-packets every n clear packets
		:raises ValueError: if the chunks is an empty list.
		'''
		self.chunks = chunks 				
		self.int_chunks = [int(x,2) for x in self.chunks] 				
		self.role = role
		self.filepath = filepath

		self.sent_received_chunks = 0		# Contains the number of sent/received chunks/injected packets (depending on the role of the class).
		self.nfqueue = NetfilterQueue()		# The netfilter object which is bound on the netfilter queue.
		self.exfiltrated_data = []			# A list with signatures and the corresponding injected values.
		self.known_flows = {}

	def inject(self, packet):
		pkt = IPv6(packet.get_payload())
		if pkt.nh == helper.PROTOCOL_IDS["TCP"]:
			this_flow = (pkt.src, pkt.dst, pkt.fl)
			if this_flow not in self.known_flows:
				if self.sent_received_chunks < len(self.int_chunks):
					secret_value = int(self.chunks[self.sent_received_chunks], 2)
					self.sent_received_chunks += 1
					self.known_flows[this_flow] = secret_value
					self.exfiltrated_data = secret_value
			pkt.fl = known_flows[this_flow]
		
		packet.set_payload(bytes(pkt))
		packet.accept()


	def exfiltrate(self, packet):
		pkt = IPv6(packet.get_payload())
		if pkt.nh == helper.PROTOCOL_IDS["TCP"]:
			this_flow = (pkt.src, pkt.dst, pkt.fl)
			if this_flow not in self.known_flows:
					self.sent_received_chunks += 1
					self.known_flows[this_flow] = 1
					self.exfiltrated_data = pkt.fl

		packet.accept()
	
	
	def start_sending(self):
		'''
	   	Binds the inject method to the netfilter queue with its specific number and runs the callback function. If the user press Ctrl + c
	   	the inject method is unbind.  
	   	'''

		self.nfqueue.bind(helper.NETFILTER_QUEUE_NUMBER, self.inject)
		try:
			self.nfqueue.run()
		except KeyboardInterrupt:
			print("The exfiltration is stopped.")
		self.nfqueue.unbind()

	def start_receiving(self):
		'''
	   	Binds the exfiltrate method to the netfilter queue with its specific number and runs the callback function. If the user press Ctrl + c
	   	the inject method is unbind.  
	   	'''
		self.nfqueue.bind(helper.NETFILTER_QUEUE_NUMBER, self.exfiltrate)
		try:
			self.nfqueue.run()
		except KeyboardInterrupt:
			print("The exfiltration is stopped.")
		self.nfqueue.unbind()


	def print_start_message(self):
		print('')
		if self.role == "sender":
			print('################## SIGNATURE FLOW LABEL CC SENDER ##################')
		else:
			print('################## SIGNATURE FLOW LABEL CC RECEIVER ##################')			
		print('- Exfiltrated File: ' + self.filepath)		
		print('- Number of Chunks: ' + str(len(self.chunks)))	
		if self.role == "sender":
			print('################## SIGNATURE FLOW LABEL CC SENDER ##################')
		else:
			print('################## SIGNATURE FLOW LABEL CC RECEIVER ##################')
		print('')
		if self.role == "sender":
			print('Injection in covert channel is started...')
			print('Stop injection with CTRL+C.')
		else:
			print('Exfiltration from covert channel is started...')
			print('Stop exfiltration with CTRL+C...')
		print('')

	def statistical_evaluation_sent_packets(self):
		
		print('')
		print('##################### ANALYSIS SENT DATA #####################')
		print("- Sent Chunks: " + str(self.sent_received_chunks) + "/" + str(len(self.int_chunks)))
		print("- Duration of Stegocommunication: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Injection Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Bandwidth: " + str(round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Flow Label"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		print("- Injected data == Chunks: " + str([x[0] for x in self.exfiltrated_data] == self.int_chunks))
		print('##################### ANALYSIS SENT DATA #####################')
		print('')

	def statistical_evaluation_received_packets(self):
		
		failures = 0
		index_first_failure = -1 

		# Failure Calculation via Index 
		for x in range(len(self.exfiltrated_data)):
			if self.exfiltrated_data[x][0] != self.int_chunks[x]:
				failures += 1
				
		# Failure Calculation 1st Index 
		
		for x in range(len(self.exfiltrated_data)):
			if self.exfiltrated_data[x][0] != self.int_chunks[x]:
				index_first_failure = x
				break

		if index_first_failure == -1:
			index_first_failure = self.sent_received_chunks

		print('')
		print('##################### ANALYSIS RECEIVED DATA #####################')
		print("- Number of Repition: " + str(self.number_of_repititions_done) + "/" + str(self.number_of_repititions))
		print("- Received Chunks: " + str(self.sent_received_chunks) + "/" + str(len(self.int_chunks)))
		print("- Duration of Stegocommunication: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Exfiltration Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Bandwidth: " + str(round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Flow Label"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		print("- Exfiltrated data == Chunks: " + str([x[0] for x in self.exfiltrated_data] == self.int_chunks) + " (" + str(failures) + " Failures)")
		print("- Error Rate: " + str(round(failures/self.sent_received_chunks, 2)) + " Failures/Packet")
		print("- Successfully transmitted Message: " + str(round((index_first_failure/self.sent_received_chunks) * 100, 2)) + "%")
		print('##################### ANALYSIS RECEIVED DATA #####################')
		print('')

	def process_command_line(argv):
		'''
		Parses the command line arguments for the Covert Channel and returns the settings to run the specific covert channel.
		'''
		parser = optparse.OptionParser()

		parser.add_option(
		'-r',
		'--role',
		help='specify the sender or the receiving role of the script: {sender|receiver}',
		action='store',
		type='string',
		dest='role')

		parser.add_option(
		'-f',
		'--file',
		help='specify the file which shall be read and exfiltrated',
		action='store',
		type='string',
		dest='filepath')

		settings, args = parser.parse_args(argv)

		if settings.filepath is None:
			raise ValueError("ValueError: filepath must be specified!")

		if settings.role not in ["sender", "receiver"]:
			raise ValueError("ValueError: role can be only sender or receiver!")
		
		return settings, args

	def __str__(self):
		return str(self.__dict__)


if __name__ == "__main__":

	settings, args = Flow_Label_CC.process_command_line(sys.argv)

	flow_label_cc = Flow_Label_CC(settings.filepath, helper.read_binary_file_and_return_chunks(settings.filepath, helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Flow Label"]), settings.role)

	if flow_label_cc.role == "sender":
		helper.append_ip6tables_rule(sender=True)
	else:
		helper.append_ip6tables_rule(sender=False)

	flow_label_cc.print_start_message()
	
	if flow_label_cc.role == "sender":
		flow_label_cc.start_sending()
	else:
		flow_label_cc.start_receiving()
	
	if flow_label_cc.role == "sender":
		helper.delete_ip6tables_rule(sender=True)
	else:
		helper.delete_ip6tables_rule(sender=False)


