from netfilterqueue import NetfilterQueue
from scapy.all import *
import optparse
import sys
import time
import csv
from pathlib import Path
sys.path.insert(1, '../')
import helper

class Flow_Label_CC:

	END_SIGNATURE = 524288

	def __init__(self, filepath, chunks, role, number_clean_packets, length_stego_packets):
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

		self.number_clean_packets = number_clean_packets
		self.length_stego_packets = length_stego_packets
		self.stegotime = True
		self.clean_counter = 0

		self.number_of_repititions = 20
		self.number_of_repititions_done = 0

		self.sent_received_chunks = 0		# Contains the number of sent/received chunks/injected packets (depending on the role of the class).
		self.nfqueue = NetfilterQueue()		# The netfilter object which is bound on the netfilter queue.
		self.exfiltrated_data = []			# A list with signatures and the corresponding injected values.

		# ------------------- MEASUREMENT VARIABLES ------------------- #
		self.starttime_stegocommunication = 0.0
		self.endtime_stegocommunication = 0.0
		self.injection_exfiltration_time_sum = 0.0

	def inject(self, packet):

		'''
	   	The inject method of the sender, which is bound the the netfilter queue NETFILTERQUEUE_NUMBER.
	   	This method injects the content of chunks into the traffic class field of parameter packet.
	   	The injected content is saved into self.injected_data. Then it increments the counter self.sent_received_chunks and self.received_packets by 1.
	   	Then the payload of the altered packet is set. This is done considering the policy parameter.

	   	:param Packet packet: The NetfilterQueue Packet object packet, where the exfiltrated data is injected into the traffic class field.
	   	'''
		if self.number_of_repititions_done < self.number_of_repititions:
			tmp1 = time.perf_counter()
			pkt = IPv6(packet.get_payload())
			if self.sent_received_chunks < len(self.int_chunks):
				if self.sent_received_chunks == 0:
					self.starttime_stegocommunication = time.perf_counter()

				if self.stegotime:
					pkt.tc = helper.get_md5_signature_at_indices(self.sent_received_chunks, helper.USED_INDICES_OF_HASH_TRAFFIC_CLASS)
					#with TC == 255, problems will occurs in the receinving side
					if pkt.tc == 255:
						pkt.tc = 254
					pkt.fl = int(self.chunks[self.sent_received_chunks], 2)
					self.exfiltrated_data.append((pkt.fl, pkt.tc))

					self.sent_received_chunks += 1

					if self.length_stego_packets > 0:
						self.stegotime = self.sent_received_chunks % self.length_stego_packets != 0
				else:
					self.clean_counter += 1
					self.stegotime = self.clean_counter % self.number_clean_packets == 0
			else:
				pkt.fl = Flow_Label_CC.END_SIGNATURE
				self.endtime_stegocommunication = time.perf_counter()
				self.stegotime = True
				self.number_of_repititions_done += 1
				self.statistical_evaluation_sent_packets()
				self.write_csv()
				self.injection_exfiltration_time_sum = 0
				self.sent_received_chunks = 0
				self.exfiltrated_data = []
			
			packet.set_payload(bytes(pkt))
			if self.sent_received_chunks != 0:
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1
		packet.accept()


	def exfiltrate(self, packet):
		'''
	   	The exfiltration method of the receiver, which is bound the the netfilter queue NETFILTERQUEUE_NUMBER.
	   	This method exfiltrates the content of the traffic class field of the received packet.
	   	The content is saved into self.exfiltrated_data. Then it increments the counter self.sent_sent_received_chunks and self.received_packets by 1. If nothing
	   	is exfiltrated only the last counter is incremented. The list self.chunks_int_exfiltration is used to check if the message is correctly exfiltrated.

	   	:param Packet packet: The NetfilterQueue Packet object which is received and can be transformed into Scapy IPv6()-packet.
	   	'''
		if self.number_of_repititions_done < self.number_of_repititions:
			tmp1 = time.perf_counter() 
			pkt = IPv6(packet.get_payload())
			if self.stegotime:
				tmp = helper.get_md5_signature_at_indices(self.sent_received_chunks, helper.USED_INDICES_OF_HASH_TRAFFIC_CLASS)
				if tmp == 255:
					tmp = 254
				if pkt.tc == tmp:
					if self.sent_received_chunks == 0:
						self.starttime_stegocommunication = time.perf_counter()
					self.exfiltrated_data.append((pkt.fl, pkt.tc))
					self.sent_received_chunks += 1
					if self.length_stego_packets > 0:
						self.stegotime = self.sent_received_chunks % self.length_stego_packets != 0
			else:
				self.clean_counter += 1
				self.stegotime = self.clean_counter % self.number_clean_packets == 0
			if pkt.fl == Flow_Label_CC.END_SIGNATURE:
					self.endtime_stegocommunication = time.perf_counter()
					self.stegotime = True
					self.number_of_repititions_done += 1
					self.statistical_evaluation_received_packets()
					self.write_csv()
					self.injection_exfiltration_time_sum = 0
					self.sent_received_chunks = 0
					self.exfiltrated_data = []
			

			if self.sent_received_chunks != 0:
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1
		packet.accept()
	
	def write_csv(self):
		
		filename="flow_label_cc_" + self.filepath.replace("../", "", 1) + "_role_" + self.role + "_clean_packets_" + str(self.number_clean_packets) + "_number_stegopackets_" + str(self.length_stego_packets) + ".csv"
		csv_file = Path(filename)
		file_existed=csv_file.is_file()

		with open(filename, 'a', newline='') as file:
			writer = csv.writer(file)

			if not file_existed:
				if self.role == 'sender':
					writer.writerow(["Sent Chunks (Packets)", "Duration of Stegocommunication (ms)", "Average Injection Time (ms)", "Bandwidth (bits/s)"])
				else:
					writer.writerow(["Received Chunks (Packets)", "Duration of Stegocommunication (ms)", "Average Exfiltration Time (ms)", "Bandwith (bits/s)", "Failures", "Error Rate (Failures/Packet)", "Successfully transmitted Message (%)"])
			
			if self.role == 'sender':
				writer.writerow([self.sent_received_chunks, \
					round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2), \
					round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2), \
					round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Flow Label"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)])  			
			else:
				failures = 0
				index_first_failure = -1 

				# Failure Calculation via Index 
				for x in range(len(self.exfiltrated_data)):
					if self.exfiltrated_data[x][0] != self.int_chunks[x]:
						failures += 1

				# Determine first index of failure for Succesfully Transmitt
				for x in range(len(self.exfiltrated_data)):
					if self.exfiltrated_data[x][0] != self.int_chunks[x]:
						index_first_failure = x
						break

				if index_first_failure == -1:
					index_first_failure = self.sent_received_chunks
					
				writer.writerow([self.sent_received_chunks, \
					round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2), \
					round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2), \
					round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Flow Label"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2), \
					failures, \
					round(failures/self.sent_received_chunks, 2), \
					# round(100 - ((failures/self.sent_received_chunks) * 100), 2)])
					round((index_first_failure/self.sent_received_chunks) * 100, 2)])


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
		print('- Number of Repitions: ' + str(self.number_of_repititions))	
		print('- Signature in field: Traffic Class')			
		print('- Exfiltrated File: ' + self.filepath)
		if self.number_clean_packets > 0 and self.length_stego_packets > 0:
			buf = ""
			for x in range(2):
				for y in range(self.length_stego_packets):
					buf += "S "
				for y in range(self.number_clean_packets):
					buf += "C "	
			print('- Length Clean Packets: ' + str(self.number_clean_packets))		
			print('- Length Stego Packets: ' + str(self.length_stego_packets))		
			print('  ==> Packet Pattern (S=stego, C=clean): ' + buf + "...")		
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
		print("- Number of Repition: " + str(self.number_of_repititions_done) + "/" + str(self.number_of_repititions))
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

		parser.add_option(
		'-p',
		'--consecutive_clean',
		help='specify the number of clean packets inserted before/after stegopackets (default: 0)',
		default=0,
		action='store',
		type='int',
		dest='consecutive_clean')

		parser.add_option(
		'-l',
		'--consecutive_stego',
		help='specify the burst length of stegopackets (default: 0)',
		default=0,
		action='store',
		type='int',
		dest='consecutive_stego')

		settings, args = parser.parse_args(argv)

		if settings.filepath is None:
			raise ValueError("ValueError: filepath must be specified!")

		if settings.role not in ["sender", "receiver"]:
			raise ValueError("ValueError: role can be only sender or receiver!")

		if settings.consecutive_clean != 0 and settings.consecutive_stego == 0 or settings.consecutive_clean == 0 and settings.consecutive_stego != 0:
			print("settings.consecutive_clean and settings.consecutive_stego are set to 0!")
			settings.consecutive_clean = 0
			settings.consecutive_stego = 0
		
		return settings, args

	def __str__(self):
		return str(self.__dict__)


if __name__ == "__main__":

	settings, args = Flow_Label_CC.process_command_line(sys.argv)

	flow_label_cc = Flow_Label_CC(settings.filepath, helper.read_binary_file_and_return_chunks(settings.filepath, helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Flow Label"]), settings.role, settings.consecutive_clean, settings.consecutive_stego)

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


