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

	#-------------- MAGIC VALUES --------------#
	START_MAGIC_VALUE = 255
	END_MAGIC_VALUE = 254
	#-------------- MAGIC VALUES --------------#

	def __init__(self, chunks, role, number_clean_packets, length_stego_packets):
		'''
		Constructor for sender and receiver of a Traffic Class cc.
		:param chunks: A string list containing the message to hide splitted in chunks.
		:param role: The role (i.e., sender or receiver) assigned.
		:param number_clean_packets: The length of the burst of non-stego packets.
		:param length_stego_packets: The lenght of the burst of stego packets
		'''
		self.chunks = chunks
		self.chunks_int = [int(x,2) for x in self.chunks]
		
		self.sent_received_chunks = 0
		self.nfqueue = NetfilterQueue()
		self.exfiltrated_data = []
		self.sent_packets = 0
		self.received_packets = 0
		self.role = role
		self.first_packet = True 
		self.start_exf = False
		self.dd = False
		self.separate_test = False
		
		self.number_of_repetitions = 10
		self.number_of_repetitions_done = 0

		self.number_clean_packets = number_clean_packets
		self.length_stego_packets = length_stego_packets
		self.stegotime = True
		self.clean_counter = 0

		# ------------------- MEASUREMENT VARIABLES ------------------- #
		self.starttime_stegocommunication = 0.0
		self.endtime_stegocommunication = 0.0
		self.injection_exfiltration_time_sum = 0.0

	def exfiltrate(self, packet):
		'''
	   	The exfiltration method of the receiver, which is bound the the netfilter queue NETFILTERQUEUE_NUMBER.
	   	This method extracts the value contained into the targeted field, accordingly to the sending mode used 
	   	(i.e., interleaved or burst).
	   	:param Packet packet: The NetfilterQueue Packet object.
	   	'''
		if self.number_of_repetitions_done < self.number_of_repetitions:
			
			if self.start_exf and self.stegotime: 
				tmp1 = time.perf_counter()

			pkt = IPv6(packet.get_payload())

			if not self.start_exf:
				self.start_exf = pkt.tc == Traffic_Class_CC.START_MAGIC_VALUE
				if self.start_exf:
					self.starttime_stegocommunication = time.perf_counter()
				
			# Exfiltration started
			else:
				# If the previous packet was an escape sequence
				if self.stegotime:
					if self.dd:
						# Unset delimiter detection Flag 
						self.dd = False
						# if the current packet is the end value => exfiltrate
						if pkt.tc == Traffic_Class_CC.END_MAGIC_VALUE:
							self.exfiltrated_data.append(pkt.tc)
							self.sent_received_chunks += 1
						# The previous packet gets interpreted as end value => stop exfiltration
						else:
							# Stop the Exfiltration
							self.start_exf = False
							self.endtime_stegocommunication = time.perf_counter()
							# Erase the Ending Value
							self.exfiltrated_data = self.exfiltrated_data[:-1]
							self.sent_received_chunks -= 1
							self.injection_exfiltration_time_sum += time.perf_counter() - tmp1
							self.number_of_repetitions_done += 1
							self.statistical_evaluation_received_packets()
							self.write_csv()
							self.received_packets = 0
							self.sent_received_chunks = 0
							self.clean_counter = 0
							self.exfiltrated_data = []
							self.stegotime = True
							self.starttime_stegocommunication = 0.0
							self.endtime_stegocommunication = 0.0
							self.injection_exfiltration_time_sum = 0.0
							if pkt.tc == Traffic_Class_CC.START_MAGIC_VALUE:
								self.starttime_stegocommunication = time.perf_counter()
								self.start_exf = True

					# Previous packet was not an escape sequence or ending value
					else:
						# Is an escape sequence detected?
						self.dd = pkt.tc == Traffic_Class_CC.END_MAGIC_VALUE
						self.exfiltrated_data.append(pkt.tc)
						self.sent_received_chunks += 1
						if self.length_stego_packets > 0:
							self.stegotime = self.sent_received_chunks % self.length_stego_packets != 0
				
					if self.start_exf:
						self.injection_exfiltration_time_sum += time.perf_counter() - tmp1

				else:
					self.clean_counter += 1
					self.stegotime = self.clean_counter % self.number_clean_packets == 0

		self.received_packets += 1
		packet.accept()

	def inject(self, packet):
		'''
	   	The inject method of the sender, which is bound the the netfilter queue NETFILTERQUEUE_NUMBER.
	   	This method injects the i-th chunks of the secret message (i.e., self.chunks[self.sent_received_chunks])
	   	into the targeted field, accordingly to the sending mode used (i.e., interleaved or burst).
	   	:param Packet packet: The NetfilterQueue Packet object packet.
	   	'''
		if self.number_of_repetitions_done < self.number_of_repetitions:
			if self.stegotime:
				tmp1 = time.perf_counter()
				pkt = IPv6(packet.get_payload())
				if self.sent_received_chunks < len(self.chunks):
					if self.first_packet:
						self.starttime_stegocommunication = time.perf_counter()
						pkt.tc = Traffic_Class_CC.START_MAGIC_VALUE
						self.first_packet = False
						packet.set_payload(bytes(pkt))
					else:
						pkt.tc = int(self.chunks[self.sent_received_chunks], 2)
						self.exfiltrated_data.append(pkt.tc)
						self.sent_received_chunks += 1
						packet.set_payload(bytes(pkt))

						if self.length_stego_packets > 0:
							if self.sent_received_chunks % self.length_stego_packets == 0:
								self.stegotime = False
							else:
								self.stegotime = True
					
					if not self.first_packet:
						self.injection_exfiltration_time_sum += time.perf_counter() - tmp1

				else:
					pkt.tc = Traffic_Class_CC.END_MAGIC_VALUE
					packet.set_payload(bytes(pkt))
					self.endtime_stegocommunication = time.perf_counter()
					self.injection_exfiltration_time_sum += time.perf_counter() - tmp1
					self.number_of_repetitions_done += 1
					self.first_packet = True
					self.statistical_evaluation_sent_packets()
					self.write_csv()
					self.sent_received_chunks = 0
					self.sent_packets = 0
					self.stegotime = True
					self.clean_counter = 0
					self.injection_exfiltration_time_sum = 0
					self.starttime_stegocommunication = 0
					self.endtime_stegocommunication = 0
					self.exfiltrated_data = []

			else:
				self.clean_counter += 1
				if self.clean_counter % self.number_clean_packets == 0:
					self.stegotime = True
					self.clean_counter = 0

		self.sent_packets += 1
		packet.accept()

	def start_sending(self):
		'''
	   	Binds the inject method to the netfilter queue with its specific number and runs the callback function. 
	   	If the user press Ctrl + c the inject method is unbind.  
	   	'''

		self.nfqueue.bind(helper.NETFILTER_QUEUE_NUMBER, self.inject)
		try:
			self.nfqueue.run()
		except KeyboardInterrupt:
			print('The injection is stopped.')
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
			print('The exfiltration is stopped.')
		self.nfqueue.unbind()

	def write_csv(self):
		
		filename="results_traffic_class_" + str(len(self.chunks_int)) + "_" + str(self.role) + ".csv"
		csv_file = Path(filename)
		file_existed = csv_file.is_file()

		with open(filename, 'a', newline='') as file:
			writer = csv.writer(file)

			if not file_existed:
				if self.role == 'sender':
					writer.writerow(["Stego-packets sent", "Duration of Stegocommunication (ms)", "Average Injection Time (ms)", "Bandwidth (bits/s)"])
				else:
					writer.writerow(["Stego-packets received", "Duration of Stegocommunication (ms)", "Average Exfiltration Time (ms)", "Bandwith (bits/s)", "Failures", "Successfully transmitted Message (%)"])
			
			if self.role == 'sender':
				writer.writerow([self.sent_received_chunks, \
					round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2), \
					round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2), \
					round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)])  			
			else:
				failures = 0
				index_first_failure = -1 

				# Count the failures
				if len(self.exfiltrated_data) <= len(self.chunks_int):
					for x in range(len(self.exfiltrated_data)):
						if self.exfiltrated_data[x] != self.chunks_int[x]:
							failures += 1
				else:
					for x in range(len(self.chunks_int)):
						if self.exfiltrated_data[x] != self.chunks_int[x]:
							failures += 1
				failures += abs(len(self.exfiltrated_data) - len(self.chunks_int))

				if failures != 0:
					# Receive less than expected => first failure can happen in the middle or after the last index
					if len(self.exfiltrated_data) < len(self.chunks_int):
						for x in range(len(self.exfiltrated_data)):
							if self.exfiltrated_data[x] != self.chunks_int[x]:
								index_first_failure = x
								break
						if index_first_failure == -1:
							index_first_failure = len(self.exfiltrated_data)
					# Receive exactly the amount which is expected => index must be in the middle
					elif len(self.exfiltrated_data) == len(self.chunks_int):
						for x in range(len(self.chunks_int)):
							if self.exfiltrated_data[x] != self.chunks_int[x]:
								index_first_failure = x
								break
					else:
					# Receive more than expected => first failure can happen in the middle or after the last index
						for x in range(len(self.chunks_int)):
							if self.exfiltrated_data[x] != self.chunks_int[x]:
								index_first_failure = x
								break
						if index_first_failure == -1:
							index_first_failure = len(self.chunks_int)

				if index_first_failure == -1:
					index_first_failure = self.sent_received_chunks

				writer.writerow([self.sent_received_chunks, \
					round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2), \
					round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2), \
					round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2), \
					round(failures), \
					round((index_first_failure/self.sent_received_chunks),2) * 100])
					
	def print_start_message(self):

		print('')
		if self.role == "sender":
			print('########## Mode: Start/Stop | CC: Traffic Class | Side: Covert Sender ##########')
		else:
			print('########## Mode: Start/Stop | CC: Traffic Class | Side: Covert Receiver ##########')
		print('- Number of Repetitions: ' + str(self.number_of_repetitions))		
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
			print('########## Mode: Start/Stop | CC: Traffic Class | Side: Covert Sender ##########')
		else:
			print('########## Mode: Start/Stop | CC: Traffic Class | Side: Covert Receiver ##########')
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
		print("- Number of Repetitions: " + str(self.number_of_repetitions_done) + "/" + str(self.number_of_repetitions))
		print("- Stego-packets sent: " + str(self.sent_received_chunks) + "/" + str(len(self.chunks_int)))
		print("- Duration of Stegocommunication: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Injection Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Bandwidth: " + str(round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		print("- Injected data == Chunks: " + str(self.exfiltrated_data == self.chunks_int))
		print('##################### ANALYSIS SENT DATA #####################')
		print('')

	def statistical_evaluation_received_packets(self):
		
		failures = 0
		index_first_failure = -1

		failures = 0
		index_first_failure = -1 

		# Count the failures
		if len(self.exfiltrated_data) <= len(self.chunks_int):
			for x in range(len(self.exfiltrated_data)):
				if self.exfiltrated_data[x] != self.chunks_int[x]:
					failures += 1
		else:
			for x in range(len(self.chunks_int)):
				if self.exfiltrated_data[x] != self.chunks_int[x]:
					failures += 1
		failures += abs(len(self.exfiltrated_data) - len(self.chunks_int))

		if failures != 0:
			# Receive less than expected => first failure can happen in the middle or after the last index
			if len(self.exfiltrated_data) < len(self.chunks_int):
				for x in range(len(self.exfiltrated_data)):
					if self.exfiltrated_data[x] != self.chunks_int[x]:
						index_first_failure = x
						break
				if index_first_failure == -1:
					index_first_failure = len(self.exfiltrated_data)
			# Receive exactly the amount which is expected => index must be in the middle
			elif len(self.exfiltrated_data) == len(self.chunks_int):
				for x in range(len(self.chunks_int)):
					if self.exfiltrated_data[x] != self.chunks_int[x]:
						index_first_failure = x
						break
			else:
			# Receive more than expected => first failure can happen in the middle or after the last index
				for x in range(len(self.chunks_int)):
					if self.exfiltrated_data[x] != self.chunks_int[x]:
						index_first_failure = x
						break
				if index_first_failure == -1:
					index_first_failure = len(self.chunks_int)

		if index_first_failure == -1:
			index_first_failure = self.sent_received_chunks

		print('')
		print('##################### ANALYSIS RECEIVED DATA #####################')
		print("- Number of Repetition: " + str(self.number_of_repetitions_done) + "/" + str(self.number_of_repetitions))
		print("- Stego-packets received: " + str(self.sent_received_chunks) + "/" + str(len(self.chunks_int)))
		print("- Duration of Stegocommunication: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Exfiltration Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Bandwidth: " + str(round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		print("- Exfiltrated data == Chunks: " + str(self.exfiltrated_data == self.chunks_int) + " (" + str(failures) + " Failures)")
		print("- Correct % message: " + str(round((index_first_failure/self.sent_received_chunks) * 100, 2)))
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

	settings, args = Traffic_Class_CC.process_command_line(sys.argv)
	traffic_class_cc = Traffic_Class_CC(helper.read_binary_file_and_return_chunks(settings.filepath, \
		helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"], \
		character_stuffing=True, \
		escape_value=Traffic_Class_CC.END_MAGIC_VALUE), \
		settings.role, settings.consecutive_clean, \
		settings.consecutive_stego)

	if traffic_class_cc.role == 'sender':
		helper.append_ip6tables_rule(sender=True)
		traffic_class_cc.print_start_message()
		traffic_class_cc.start_sending()
		helper.delete_ip6tables_rule(sender=True)
	elif traffic_class_cc.role == 'receiver':
		helper.append_ip6tables_rule(sender=False)
		traffic_class_cc.print_start_message()
		traffic_class_cc.start_receiving()
		helper.delete_ip6tables_rule(sender=False)


