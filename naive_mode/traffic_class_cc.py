from netfilterqueue import NetfilterQueue
from scapy.all import *
import optparse
import sys
import time
import csv
from pathlib import Path
sys.path.insert(1, '../')
import helper

def get_comma_separated_args(option, opt, value, parser):
	setattr(parser.values, option.dest, value.split(','))

class Traffic_Class_CC:

	def __init__(self, filepath, chunks, number_of_packets, role, number_clean_packets, length_stego_packets):
		'''
		Constructor for sender and receiver of a Traffic Class Covert Channel
		:param list chunks: A list of strings in binary format, which shall be injected into the traffic class field.
		:param policy: injection policy: n stego-packets every n clear packets
		:raises ValueError: if the chunks is an empty list.
		'''
		self.chunks = chunks
		self.int_chunks = [int(x,2) for x in self.chunks] 				
		self.number_of_packets = number_of_packets
		self.actual_number = 0
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
			if self.sent_received_chunks < self.number_of_packets[self.actual_number]:
				
				if self.sent_received_chunks == 0:
					self.starttime_stegocommunication = time.perf_counter()

				if self.stegotime:
					pkt.tc = int(self.chunks[self.sent_received_chunks], 2)
					self.exfiltrated_data.append(pkt.tc)
					packet.set_payload(bytes(pkt))

					self.sent_received_chunks += 1

					if self.length_stego_packets > 0:
						self.stegotime = self.sent_received_chunks % self.length_stego_packets != 0
					
				else:
					self.clean_counter += 1
					self.stegotime = self.clean_counter % self.number_clean_packets == 0
			else:

				self.endtime_stegocommunication = time.perf_counter()
				self.stegotime = True
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1
				self.number_of_repititions_done += 1
				self.statistical_evaluation_sent_packets()
				self.write_csv()
				self.injection_exfiltration_time_sum = 0
				self.sent_received_chunks = 0
				self.stegotime = True
				self.exfiltrated_data = []
				# time.sleep(1)
				
			if self.sent_received_chunks != 0:
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1

		else:
			
			if self.actual_number < len(self.number_of_packets) - 1:
				self.actual_number += 1
				self.chunks = helper.read_binary_file_for_n_packets_and_return_chunks(self.filepath, self.number_of_packets[self.actual_number], helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"])
				self.int_chunks = [int(x,2) for x in self.chunks] 				
				self.print_start_message()
				self.number_of_repititions_done = 0
				# time.sleep(3)
			
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
			if self.sent_received_chunks < self.number_of_packets[self.actual_number]:
				
				if self.sent_received_chunks == 0:
					self.starttime_stegocommunication = time.perf_counter()

				if self.stegotime:
					self.exfiltrated_data.append(pkt.tc)

					self.sent_received_chunks += 1

					if self.length_stego_packets > 0:
						self.stegotime = self.sent_received_chunks % self.length_stego_packets != 0
				else:
					self.clean_counter += 1
					self.stegotime = self.clean_counter % self.number_clean_packets == 0
			else:

				self.endtime_stegocommunication = time.perf_counter()
				self.stegotime = True
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1
				self.number_of_repititions_done += 1
				self.statistical_evaluation_received_packets()
				self.write_csv()
				self.injection_exfiltration_time_sum = 0
				self.sent_received_chunks = 0
				self.exfiltrated_data = []
				# time.sleep(1)

			if self.sent_received_chunks != 0:
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1

		else:

			if self.actual_number < len(self.number_of_packets) - 1:
				self.actual_number += 1
				self.chunks = helper.read_binary_file_for_n_packets_and_return_chunks(self.filepath, self.number_of_packets[self.actual_number], helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"])
				self.int_chunks = [int(x,2) for x in self.chunks] 				
				self.print_start_message()
				self.number_of_repititions_done = 0
				# time.sleep(3)
			
		packet.accept()
		
	def write_csv(self):
		
		filename="traffic_class_cc_" + self.filepath.replace("../", "", 1) + "_number_of_packets_" + str(self.number_of_packets[self.actual_number]) + "_role_" + self.role + "_clean_packets_" + str(self.number_clean_packets) + "_number_stegopackets_" + str(self.length_stego_packets) + ".csv"
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

				# Count the failures
				if len(self.exfiltrated_data) <= len(self.int_chunks):
					for x in range(len(self.exfiltrated_data)):
						if self.exfiltrated_data[x] != self.int_chunks[x]:
							failures += 1
				else:
					for x in range(len(self.int_chunks)):
						if self.exfiltrated_data[x] != self.int_chunks[x]:
							failures += 1
				failures += abs(len(self.exfiltrated_data) - len(self.int_chunks))

				if failures != 0:
					# Receive less than expected => first failure can happen in the middle or after the last index
					if len(self.exfiltrated_data) < len(self.int_chunks):
						for x in range(len(self.exfiltrated_data)):
							if self.exfiltrated_data[x] != self.int_chunks[x]:
								index_first_failure = x
								break
						if index_first_failure == -1:
							index_first_failure = len(self.exfiltrated_data)
					# Receive exactly the amount which is expected => index must be in the middle
					elif len(self.exfiltrated_data) == len(self.int_chunks):
						for x in range(len(self.int_chunks)):
							if self.exfiltrated_data[x] != self.int_chunks[x]:
								index_first_failure = x
								break
					else:
					# Receive more than expected => first failure can happen in the middle or after the last index
						for x in range(len(self.int_chunks)):
							if self.exfiltrated_data[x] != self.int_chunks[x]:
								index_first_failure = x
								break
						if index_first_failure == -1:
							index_first_failure = len(self.int_chunks)

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
			print('################## NUMBER STEGO PACKETS TRAFFIC CLASS CC SENDER ##################')
		else:
			print('################## NUMBER STEGO PACKETS TRAFFIC CLASS CC RECEIVER ##################')
		print('- Number of Repitions: ' + str(self.number_of_repititions))		
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
			print('################## NUMBER STEGO PACKETS TRAFFIC CLASS CC SENDER ##################')
		else:
			print('################## NUMBER STEGO PACKETS TRAFFIC CLASS CC RECEIVER ##################')
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
		print("- Sent Chunks: " + str(self.sent_received_chunks) + "/" + str(self.number_of_packets[self.actual_number]))
		print("- Duration of Stegocommunication: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Injection Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Bandwidth: " + str(round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		print("- Injected data == Chunks: " + str(self.exfiltrated_data == self.int_chunks))
		print('##################### ANALYSIS SENT DATA #####################')
		print('')

	def statistical_evaluation_received_packets(self):
		
		failures = 0
		index_first_failure = -1 

		# Count the failures
		if len(self.exfiltrated_data) <= len(self.int_chunks):
			for x in range(len(self.exfiltrated_data)):
				if self.exfiltrated_data[x] != self.int_chunks[x]:
					failures += 1
		else:
			for x in range(len(self.int_chunks)):
				if self.exfiltrated_data[x] != self.int_chunks[x]:
					failures += 1
		failures += abs(len(self.exfiltrated_data) - len(self.int_chunks))

		if failures != 0:
			# Receive less than expected => first failure can happen in the middle or after the last index
			if len(self.exfiltrated_data) < len(self.int_chunks):
				for x in range(len(self.exfiltrated_data)):
					if self.exfiltrated_data[x] != self.int_chunks[x]:
						index_first_failure = x
						break
				if index_first_failure == -1:
					index_first_failure = len(self.exfiltrated_data)
			# Receive exactly the amount which is expected => index must be in the middle
			elif len(self.exfiltrated_data) == len(self.int_chunks):
				for x in range(len(self.int_chunks)):
					if self.exfiltrated_data[x] != self.int_chunks[x]:
						index_first_failure = x
						break
			else:
			# Receive more than expected => first failure can happen in the middle or after the last index
				for x in range(len(self.int_chunks)):
					if self.exfiltrated_data[x] != self.int_chunks[x]:
						index_first_failure = x
						break
				if index_first_failure == -1:
					index_first_failure = len(self.int_chunks)

		if index_first_failure == -1:
			index_first_failure = self.sent_received_chunks

		print('')
		print('##################### ANALYSIS RECEIVED DATA #####################')
		print("- Number of Repition: " + str(self.number_of_repititions_done) + "/" + str(self.number_of_repititions))
		print("- Received Chunks: " + str(self.sent_received_chunks) + "/" + str(self.number_of_packets[self.actual_number]))
		print("- Duration of Stegocommunication: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Exfiltration Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Bandwidth: " + str(round((helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"] * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		print("- Exfiltrated data == Chunks: " + str(self.exfiltrated_data == self.int_chunks) + " (" + str(failures) + " Failures)")
		print("- Error Rate: " + str(round(failures/self.sent_received_chunks, 2)) + " Failures/Packet")
		print("- Successfully transmitted Message: " + str(round( (index_first_failure/self.sent_received_chunks) * 100, 2)) + "%")
		# print("- Successfully transmitted Message: " + str(round(100 - ((failures/self.sent_received_chunks) * 100), 2)) + "%")
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
		'-n',
		'--stegopackets',
		help='specify the number of packets which shall be exfiltrated: number > 0',
		action='callback',
		callback=get_comma_separated_args,
		type='string',
		dest='stegopackets')

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
		
		settings.stegopackets = [int(x) for x in settings.stegopackets]

		if any(n < 1 for n in settings.stegopackets):
			raise ValueError("The List of numbers contains at least one element < 1!")

		if not settings.stegopackets:
			raise ValueError("The List of numbers which shall be exfiltrated needs at least one positive element!")

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

	traffic_class_cc = Traffic_Class_CC(settings.filepath, helper.read_binary_file_for_n_packets_and_return_chunks(settings.filepath, settings.stegopackets[0], helper.IPv6_HEADER_FIELD_LENGTHS_IN_BITS["Traffic Class"]), settings.stegopackets, settings.role, settings.consecutive_clean, settings.consecutive_stego)

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

