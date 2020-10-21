from netfilterqueue import NetfilterQueue
from scapy.all import *
import optparse
import sys
import time
import csv
from pathlib import Path
sys.path.insert(1, '../')
import helper

class Hop_Limit_CC:

	#-------------- MAGIC VALUES --------------#
	START_MAGIC_VALUE = 230
	END_MAGIC_VALUE = 150
	#-------------- MAGIC VALUES --------------#

	def __init__(self, chunks, role, consecutive_nonstego, consecutive_stego):
		'''
		Constructor for sender and receiver of a Hop Limit cc.
		:param chunks: A string list containing the message to hide splitted in chunks.
		:param role: The role (i.e., sender or receiver) assigned.
		:param consecutive_nonstego: The length of the burst of non-stego packets.
		:param consecutive_stego: The lenght of the burst of stego packets
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
		self.finish_exf = False

		self.number_of_repetitions = 20
		self.number_of_repetitions_done = 0
		self.hoplimit_delta = 20

		self.consecutive_nonstego = consecutive_nonstego
		self.consecutive_stego = consecutive_stego
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
			tmp1 = time.perf_counter()
			pkt = IPv6(packet.get_payload())
			if pkt.hlim > Hop_Limit_CC.START_MAGIC_VALUE:
				self.starttime_stegocommunication = time.perf_counter()
				self.start_exf = True
			if pkt.hlim > Hop_Limit_CC.END_MAGIC_VALUE and pkt.hlim < Hop_Limit_CC.START_MAGIC_VALUE:
				self.endtime_stegocommunication = time.perf_counter()
				self.finish_exf = True
				self.start_exf = False
				self.number_of_repetitions_done += 1
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1
				self.statistical_evaluation_received_packets()
				self.write_csv()
				self.starttime_stegocommunication = 0.0
				self.endtime_stegocommunication = 0.0
				self.injection_exfiltration_time_sum = 0.0
				self.received_packets = 0
				self.sent_received_chunks = 0
				self.exfiltrated_data = []
				self.clean_counter = 0
				self.stegotime = True

			if self.start_exf and not pkt.hlim > Hop_Limit_CC.START_MAGIC_VALUE:
				if self.sent_received_chunks == 0 or self.stegotime:
					hlim = pkt.hlim
					if hlim > 64 and hlim < 150:
						self.exfiltrated_data.append(1)
					else:
						if hlim < 64:
							self.exfiltrated_data.append(0)
					self.sent_received_chunks += 1
					if self.consecutive_stego > 0:
						if self.sent_received_chunks % self.consecutive_stego == 0:
							self.stegotime = False
				else:
					self.clean_counter += 1
					if self.clean_counter % self.consecutive_nonstego == 0:
						self.stegotime = True
						self.clean_counter = 0
		
			if self.start_exf:
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1

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
			tmp1 = time.perf_counter()
			pkt = IPv6(packet.get_payload())
			if self.sent_received_chunks < len(self.chunks):
				if self.sent_received_chunks == 0 or self.stegotime:
					if self.first_packet:
						self.starttime_stegocommunication = time.perf_counter()
						pkt.hlim = 255
						self.first_packet = False
						packet.set_payload(bytes(pkt))
					else:
						single_bit = int(self.chunks[self.sent_received_chunks], 2)
						if single_bit == 1:
							pkt.hlim += self.hoplimit_delta
						else:
							pkt.hlim -= self.hoplimit_delta
						self.exfiltrated_data.append(single_bit)
						self.sent_received_chunks += 1
						packet.set_payload(bytes(pkt))

					if self.consecutive_stego > 0:
						if self.sent_received_chunks % self.consecutive_stego == 0:
							self.stegotime = False
						else:
							self.stegotime = True
				else:
					self.clean_counter += 1
					if self.clean_counter % self.consecutive_nonstego == 0:
						self.stegotime = True
						self.clean_counter = 0
			else:
				if self.sent_received_chunks == len(self.chunks):
					pkt.hlim = 200
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
			
			if not self.first_packet:
				self.injection_exfiltration_time_sum += time.perf_counter() - tmp1
		
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
			print("The injection is stopped.")
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

	def write_csv(self):
		
		filename="results_hop_limit_" + str(len(self.chunks_int)) + "_" + str(self.role) + ".csv"
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
					round((1 * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)])  			
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
					round((1 * self.sent_received_chunks) / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2), \
					round(failures), \
					round((index_first_failure/self.sent_received_chunks),2) * 100])

	def print_start_message(self):

		print('')
		if self.role == "sender":
			print('########## Mode: Start/Stop | CC: Hop Limit | Side: Covert Sender ##########')
		else:
			print('########## Mode: Start/Stop | CC: Hop Limit | Side: Covert Receiver ##########')
		print('- Number of Repetitions: ' + str(self.number_of_repetitions))		
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
			print('########## Mode: Start/Stop | CC: Hop Limit | Side: Covert Sender ##########')
		else:
			print('########## Mode: Start/Stop | CC: Hop Limit | Side: Covert Receiver ##########')
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
		print("- Sent stego-packets: " + str(self.sent_received_chunks) + "/" + str(len(self.chunks_int)))
		print("- Duration: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Injection Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Average Bandwidth: " + str(round(self.sent_received_chunks / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		#print("- Injected data == Chunks: " + str(self.exfiltrated_data == self.chunks_int))
		print('##################### ANALYSIS SENT DATA #####################')
		print('')

	def statistical_evaluation_received_packets(self):
		
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
		print("- Number of Repetitions: " + str(self.number_of_repetitions_done) + "/" + str(self.number_of_repetitions))
		print("- Received stego-packets: " + str(self.sent_received_chunks) + "/" + str(len(self.chunks_int)))
		print("- Duration: " + str(round((self.endtime_stegocommunication - self.starttime_stegocommunication) * 1000, 2)) + " ms")
		print("- Average Exfiltration Time: " + str(round((self.injection_exfiltration_time_sum / self.sent_received_chunks) * 1000, 2)) + " ms")
		print("- Average Bandwidth: " + str(round(self.sent_received_chunks / (self.endtime_stegocommunication - self.starttime_stegocommunication), 2)) + " bits/s")
		print("- Error Rate: " + str(round(failures/self.sent_received_chunks, 2)) + " Failures/Packet")
		#print("- Exfiltrated data == Chunks: " + str(self.exfiltrated_data == self.chunks_int) + " (" + str(failures) + " Failures)")
		#print("- Correct % message: " + str(round((index_first_failure/self.sent_received_chunks) * 100, 2)))
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

	settings, args = Hop_Limit_CC.process_command_line(sys.argv)
	hop_limit_cc = Hop_Limit_CC(helper.read_binary_file_and_return_chunks(settings.filepath, 1), settings.role, settings.consecutive_nonstego, settings.consecutive_stego)

	if hop_limit_cc.role == 'sender':
		helper.append_ip6tables_rule(sender=True)
		hop_limit_cc.print_start_message()
		hop_limit_cc.start_sending()
		helper.delete_ip6tables_rule(sender=True)
	elif hop_limit_cc.role == 'receiver':
		helper.append_ip6tables_rule(sender=False)
		hop_limit_cc.print_start_message()
		hop_limit_cc.start_receiving()
		helper.delete_ip6tables_rule(sender=False)
	