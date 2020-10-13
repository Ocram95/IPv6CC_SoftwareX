# IPv6 Covert Channels Suite
This repository contains several network covert channels based on IPv6 protocol. The covert channels allow a sender to secretly communicate
with a receiver, by injecting the information through three possible field of the header:

- Traffic Class (8 bit/packet)
- Flow Label (20 bit/packet)
- Hop Limit (1 bit/packet)

There are multiple variants implemented:
- Naive implementations:
	- magic value: the covert sender and the covert receiver agree on a value (which can be found at the start of each .py file). 
	The receiver will interpret every received packets contained between packets marked with the starting and the ending value
	as those containing the secret.
	- number of stegopackets: the covert sender and the covert receiver agree on the total number of stegopackets to transmit.
	The receiver will extract the proper number of incoming packets from the beginning of the flow.
- Signature implementations: the covert sender and the covert receiver agree on a certain sequence of signature to identify stegopackets.
This sequence is generated from a seed which can be found in the helper.py file. The signatures are the injected into a field of IPv6 header
different from the one containing the secret: Flow Label field in the case of Traffic Class and Hop Limit covert channels and Traffic Class field
in the case of Flow Label covert channel.
- Signature + TCP implementations: it is based on the signature implementation but it provides an error correction mechanism. The covert sender uses 
the knowledge of sequence numbers of the TCP header to identify missing packets that needs to be sent again. 

## Table of Contents

- [Architecture](#architecture)
- [Libraries](#libraries)
- [Installation](#installation)
- [Usage](#Usage)

## Architecture
image

## Libraries

The following libraries for the implementation have been used:

- Scapy 2.4.3 (https://scapy.net/)
- NetfilterQueue (https://github.com/kti/python-netfilterqueue)

Scapy is used for the injection and extraction of the secret information in the corresponding fields.

NetfilterQueue is used to insert specific packets which match an ip6tables rule into the netfilter queue number.

Multiple dependencies are required. We recommend the use of Docker to install the suite.



## Installation
The simply way to use IPv6 Covert Channels suite is to clone the repository and use the dockerfile to build a Docker container:
 ```	
$  git clone https://github.com/covert-channels-ipv6/ipv6_cc_scripts.git
$  docker build -t name_of_container /path_to_dockerfile
 ```
 
 Another possibility is to clone the repository and manually install all libraries needed and their dependencies.

## Usage
Let's start by looking at the help message:

```

Options:
-h, --help            show this help message and exit
  -r ROLE, --role=ROLE  specify the sender or the receiving role of the
                        script: {sender|receiver} (default: sender)
  -f FILE_PATH, --file=FILE_PATH
                        specify the path to the file, which shall be
                        exfiltrated
  -p NUMBER_CLEAN_PACKETS, --packets=NUMBER_CLEAN_PACKETS
                        specify the number of clean packets inserted
                        before/after stegopackets (default: 0)
  -l LENGTH_STEGO_PACKETS, --length=LENGTH_STEGO_PACKETS
                        specify the burst length of stegopackets (default: 0)

```

- ```-r ROLE``` is used to specify the role. Two possibilities can be used: ```-r s``` for the sender role and ```-r r``` for the receiver role;  
- ```-f FILE-PATH``` is used to specify the path for the file to secretly communicate from the sender to the receiver;  
- ```-p NUMBER_CLEAN_PACKETS``` is used to specify how many original packets are alternated with the stegopackets;  
- ```-l LENGTH_STEGO_PACKETS``` is used to specify how many stegopackets are alternated with the original packets.  

Before start the sender and the receiver, it is necessary to specify the source and the destination IPv6 addresses in the ```helper.py``` file. <br/>
```python
SOURCE_IPv6_ADDRESS = "source address"
DESTINATION_IPv6_ADDRESS = "destination address"
```
In the same file it is also possible to modify the seed to generate the list of signatures for the implementations that need it. <br/>
```python
PRESHARED_SEED = "seed"
```

Let's consider now a simple example on how it works: <br/>
```sudo python3 flow_label.py -r sender -f ../test5000 -p 10 -l 5``` <br/>
When running the above command a sender application is instantiated. It will inject the ../test5000 file as the secret information into
the Flow Label field with the following pattern: 10 original packets alternated with 5 stegopackets, until the secret information is parsed in its
entirety. <br/>

```sudo python3 flow_label.py -r receiver -f ../test5000 -p 10 -l 5``` <br/>
The above command, instead, is needed to run the receiver, with the same parameters of the sender.

In the case of 'number of stegopackets' implementation, an additional parameter is required:
```

-n NUMBER, --number=NUMBER
                        specify the number of packets which shall be
                        exfiltrated: number > 0
 
```

- ```-n NUMBER``` is used to specify the amount of stegopackets to inject and to extract.
