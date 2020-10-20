# IPv6CC Suite
IPv6CC implements several network covert channels based on IPv6 protocol in Python3. The covert channels allow a sender to secretly communicate
with a receiver, by injecting the information through three possible fields of the IPv6 header:

- Traffic Class (8 bit/packet)
- Flow Label (20 bit/packet)
- Hop Limit (1 bit/packet)

There are multiple variants implemented:
- Naive mode: the covert sender and the covert receiver agree on the total number of stegopackets to transmit. The receiver will extract the proper number of incoming 
packets from the beginning of the flow.

- Start/stop: the covert sender and the covert receiver agree on a value (which can be found at the start of each .py file). 
The receiver will interpret every received packets contained between packets marked with the starting and the ending value
as those containing the secret.
- Packet marking: the covert sender and the covert receiver agree on a certain sequence of signature to identify stegopackets.
This sequence is generated from a seed which can be found in the  ```helper.py``` file. The signatures are then injected into a field of IPv6 header
different from the one containing the secret: Flow Label field in the case of Traffic Class and Hop Limit covert channels and Traffic Class field
in the case of Flow Label covert channel.
- Reliable marking: it is based on the signature implementation but it provides an error correction mechanism. The covert sender uses 
the knowledge of sequence numbers of the TCP header to identify missing packets that needs to be sent again. 

## Table of Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#Usage)

## Architecture
![Alt text](https://github.com/Ocram95/IPV6CC_SoftwareX/blob/main/docs/architecture/softarch.png)

IPv6CC is written in Python3 and it is composed of 13 different python scripts: 12 scripts implement both the covert sender and receiver in each variant while 
the additional script, i.e., the ```helper.py``` script, contains functions shared among all channels.
IPv6CC uses a combination of different libraries:
- Scapy 2.4.3 (https://scapy.net/);
- NetfilterQueue 0.8.1 (https://github.com/kti/python-netfilterqueue).

In detail, NetfilterQueue is used to insert packets which match a specific ip6tables rule (which can be found in the ```helper.py``` file) into a queue. 
A callback function (inject or extraction function) is called by the library each time that a packet is inserted into the queue. The callback function 
uses Scapy primitives to access the packet and inject, or extract, the secret information.


## Installation
The simply way to use IPv6CC is to clone the repository and use the dockerfile to build a Docker container:
 ```	
$  git clone https://github.com/Ocram95/IPv6CC_SoftwareX.git
$  docker build -t name_of_container /docker/Dockerfile
 ```
 Another possibility is to clone the repository and manually install all libraries needed and their dependencies.

## Usage
Let's start by looking at the help message of a the ```flow_label_cc.py``` file in the naive mode:

```
$ python3 flow_label_cc.py [-r ROLE] [-f FILE_PATH] [-l CONSECUTIVE_STEGO]  
					  [-p CONSECUTIVE_NONSTEGO] [-n STEGOPACKETS]
```
There are three mandatory parameters: 
- ```-r ROLE``` is used to specify the role. Admitted values are ```sender``` and ```receiver```;
- ```-f FILE-PATH``` is used to specify the path for the file to secretly communicate from the sender to the receiver; 
- ```-n STEGOPACKETS``` is used to specify the number of stego-packets to be used. It is applied ONLY in the case
of naive implementations;
To configure the interleaving sending mode two optional parameters can be used:
- ```-p CONSECUTIVE_NONSTEGO``` is the length of the burst of non-stego packets;  
- ```-l CONSECUTIVE_STEGO``` is the length of the burst of stego-packets.  

Before start the sender and the receiver, it is necessary to specify the source and the destination IPv6 addresses in the ```helper.py``` file: <br/>
```python
SOURCE_IPv6_ADDRESS = "source address"
DESTINATION_IPv6_ADDRESS = "destination address"
```
In the same file it is also possible to modify the seed to generate the list of signatures for the implementations that need it: <br/>
```python
PRESHARED_SEED = "seed"
```
An additional parameter can be found in each script, and it defines the number of times to inject the same secret within the overt communication. This can be used
to test multiple times at once:
```python
NUMBER_OF_REPETITIONS = "20"
```

Let's consider now a simple example on how it works, specifically using the Flow Label covert channel in the naive mode: <br/>

```sudo python3 flow_label_cc.py -r sender -f ../test5000 -n 250 -p 10 -l 5``` <br/>

When running the above command a sender application is instantiated. It will inject the ../test5000 file as the secret information into
the Flow Label field with the following pattern: 10 non-stego packets alternated with 5 stego-packets, until the secret information is parsed in its
entirety, reaching 250 stego-packets. <br/>

```sudo python3 flow_label_cc.py -r receiver -f ../test5000 -n 250 -p 10 -l 5``` <br/>

The above command, instead, is needed to run the receiver with the same parameters of the sender.

At the end of each repetition, a log reports the output and the obtained performances, both for covert sender and receiver role:

![Alt text](https://github.com/Ocram95/IPV6CC_SoftwareX/blob/main/docs/logs/analysis_receiver.png)

In the above image is depicted the log from the receiver side. Specifically, it reports the number of repetitions, the amount of stego-packets transmitted,
the time needed to exfiltrate the secret message in its entirety, the average injection time to capture a packet and to modify it, the steganographic bandwidth, 
the number of failures, the error rate and the fraction of the message correctly received.

