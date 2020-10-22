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

### Using Docker
The simple way to use IPv6CC is to clone the repository and use the dockerfile to build a Docker container containing the src folder with the scripts. The scripts are then visible in the root directory /root/covert_channels.

1. Clone the repository to your local machine.
```
$  git clone https://github.com/Ocram95/IPv6CC_SoftwareX.git
```
2. Copy the src folder of the repository into the docker directory
```
$  copy src/ -R docker/
```
3. Build the docker image from the docker file (you have to change to the directory with the dockerfile).
```	
$  cd docker/
$  docker build -t [imagename] .
```
4. Create a docker subnetwork connecting sender and receiver to it. 
```
$  docker network create --driver bridge --ipv6 --subnet=[subnet]/subnetmask [networkname]
```
5. Instantiate the sender and the receiver from the build image.
```
$  docker run -d -P --privileged --name sender [imagename]
$  docker run -d -P --privileged --name receiver [imagename]
```
6. Connect the sender and the receiver to the IPv6 docker network.
```
$  docker network connect --ip6 '[IPv6 address for sender in the subnet]' [networkname] sender
$  docker network connect --ip6 '[IPv6 address for sender in the subnet]' [networkname] receiver
```
7. Display your running containers and look for the exposed SSH-port.
```
$  docker ps -a
```
8. Login to the exposed SSH-port  of the container on your local machine.
```
$  ssh root@localhost -p [exposed portnumber]
```
9. The password for the login prompt can be seen and set in the line of the docker file 24:
```
$  RUN echo 'root:PASSWORD' | chpasswd
```

### Native Usage 
Another possibility is to clone the repository and manually install all libraries needed and their dependencies.

1. Clone the repository to your local machine.
```
$  git clone https://github.com/Ocram95/IPv6CC_SoftwareX.git
```
2. Install python3
```
$  sudo apt-get install python3
```
3. Install libnetfilter-queue-dev 
```
$  sudo apt-get install libnetfilter-queue-dev 
```
4. Install pip3
```
$  sudo apt-get install python3-pip
```
5. Install NetfilterQueue 0.8.1
```
$  pip3 install NetfilterQueue
```
6. Install Scapy 2.4.3
```
$  pip3 install scapy
```

## Usage
Let's start by looking at the help message of a the ```flow_label_cc.py``` file in the naive mode:

```
$ python3 flow_label_cc.py [-r ROLE] [-f FILE_PATH] [-l CONSECUTIVE_STEGO]  [-p CONSECUTIVE_NONSTEGO] [-n STEGOPACKETS]
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
number_of_repetitions = "20"
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

