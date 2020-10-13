FROM ubuntu:16.04

RUN mkdir /root/covert_channels
COPY ipv6_cc_scripts /root/covert_channels
COPY *.iso /root/

ENV TZ=Europe/Kiev
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt update
RUN apt install sudo
RUN apt install iputils-ping -y
RUN apt install net-tools -y
RUN apt install vim -y
RUN apt-get install python3-pip -y
RUN pip3 install -Iv scapy==2.4.3
RUN apt install libnetfilter-queue-dev -y
RUN pip3 install -Iv NetfilterQueue==0.8.1
RUN apt install iptables -y
RUN apt install iperf3 -y
RUN DEBIAN_FRONTEND=noninteractive apt install tshark -y
RUN apt-get update && apt-get install -y openssh-server
RUN mkdir /var/run/sshd

RUN echo 'root:steg4ever' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]

