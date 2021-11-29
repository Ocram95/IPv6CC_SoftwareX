FROM ubuntu:16.04

RUN mkdir /root/covert_channels
COPY src/ /root/covert_channels

ENV TZ=Europe/Kiev
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update
RUN apt-get install sudo
RUN apt-get install iputils-ping -y
RUN apt-get install net-tools -y
RUN apt-get install vim -y
RUN apt-get install python3-pip -y
RUN pip3 install -Iv scapy==2.4.3
RUN apt-get install libnetfilter-queue-dev -y
RUN pip3 install -Iv NetfilterQueue==0.8.1
RUN apt-get install iptables -y
RUN apt-get install iperf3 -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install tshark -y
RUN apt-get update && apt-get install -y openssh-server
RUN mkdir /var/run/sshd

RUN echo 'root:PASSWORD' | chpasswd
RUN sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
# SSH login fix. Otherwise user is kicked off after login
RUN sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]

