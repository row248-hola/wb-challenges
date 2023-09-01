FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Tauri Prerequisites
RUN apt-get update && apt install -y openssh-server sudo

# Set up ssh access
RUN useradd -rm -d /home/ubuntu -s /bin/bash -g root -G sudo -u 1000 client
RUN echo 'client:client' | chpasswd
RUN sed -i 's/UsePAM/#UsePAM/g' /etc/ssh/sshd_config
RUN service ssh start

EXPOSE 22/tcp

ENTRYPOINT ["/usr/sbin/sshd", "-D"]