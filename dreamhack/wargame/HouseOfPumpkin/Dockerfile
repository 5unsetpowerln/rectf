#FROM ubuntu:16.04
FROM ubuntu@sha256:6239ca16d54d8edd38788aacde7c6426e5999ffbbd7e97ac3cf04d474341d079

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -y update --fix-missing && apt-get -y upgrade
RUN apt-get -y install xinetd
RUN groupadd -r pwn && useradd -r -g pwn pwn

ADD deploy/pwn.xinetd /etc/xinetd.d/pwn
ADD deploy/init.sh    /etc/init.sh
ADD deploy/redir.sh   /home/pwn/redir.sh
RUN chmod 550        /home/pwn/redir.sh
RUN chmod 700        /etc/init.sh
RUN chmod 1733 /tmp /var/tmp /dev/shm

ADD deploy/flag     /home/pwn/flag
ADD deploy/chall        /home/pwn/chall
ADD deploy/libsalloc.so /lib/x86_64-linux-gnu/libsalloc.so
RUN chmod 440 /home/pwn/flag
RUN chmod 550 /home/pwn/chall
RUN chmod 555 /lib/x86_64-linux-gnu/libsalloc.so

RUN chown -R root:pwn /home/pwn

RUN ls /home/pwn -lh

RUN service xinetd restart
