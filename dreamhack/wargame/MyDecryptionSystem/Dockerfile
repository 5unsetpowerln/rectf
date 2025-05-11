FROM ubuntu:22.04@sha256:965fbcae990b0467ed5657caceaec165018ef44a4d2d46c7cdea80a9dff0d1ea

ENV user prob

RUN apt update
RUN apt-get install -y socat

RUN adduser $user

COPY ./deploy/flag /home/$user/flag
COPY ./deploy/prob /home/$user/prob
COPY ./deploy/libcrypto.so.1.1 /home/$user/lib/libcrypto.so.1.1

RUN chown -R root:$user /home/$user
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/prob

RUN chmod 755 /home/$user/prob
RUN chmod 440 /home/$user/flag

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/home/$user/lib

WORKDIR /home/$user
USER $user
EXPOSE 1118
CMD socat TCP-LISTEN:1118,reuseaddr,fork EXEC:/home/$user/prob