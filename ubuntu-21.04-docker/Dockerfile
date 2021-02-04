FROM ubuntu:21.04

ENV DEBIAN_FRONTEND noninteractive
ENV TZ "Asia/Shanghai"

COPY aliyun.sources.list /etc/apt/sources.list
RUN apt-get update \
  && apt-get install -y apt-utils \
  && apt-get install -y tzdata \
  && ln -fs /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
  && dpkg-reconfigure --frontend noninteractive tzdata \
  && apt-get install -y udev tpm-udev \
  && apt-get install -y build-essential meson \
  && apt-get build-dep -y tpm2-tss \
  && apt-get clean all

CMD "/usr/bin/bash"
