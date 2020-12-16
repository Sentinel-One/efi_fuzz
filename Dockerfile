FROM ubuntu:20.04

# Environment needed to install cmake.
ENV TZ=US/Pacific
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN apt-get update && apt-get install -y && apt-get install -y apt-utils \
    && apt-get install -y build-essential && apt-get install -y gcc && apt-get install -y automake && apt-get install -y autoconf \ 
    && apt-get install -y git && apt-get install -y cmake && apt-get install -y wget

RUN wget https://github.com/aquynh/capstone/archive/4.0.2.tar.gz && tar xzf 4.0.2.tar.gz && cd capstone-4.0.2 && ./make.sh install  && cd / 

RUN apt-get install -y python3 && apt-get install -y python3-dev && apt-get install -y python3-setuptools && apt-get install -y libz3-dev && apt-get install -y libboost-dev

RUN wget https://github.com/JonathanSalwan/Triton/archive/v0.8.1.tar.gz \
    && tar xzf v0.8.1.tar.gz \
    && cd Triton-0.8.1/ \
    && mkdir build \
    && cd build \
    && cmake .. \
    && make -j2 install \
    && cd /

# AFLplusplus checks git repo during make, so we need to clone instead of download a specific release.
RUN git clone https://github.com/AFLplusplus/AFLplusplus.git && cd AFLplusplus/ && git checkout 2.68c && make \
    && cd unicorn_mode && ./build_unicorn_support.sh && cd .. && make install && cd /

RUN wget https://bootstrap.pypa.io/get-pip.py && python3 get-pip.py

COPY requirements.txt efi_fuzz_requirements.txt
# uefi-firmware-parser in pypi is too old, let's use the one from github
RUN pip3 install git+https://github.com/theopolis/uefi-firmware-parser.git 
RUN pip3 install -r efi_fuzz_requirements.txt
RUN pip3 install debugpy
