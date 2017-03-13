#!/bin/bash
cd ./libtpms
apt-get install libtool automake libgmp-dev libnspr4-dev libnss3-dev \
libssl-dev  

./bootstrap.sh
./configure --prefix=/usr --with-openssl
make
make install
