#!/bin/bash
yum install -y epel-release pcre-devel openssl-devel gcc cmake make  lua-devel  automake
wget https://openresty.org/download/openresty-1.21.4.1.tar.gz 
tar zxvf openresty-1.21.4.1.tar.gz
cd openresty-1.21.4.1
./configure --prefix=/opt/server && gmake && gmake install
pip install uwsgi
cd ..
mv /opt/server/nginx/conf/nginx.conf  /opt/server/nginx/conf/nginx.conf.bak 
cp nginx.conf /opt/server/nginx/conf/
cp -r static/ /opt/server/nginx/html/
rm -rf openresty*
