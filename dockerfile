FROM centos:7 as builder
WORKDIR /opt/server/
# RUN  sh install_jxwaf_server.sh
RUN yum install -y epel-release pcre-devel openssl-devel gcc cmake make  lua-devel  automake wget
RUN wget https://openresty.org/download/openresty-1.21.4.1.tar.gz 
RUN tar zxvf openresty-1.21.4.1.tar.gz && cd openresty-1.21.4.1 && ./configure --prefix=/opt/server && gmake && gmake install
RUN mv /opt/server/nginx/conf/nginx.conf  /opt/server/nginx/conf/nginx.conf.bak 
COPY  nginx.conf /opt/server/nginx/conf/
COPY  static /opt/server/nginx/html/static



FROM centos:7
COPY --from=builder /opt/server  /opt/server/
WORKDIR /opt/jxwaf-mini-server
# WORKDIR /opt/jxwaf 
RUN yum install -y  epel-release 
RUN yum install -y python2-pip python-devel python  wget  gcc make mysql mysql-devel
# RUN yum install -y pip
RUN wget https://bootstrap.pypa.io/pip/2.7/get-pip.py  &&  python get-pip.py && python -m pip install --upgrade pip && pip install --upgrade pip
COPY . .
RUN cp packer/*   /usr/lib/python2.7/site-packages/ -R
RUN pip install -r requirements.txt && pip install   uwsgi
# RUN pip install   -i  http://mirrors.tencentyun.com/pypi/simple  --trusted-host mirrors.tencentyun.com   --no-dependencies -r requirements.txt 
# RUN pip install   uwsgi
# RUN mkdir /opt/server

# COPY --from=builder /opt/jxwaf /opt/jxwaf

# CMD   ["uwsgi", "--ini", "uwsgi.ini"]
CMD [ "/bin/bash","Entrypoint.sh" ]

