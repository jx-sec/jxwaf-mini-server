FROM python:2.7-stretch

WORKDIR /app
COPY .  .
RUN echo "deb http://archive.debian.org/debian/ stretch main" > /etc/apt/sources.list && \
    echo "Acquire::Check-Valid-Until false;" >> /etc/apt/apt.conf.d/10periodic && \
    echo "Acquire::Check-Valid-Until false;" >> /etc/apt/apt.conf.d/99update
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
#RUN pip install -i https://mirrors.aliyun.com/pypi/simple/ --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
RUN cp -f settings-mysql.py jxwaf_base_server/settings.py
RUN chmod +x entrypoint.sh
EXPOSE 8000

ENV HTTP=0.0.0.0:8000 \
    CHDIR=/app \
    WSGI_FILE=jxwaf_base_server/wsgi.py \
    STATIC_MAP=/static=/app/static \
    PROCESSES=4 \
    THREADS=2

ENTRYPOINT ["/app/entrypoint.sh"]

