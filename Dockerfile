FROM python:2.7-stretch

WORKDIR /app
COPY .  .

#RUN pip install -i https://mirrors.aliyun.com/pypi/simple/ --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

ENV HTTP=0.0.0.0:8000 \
    CHDIR=/app \
    WSGI_FILE=jxwaf_base_server/wsgi.py \
    STATIC_MAP=/static=/app/static \
    PROCESSES=4 \
    THREADS=2

ENTRYPOINT uwsgi \
            --http $HTTP \
            --chdir $CHDIR \
            --wsgi-file $WSGI_FILE \
            --static-map $STATIC_MAP \
            --processes $PROCESSES \
            --threads $THREADS \
            --logto /app/app.log \
            --log-format '%(addr) - %(user) [%(ltime)] "%(method) %(uri) %(proto)" %(status) %(size) %(micros)ms' \
            --enable-threads \
            --thunder-lock \
            --die-on-term \
            --log-5xx \
            --log-4xx \
            --log-master
