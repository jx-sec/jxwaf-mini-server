FROM python:2.7-stretch

WORKDIR /app
COPY .  .

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

