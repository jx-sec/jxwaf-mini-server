#!/bin/sh

while ! nc -z db 3306; do   
  sleep 1
done

# 执行数据库迁移
python manage.py migrate

# 收集静态文件
python manage.py collectstatic --noinput

# 启动 uwsgi
exec uwsgi \
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

