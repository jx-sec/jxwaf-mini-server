#!/usr/bin/env bash

python manage.py makemigrations;
if [ $? != 0 ] ; then exit 1 ; fi
python manage.py migrate;
if [ $? != 0 ] ; then exit 1 ; fi
uwsgi --ini uwsgi.ini;
/opt/server/nginx/sbin/nginx -g "daemon off;"