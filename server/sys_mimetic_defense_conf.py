# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
import hashlib
from DjangoCaptcha import Captcha
import sys
from django.conf import settings
import requests
import traceback
import time

reload(sys)
sys.setdefaultencoding('utf8')


def waf_edit_sys_mimetic_defense_conf(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        mimetic_defense = json_data['mimetic_defense']
        proxy_host = json_data['proxy_host']
        proxy_port = json_data['proxy_port']
        token = json_data['token']
        sys_mimetic_defense_conf.objects.filter(user_id=user_id).update(
            mimetic_defense=mimetic_defense,
            proxy_host=proxy_host, proxy_port=proxy_port, token=token)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_mimetic_defense_conf(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        try:
            sys_mimetic_defense_conf_result = sys_mimetic_defense_conf.objects.get(user_id=user_id)
        except:
            sys_mimetic_defense_conf.objects.create(user_id=user_id)
            sys_mimetic_defense_conf_result = sys_mimetic_defense_conf.objects.get(user_id=user_id)
        data['mimetic_defense'] = sys_mimetic_defense_conf_result.mimetic_defense
        data['proxy_host'] = sys_mimetic_defense_conf_result.proxy_host
        data['proxy_port'] = sys_mimetic_defense_conf_result.proxy_port
        data['token'] = sys_mimetic_defense_conf_result.token
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
