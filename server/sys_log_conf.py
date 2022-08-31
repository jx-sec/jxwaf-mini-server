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


from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_sys_log_conf(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        log_local_debug = json_data['log_local_debug']
        log_remote = json_data['log_remote']
        log_ip = json_data['log_ip']
        log_port = json_data['log_port']
        log_all = json_data['log_all']
        sys_log_conf.objects.filter(user_id=user_id).update(
            log_local_debug=log_local_debug,
            log_remote=log_remote, log_ip=log_ip, log_port=log_port,log_all=log_all)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_log_conf(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        try:
            sys_log_result = sys_log_conf.objects.get(user_id=user_id)
        except:
            sys_log_conf.objects.create(user_id=user_id)
            sys_log_result = sys_log_conf.objects.get(user_id=user_id)
        data['log_local_debug'] = sys_log_result.log_local_debug
        data['log_remote'] = sys_log_result.log_remote
        data['log_ip'] = sys_log_result.log_ip
        data['log_port'] = sys_log_result.log_port
        data['log_all'] = sys_log_result.log_all
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)