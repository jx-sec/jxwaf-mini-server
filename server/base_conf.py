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


def waf_edit_base_conf(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        jxwaf_login = json_data['jxwaf_login']
        jxwaf_login_api_token = json_data['jxwaf_login_api_token']
        proxie = json_data['proxie']
        proxie_site = json_data['proxie_site']
        api_password = json_data['api_password']
        base_conf.objects.filter(user_id=user_id).update(
            jxwaf_login=jxwaf_login,
            jxwaf_login_api_token=jxwaf_login_api_token, proxie=proxie, proxie_site=proxie_site)
        jxwaf_user.objects.filter(user_id=user_id).update(api_password=api_password)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_base_conf(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        try:
            base_conf_result = base_conf.objects.get(user_id=user_id)
        except:
            base_conf.objects.create(user_id=user_id)
            base_conf_result = base_conf.objects.get(user_id=user_id)
        jxwaf_user_result = jxwaf_user.objects.get(user_id=user_id)
        data['jxwaf_login'] = base_conf_result.bypass_check
        data['jxwaf_login_api_token'] = base_conf_result.jxwaf_login_api_token
        data['proxie'] = base_conf_result.proxie
        data['proxie_site'] = base_conf_result.proxie_site
        data['api_key'] = jxwaf_user_result.api_key
        data['api_password'] = jxwaf_user_result.api_password
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)