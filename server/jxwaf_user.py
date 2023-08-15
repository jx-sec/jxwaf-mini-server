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


def account_init_check(request):
    return_result = {}
    try:
        account_count = jxwaf_user.objects.all().count()
        if account_count == 0:
            return_result['result'] = True
            return_result['message'] = "account_init_fail"
            return JsonResponse(return_result, safe=False)
        else:
            return_result['result'] = True
            return_result['message'] = "account_init_success"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)


def account_regist(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        user_name = json_data['user_name']
        user_password = json_data['user_password']
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)
    try:
        account_count = jxwaf_user.objects.all().count()
        if account_count == 0:
            md5 = hashlib.md5()
            md5.update(user_password)
            jxwaf_user.objects.create(user_name=user_name, user_password=md5.hexdigest())
            return_result['result'] = True
            return_result['message'] = "create success"
            return JsonResponse(return_result, safe=False)
        else:
            return_result['result'] = False
            return_result['errCode'] = 105
            return_result['message'] = "account_has_been_registered"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)


def index(request):
    try:
        request.session['user_id']
        return render(request, 'index.html')
    except:
        return render(request, 'login.html')


def login_html(request):
    return render(request, 'login.html')


def login(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        user_name = json_data['user_name']
        user_password = json_data['user_password']
        code = json_data['code']
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)
    ca = Captcha(request)
    if ca.check(code):
        try:
            result = jxwaf_user.objects.get(user_name=user_name)
        except Exception, e:
            return_result['result'] = False
            return_result['errCode'] = 101
            return_result['message'] = "account_no_exist_or_password_error"
            return JsonResponse(return_result, safe=False)
        md5 = hashlib.md5()
        md5.update(user_password)
        if result.user_password == md5.hexdigest():
            request.session['user_id'] = str(result.api_key)
            return_result['result'] = True
            return_result['api_key'] = result.api_key
            return_result['api_password'] = result.api_password
            return JsonResponse(return_result, safe=False)
        else:
            return_result['result'] = False
            return_result['errCode'] = 101
            return_result['message'] = "account_no_exist_or_password_error"
            return JsonResponse(return_result, safe=False)
    else:
        return_result['result'] = False
        return_result['errCode'] = 104
        return_result['message'] = 'code_is_wrong'
        return JsonResponse(return_result, safe=False)


def captcha(request):
    ca = Captcha(request)
    ca.mode = 'four_number'
    ca.img_width = 100
    ca.img_height = 30
    return ca.display()


def logout(request):
    data = {}
    try:
        del request.session['user_id']
        data['result'] = True
        return render(request, 'login.html')
    except:
        data['result'] = False
        data['message'] = 'Operation failed'
        return render(request, 'login.html')


def sys_init_check(request):
    return_result = {}
    try:
        request.session['user_id']
        web_engine_version_count = sys_web_engine_protection.objects.all().count()
        if web_engine_version_count == 0:
            return_result['result'] = True
            return_result['message'] = "sys_init_fail"
            return JsonResponse(return_result, safe=False)
        flow_engine_version_count = sys_flow_engine_protection.objects.all().count()
        if flow_engine_version_count == 0:
            return_result['result'] = True
            return_result['message'] = "sys_init_fail"
            return JsonResponse(return_result, safe=False)
        return_result['result'] = True
        return_result['message'] = "account_init_success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)


# pip install requests[socks]
def sys_init(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        proxie_status = False
        proxies = {}
        try:
            json_data = json.loads(request.body)
            proxie = json_data['proxie']
            proxie_site = json_data['proxie_site']
            if proxie == "true":
                proxie_status = True
                proxies['http'] = proxie_site
                proxies['https'] = proxie_site
        except:
            pass
        web_engine_version_count = sys_web_engine_protection.objects.all().count()
        flow_engine_version_count = sys_flow_engine_protection.objects.all().count()
        if web_engine_version_count != 0 and flow_engine_version_count != 0:
            return_result['result'] = False
            return_result['message'] = "has_completed_initialization"
            return JsonResponse(return_result, safe=False)
        web_engine_uri = "https://api.jxwaf.com/jxwaf/get_web_engine"
        try:
            payload = {'version': settings.JXWAF_SYS_VERSION}
            if proxie_status:
                r = requests.post(web_engine_uri, data=json.dumps(payload), proxies=proxies)
            else:
                r = requests.post(web_engine_uri, data=json.dumps(payload))
            result = r.json()
            if result['result'] == True:
                message = result['message']
                sys_web_engine_protection.objects.create(user_id=user_id, name=message['name'], code=message['code'],
                                                         detail=message['detail'], default='true',
                                                         update_time=int(time.time()))
            else:
                return_result['result'] = False
                return_result['message'] = "web_engine_init_error"
                return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return JsonResponse(return_result, safe=False)
        flow_engine_uri = "https://api.jxwaf.com/jxwaf/get_flow_engine"
        try:
            payload = {'version': settings.JXWAF_SYS_VERSION}
            if proxie_status:
                r = requests.post(flow_engine_uri, data=json.dumps(payload), proxies=proxies)
            else:
                r = requests.post(flow_engine_uri, data=json.dumps(payload))
            result = r.json()
            if result['result'] == True:
                message = result['message']
                sys_flow_engine_protection.objects.create(user_id=user_id, name=message['name'], code=message['code'],
                                                          detail=message['detail'], default='true',
                                                          update_time=int(time.time()))
            else:
                return_result['result'] = False
                return_result['message'] = "flow_engine_init_error"
                return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return JsonResponse(return_result, safe=False)
        return_result['result'] = True
        return_result['message'] = "sys_init_success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = str(traceback.format_exc())
        return JsonResponse(return_result, safe=False)
