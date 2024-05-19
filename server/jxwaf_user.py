# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
import hashlib
from DjangoCaptcha import Captcha
import sys
import traceback
import time
from server.models import *

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
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)


def account_regist(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        user_name = json_data['user_name']
        user_password = json_data['user_password']
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)
    try:
        account_count = jxwaf_user.objects.all().count()
        if account_count == 0:
            md5 = hashlib.md5()
            md5.update(user_password)
            jxwaf_user.objects.create(user_name=user_name, user_password=md5.hexdigest())
            result = jxwaf_user.objects.get(user_name=user_name)
            sys_conf.objects.create(user_id=result.user_id)
            return_result['result'] = True
            return_result['message'] = "create_success"
            return JsonResponse(return_result, safe=False)
        else:
            return_result['result'] = False
            return_result['errCode'] = 105
            return_result['message'] = "account_has_been_registered"
            return JsonResponse(return_result, safe=False)
    except Exception as e:
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
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)
    ca = Captcha(request)
    if ca.check(code):
        try:
            result = jxwaf_user.objects.get(user_name=user_name)
        except Exception as e:
            return_result['result'] = False
            return_result['errCode'] = 101
            return_result['message'] = "account_no_exist_or_password_error"
            return JsonResponse(return_result, safe=False)
        md5 = hashlib.md5()
        md5.update(user_password)
        if result.user_password == md5.hexdigest():
            request.session['user_id'] = str(result.user_id)
            return_result['result'] = True
            return_result['waf_auth'] = result.waf_auth
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
        data['message'] = 'Operation failed'
        return render(request, 'login.html')


def demo_env_init(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        user_name = json_data['user_name']
        user_password = json_data['user_password']
        waf_auth = json_data['waf_auth']
        log_conf_remote = json_data['log_conf_remote']
        log_ip = json_data['log_ip']
        log_port = json_data['log_port']
        log_response = json_data['log_response']
        log_all = json_data['log_all']
        report_conf = json_data['report_conf']
        report_conf_ch_host = json_data['report_conf_ch_host']
        report_conf_ch_port = json_data['report_conf_ch_port']
        report_conf_ch_user = json_data['report_conf_ch_user']
        report_conf_ch_password = json_data['report_conf_ch_password']
        report_conf_ch_database = json_data['report_conf_ch_database']
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)
    try:
        account_count = jxwaf_user.objects.all().count()
        if account_count != 0:
            return_result['result'] = False
            return_result['message'] = "account_init_fail"
            return JsonResponse(return_result, safe=False)

        md5 = hashlib.md5()
        md5.update(user_password)
        jxwaf_user.objects.create(user_name=user_name, user_password=md5.hexdigest(), waf_auth=waf_auth)
        result = jxwaf_user.objects.get(user_name=user_name)
        sys_conf.objects.create(user_id=result.user_id, log_conf_remote=log_conf_remote, log_ip=log_ip,
                                log_port=log_port, log_response=log_response, log_all=log_all, report_conf=report_conf,
                                report_conf_ch_host=report_conf_ch_host, report_conf_ch_port=report_conf_ch_port,
                                report_conf_ch_user=report_conf_ch_user,
                                report_conf_ch_password=report_conf_ch_password,
                                report_conf_ch_database=report_conf_ch_database)
        return_result['result'] = True
        return_result['message'] = "init_success"
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)
