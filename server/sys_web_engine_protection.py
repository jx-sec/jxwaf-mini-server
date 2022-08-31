# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
import sys
import time
from django.core.paginator import Paginator
from django.db.models import Q
import traceback

reload(sys)
sys.setdefaultencoding('utf8')


def waf_get_sys_web_engine_protection_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        web_engine_protection_results = sys_web_engine_protection.objects.filter(user_id=user_id)
        for web_engine_protection_result in web_engine_protection_results:
            data.append({
                'name': web_engine_protection_result.name,
                'detail': web_engine_protection_result.detail,
                'default': web_engine_protection_result.default,
                'update_time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(web_engine_protection_result.update_time)))
            })
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['errCode'] = 504
        return_result['message'] = str(e)
        return_result['detail'] = str(traceback.format_exc())
        return JsonResponse(return_result, safe=False)


def waf_edit_sys_web_engine_protection(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        sys_web_engine_protection.objects.filter(user_id=user_id).update(default='false')
        sys_web_engine_protection.objects.filter(user_id=user_id).filter(name=name).update(default='true')
        return_result['result'] = True
        return_result['message'] = "edit success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_delete_sys_web_engine_protection(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        try:
            sys_web_engine_protection.objects.get(Q(user_id=user_id) & Q(name=name) & Q(default='false'))
        except:
            return_result['result'] = False
            return_result['message'] = "delete fail"
            return JsonResponse(return_result, safe=False)
        sys_web_engine_protection.objects.filter(user_id=user_id).filter(name=name).filter(default='false').delete()
        return_result['result'] = True
        return_result['message'] = "delete success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
