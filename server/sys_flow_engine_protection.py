# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
import sys
import time
from django.core.paginator import Paginator
from django.db.models import Q

reload(sys)
sys.setdefaultencoding('utf8')


def waf_get_sys_flow_engine_protection_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        flow_engine_protection_results = sys_flow_engine_protection.objects.filter(user_id=user_id)
        for flow_engine_protection_result in flow_engine_protection_results:
            data.append({
                'name': flow_engine_protection_result.name,
                'detail': flow_engine_protection_result.detail,
                'default': flow_engine_protection_result.default,
                'update_time': time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(flow_engine_protection_result.update_time)))
            })
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_sys_flow_engine_protection(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        sys_flow_engine_protection.objects.filter(user_id=user_id).update(default='false')
        sys_flow_engine_protection.objects.filter(user_id=user_id).filter(name=name).update(default='true')
        return_result['result'] = True
        return_result['message'] = "edit success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_delete_sys_flow_engine_protection(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        try:
            sys_flow_engine_protection.objects.get(Q(user_id=user_id) & Q(name=name) & Q(default='false'))
        except:
            return_result['result'] = False
            return_result['message'] = "delete fail"
            return JsonResponse(return_result, safe=False)
        sys_flow_engine_protection.objects.filter(user_id=user_id).filter(name=name).filter(default='false').delete()
        return_result['result'] = True
        return_result['message'] = "delete success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
