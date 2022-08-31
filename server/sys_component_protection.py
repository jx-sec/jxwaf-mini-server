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


def waf_get_sys_component_protection_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        sys_component_protection_results = sys_component_protection.objects.filter(user_id=user_id)
        for sys_component_protection_result in sys_component_protection_results:
            data.append({
                'uuid': sys_component_protection_result.uuid,
                'name': sys_component_protection_result.name,
                'detail': sys_component_protection_result.detail,
                'demo_conf': sys_component_protection_result.demo_conf,
                'waf_domain_count': 0,
                'waf_group_domain_count': 0
            })
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_sys_component_protection(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        uuid = json_data['uuid']
        demo_conf = json_data['demo_conf']
        try:
            json_demo_conf = json.loads(demo_conf)
        except:
            return_result['result'] = False
            return_result['message'] = "json error"
            return JsonResponse(return_result, safe=False)
        sys_component_protection.objects.filter(user_id=user_id).filter(name=name).filter(uuid=uuid).update(demo_conf=json.dumps(json_demo_conf))
        return_result['result'] = True
        return_result['message'] = "edit success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_delete_sys_component_protection(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        uuid = json_data['uuid']
        try:
            sys_component_protection.objects.filter(user_id=user_id).filter(uuid=uuid).filter(name=name).delete()
        except:
            return_result['result'] = False
            return_result['message'] = "delete fail"
            return JsonResponse(return_result, safe=False)
        sys_flow_engine_protection.objects.filter(user_id=user_id).filter(name=name).filter(defalut='false').delete()
        return_result['result'] = True
        return_result['message'] = "delete success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
