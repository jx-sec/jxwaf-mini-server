# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
import hashlib
from django.db.models import Q
import sys
from django.conf import settings
import requests
import traceback
import time

reload(sys)
sys.setdefaultencoding('utf8')


def waf_get_identity_cheat_traffic_forward_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        identity_cheat_traffic_forward_results = identity_cheat_traffic_forward.objects.filter(user_id=user_id)
        for result in identity_cheat_traffic_forward_results:
            data.append({'name': result.name,
                         'detail': result.detail,
                         'traffic_forward_ip': result.traffic_forward_ip,
                         'traffic_forward_port': result.traffic_forward_port
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_identity_cheat_traffic_forward(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        traffic_forward_ip = json_data['traffic_forward_ip']
        traffic_forward_port = json_data['traffic_forward_port']
        identity_cheat_traffic_forward.objects.filter(user_id=user_id).filter(name=name).update(
            traffic_forward_ip=traffic_forward_ip,
            traffic_forward_port=traffic_forward_port)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_identity_cheat_traffic_forward(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        identity_cheat_traffic_forward_result = identity_cheat_traffic_forward.objects.get(
            Q(name=name) & Q(user_id=user_id))
        data['name'] = identity_cheat_traffic_forward_result.name
        data['detail'] = identity_cheat_traffic_forward_result.detail
        data['traffic_forward_ip'] = identity_cheat_traffic_forward_result.traffic_forward_ip
        data['traffic_forward_port'] = identity_cheat_traffic_forward_result.traffic_forward_port
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_identity_cheat_traffic_forward(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        try:
            identity_cheat_traffic_forward.objects.filter(user_id=user_id).filter(name=name).delete()
            return_result['result'] = True
            return_result['message'] = 'del success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)


def waf_create_identity_cheat_traffic_forward(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        detail = json_data['detail']
        traffic_forward_ip = json_data['traffic_forward_ip']
        traffic_forward_port = json_data['traffic_forward_port']
        try:
            result = identity_cheat_traffic_forward.objects.create(user_id=user_id, name=name, detail=detail,
                                                                   traffic_forward_ip=traffic_forward_ip,
                                                                   traffic_forward_port=traffic_forward_port)
            return_result['result'] = True
            return_result['message'] = 'create success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(traceback.format_exc())
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
