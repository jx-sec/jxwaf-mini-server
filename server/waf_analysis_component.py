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


def waf_get_analysis_component_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        results = waf_analysis_component.objects.filter(user_id=user_id).order_by('order_time')
        for result in results:
            data.append({'name': result.name,
                         'detail': result.detail,
                         'conf': result.conf,
                         'status': result.status,
                         'order_time': result.order_time
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_analysis_component(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        result = waf_analysis_component.objects.get(
            Q(user_id=user_id) & Q(name=name))
        data['name'] = result.name
        data['detail'] = result.detail
        data['code'] = result.code
        data['conf'] = result.conf
        return_result['message'] = data
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_analysis_component(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        try:
            waf_analysis_component.objects.filter(user_id=user_id).filter(name=name).delete()
            return_result['result'] = True
            return_result['message'] = 'del_success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'del_error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_analysis_component(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        detail = json_data['detail']
        code = json_data['code']
        conf = json_data['conf']
        try:
            json.loads(conf)
        except:
            return_result['result'] = False
            return_result['message'] = "json error"
            return JsonResponse(return_result, safe=False)
        try:
            waf_analysis_component.objects.filter(name=name).filter(user_id=user_id).update(
                code=code, conf=conf,
                detail=detail)
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = 'edit_error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_analysis_component_status(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        status = json_data['status']
        try:
            waf_analysis_component.objects.filter(name=name).filter(user_id=user_id).update(
                status=status)
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = 'edit_error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_create_analysis_component(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        detail = json_data['detail']
        code = json_data['code']
        conf = json_data['conf']
        count = waf_analysis_component.objects.filter(user_id=user_id).filter(name=name).count()
        if count > 0:
            return_result['result'] = False
            return_result['message'] = 'create error,component is exist'
            return JsonResponse(return_result, safe=False)
        try:
            json.loads(conf)
        except:
            return_result['result'] = False
            return_result['message'] = "json error"
            return JsonResponse(return_result, safe=False)
        waf_analysis_component.objects.create(user_id=user_id, name=name,
                                          detail=detail,
                                          code=code, conf=conf,
                                          order_time=int(time.time()))
        return_result['message'] = 'create success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_exchange_analysis_component_priority(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        type = json_data['type']
        if type == "top":
            name = json_data['name']
            results = waf_analysis_component.objects.filter(
                user_id=user_id).order_by('order_time')
            result = results[0]
            waf_analysis_component.objects.filter(user_id=user_id).filter(
                name=name).update(
                order_time=int(result.order_time) - 1)
        elif type == "exchange":
            name = json_data['name']
            exchange_name = json_data['exchange_name']
            result = waf_analysis_component.objects.get(
                Q(user_id=user_id) & Q(name=name))
            exchange_name_result = waf_analysis_component.objects.get(
                Q(user_id=user_id) & Q(name=exchange_name))
            waf_analysis_component.objects.filter(user_id=user_id).filter(
                name=result.name).update(
                order_time=exchange_name_result.order_time)
            waf_analysis_component.objects.filter(user_id=user_id).filter(
                name=exchange_name_result.name).update(
                order_time=result.order_time)
        return_result['result'] = True
        return_result['message'] = 'exchange priority success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)