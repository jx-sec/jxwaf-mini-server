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


def waf_get_name_list_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        results = waf_name_list.objects.filter(user_id=user_id).order_by('order_time')
        for result in results:
            count = waf_name_list_item.objects.filter(user_id=user_id).filter(
                name_list_name=result.name_list_name).count()
            data.append({'name_list_name': result.name_list_name,
                         'name_list_detail': result.name_list_detail,
                         'name_list_rule': result.name_list_rule,
                         'name_list_action': result.name_list_action,
                         'name_list_expire': result.name_list_expire,
                         'name_list_expire_time': result.name_list_expire_time,
                         'action_value': result.action_value,
                         'order_time': result.order_time,
                         'status': result.status,
                         'count': count
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


def waf_get_name_list(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        result = waf_name_list.objects.get(
            Q(user_id=user_id) & Q(name_list_name=name_list_name))
        data['name_list_name'] = result.name_list_name
        data['name_list_detail'] = result.name_list_detail
        data['name_list_rule'] = result.name_list_rule
        data['name_list_action'] = result.name_list_action
        data['name_list_expire'] = result.name_list_expire
        data['name_list_expire_time'] = result.name_list_expire_time
        data['action_value'] = result.action_value
        return_result['message'] = data
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        try:
            waf_name_list_item.objects.filter(user_id=user_id).filter(name_list_name=name_list_name).delete()
            waf_name_list.objects.filter(user_id=user_id).filter(name_list_name=name_list_name).delete()
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


def waf_edit_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        name_list_detail = json_data['name_list_detail']
        name_list_rule = json_data['name_list_rule']
        name_list_action = json_data['name_list_action']
        action_value = json_data['action_value']
        name_list_expire = json_data['name_list_expire']
        name_list_expire_time = json_data['name_list_expire_time']
        try:
            waf_name_list.objects.filter(name_list_name=name_list_name).filter(user_id=user_id).update(
                name_list_detail=name_list_detail, action_value=action_value,
                name_list_rule=name_list_rule, name_list_action=name_list_action, name_list_expire=name_list_expire,
                name_list_expire_time=name_list_expire_time)
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


def waf_edit_name_list_status(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        status = json_data['status']
        try:
            waf_name_list.objects.filter(name_list_name=name_list_name).filter(user_id=user_id).update(
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


def waf_create_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        name_list_detail = json_data['name_list_detail']
        name_list_rule = json_data['name_list_rule']
        name_list_action = json_data['name_list_action']
        action_value = json_data['action_value']
        name_list_expire = json_data['name_list_expire']
        name_list_expire_time = json_data['name_list_expire_time']
        count = waf_name_list.objects.filter(user_id=user_id).filter(name_list_name=name_list_name).count()
        if count > 0:
            return_result['result'] = False
            return_result['message'] = 'create error,name_list is exist'
            return JsonResponse(return_result, safe=False)
        waf_name_list.objects.create(user_id=user_id, name_list_name=name_list_name,
                                     name_list_detail=name_list_detail,
                                     name_list_rule=name_list_rule, name_list_action=name_list_action,
                                     action_value=action_value, order_time=int(time.time()),
                                     name_list_expire=name_list_expire,
                                     name_list_expire_time=name_list_expire_time)
        return_result['message'] = 'create success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_exchange_name_list_priority(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        type = json_data['type']
        if type == "top":
            name_list_name = json_data['name_list_name']
            results = waf_name_list.objects.filter(
                user_id=user_id).order_by('order_time')
            result = results[0]
            waf_name_list.objects.filter(user_id=user_id).filter(
                name_list_name=name_list_name).update(
                order_time=int(result.order_time) - 1)
        elif type == "exchange":
            name_list_name = json_data['name_list_name']
            exchange_name = json_data['exchange_name']
            name_list_result = waf_name_list.objects.get(
                Q(user_id=user_id) & Q(name_list_name=name_list_name))
            exchange_name_list__result = waf_name_list.objects.get(
                Q(user_id=user_id) & Q(name_list_name=exchange_name))
            waf_name_list.objects.filter(user_id=user_id).filter(
                name_list_name=name_list_result.name_list_name).update(
                order_time=exchange_name_list__result.order_time)
            waf_name_list.objects.filter(user_id=user_id).filter(
                name_list_name=exchange_name_list__result.name_list_name).update(
                order_time=name_list_result.order_time)
        return_result['result'] = True
        return_result['message'] = 'exchange priority success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
