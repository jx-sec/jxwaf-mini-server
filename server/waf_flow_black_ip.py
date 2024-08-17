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


def waf_get_flow_black_ip_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        try:
            page = json_data['page']
        except:
            page = 1
        results = waf_flow_black_ip.objects.filter(user_id=user_id).filter(
            domain=domain)
        paginator = Paginator(results, 50)
        is_error = False
        try:
            page_results = paginator.page(int(page))
        except:
            is_error = True
            page_results = paginator.page(1)
        for result in page_results.object_list:
            if result.ip_expire == "false":
                expire_time = "永久生效"
            else:
                expire_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                            time.localtime(int(result.expire_time)))
            data.append({
                'ip': result.ip,
                'detail': result.detail,
                'expire_time': expire_time,
                'block_action': result.block_action,
                'action_value': result.action_value
            }
            )
        return_result['result'] = True
        return_result['message'] = data
        return_result['count'] = paginator.count
        return_result['num_pages'] = paginator.num_pages
        if is_error:
            return_result['now_page'] = 1
        else:
            return_result['now_page'] = page_results.number
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_flow_black_ip(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        ip = json_data['ip']
        result = waf_flow_black_ip.objects.get(Q(user_id=user_id) & Q(domain=domain) & Q(ip=ip))
        data['ip'] = result.ip
        data['detail'] = result.detail
        data['expire_time'] = result.expire_time
        data['block_action'] = result.block_action
        data['action_value'] = result.action_value
        return_result['message'] = data
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_flow_black_ip(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        ip = json_data['ip']
        try:
            waf_flow_black_ip.objects.filter(user_id=user_id).filter(domain=domain).filter(
                ip=ip).delete()
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


def waf_create_flow_black_ip(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        ip = json_data['ip']
        detail = json_data['detail']
        ip_expire = json_data['ip_expire']
        expire_time = json_data['expire_time']
        block_action = json_data['block_action']
        action_value = json_data['action_value']
        count = waf_flow_black_ip.objects.filter(user_id=user_id).filter(
            domain=domain).filter(
            ip=ip).count()
        if ip_expire == "false":
            expire_time = 0
        else:
            expire_time = int(time.time()) + int(expire_time)
        if count == 0:
            waf_flow_black_ip.objects.create(user_id=user_id, domain=domain,
                                             ip=ip,
                                             detail=detail,
                                             ip_expire=ip_expire, expire_time=expire_time, block_action=block_action,
                                             action_value=action_value)
        return_result['message'] = 'create_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_flow_black_ip(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        ip = json_data['ip']
        detail = json_data['detail']
        ip_expire = json_data['ip_expire']
        expire_time = json_data['expire_time']
        block_action = json_data['block_action']
        action_value = json_data['action_value']
        if ip_expire == "false":
            expire_time = 0
        else:
            expire_time = int(time.time()) + int(expire_time)
        waf_flow_black_ip.objects.filter(user_id=user_id).filter(
            domain=domain).filter(
            ip=ip).update(
            detail=detail,
            ip_expire=ip_expire,
            expire_time=expire_time,
            block_action=block_action,
            action_value=action_value
        )
        return_result['message'] = 'edit_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_search_flow_black_ip(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        search_value = json_data['search_value']
        try:
            page = json_data['page']
        except:
            page = 1
        results = waf_flow_black_ip.objects.filter(user_id=user_id).filter(
            domain=domain).filter(
            ip__contains=search_value)
        paginator = Paginator(results, 50)
        is_error = False
        try:
            page_results = paginator.page(int(page))
        except:
            is_error = True
            page_results = paginator.page(1)
        for result in page_results.object_list:
            if result.ip_expire == "false":
                expire_time = "永久生效"
            else:
                expire_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                            time.localtime(int(result.name_list_item_expire_time)))
            data.append({
                'ip': result.ip,
                'detail': result.detail,
                'expire_time': expire_time,
                'block_action': result.block_action,
                'action_value': result.action_value
            }
            )
        return_result['result'] = True
        return_result['message'] = data
        return_result['count'] = paginator.count
        return_result['num_pages'] = paginator.num_pages
        if is_error == True:
            return_result['now_page'] = 1
        else:
            return_result['now_page'] = page_results.number
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def api_add_flow_black_ip(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        waf_auth = json_data['waf_auth']
        domain = json_data['domain']
        ip = json_data['ip']
        detail = json_data['detail']
        ip_expire = json_data['ip_expire']
        expire_time = json_data['expire_time']
        block_action = json_data['block_action']
        action_value = json_data['action_value']
        try:
            user_result = jxwaf_user.objects.get(waf_auth=waf_auth)
        except:
            return_result['result'] = False
            return_result['message'] = "waf_auth error"
            return JsonResponse(return_result, safe=False)
        user_id = user_result.user_id
        count = waf_flow_black_ip.objects.filter(user_id=user_id).filter(
            domain=domain).filter(
            ip=ip).count()
        if count == 0:
            waf_flow_black_ip.objects.create(user_id=user_id, domain=domain,
                                             ip=ip,
                                             detail=detail,
                                             ip_expire=ip_expire, expire_time=expire_time, block_action=block_action,
                                             action_value=action_value)
        return_result['message'] = 'add_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
