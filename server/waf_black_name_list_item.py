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


def waf_get_black_name_list_item_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        domain = json_data['domain']
        try:
            page = json_data['page']
        except:
            page = 1
        results = waf_black_name_list_item.objects.filter(user_id=user_id).filter(domain=domain).filter(
            name_list_name=name_list_name)
        paginator = Paginator(results, 50)
        is_error = False
        try:
            page_results = paginator.page(int(page))
        except:
            is_error = True
            page_results = paginator.page(1)
        for result in page_results.object_list:
            data.append({
                'name_list_item': result.name_list_item,
                'name_list_expire': result.name_list_expire,
                'name_list_expire_time': time.strftime('%Y-%m-%d %H:%M:%S',
                                                       time.gmtime(int(result.name_list_expire_time)))
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


def waf_del_black_name_list_item(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        name_list_item = json_data['name_list_item']
        domain = json_data['domain']
        try:
            waf_black_name_list_item.objects.filter(user_id=user_id).filter(name_list_name=name_list_name).filter(
                name_list_item=name_list_item).filter(domain=domain).delete()
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


def waf_create_black_name_list_item(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        name_list_item = json_data['name_list_item']
        domain = json_data['domain']
        waf_black_name_list_result = waf_black_name_list.objects.get(
            Q(user_id=user_id) & Q(domain=domain) & Q(name_list_name=name_list_name))
        if waf_black_name_list_result.name_list_expire == "false":
            name_list_expire_time = ""
        else:
            name_list_expire_time = int(time.time()) + waf_black_name_list_result.name_list_expire_time
        name_list_item_count = waf_black_name_list_item.objects.filter(user_id=user_id).filter(
            name_list_name=name_list_name).filter(domain=domain).filter(
            name_list_item=name_list_item).count()
        if name_list_item_count == 0:
            waf_black_name_list_item.objects.create(user_id=user_id, domain=domain, name_list_name=name_list_name,
                                                    name_list_item=name_list_item,
                                                    name_list_expire=waf_black_name_list_result.name_list_expire,
                                                    name_list_expire_time=name_list_expire_time)
        return_result['message'] = 'create_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_search_black_name_list_item(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        search_value = json_data['search_value']
        domain = json_data['domain']
        try:
            page = json_data['page']
        except:
            page = 1
        results = waf_black_name_list_item.objects.filter(user_id=user_id).filter(domain=domain).filter(
            name_list_name=name_list_name).filter(
            name_list_item__contains=search_value)
        paginator = Paginator(results, 50)
        is_error = False
        try:
            page_results = paginator.page(int(page))
        except:
            is_error = True
            page_results = paginator.page(1)
        for result in page_results.object_list:
            data.append({'name_list_item': result.name_list_item,
                         'name_list_expire': result.name_list_expire,
                         'name_list_expire_time': time.strftime('%Y-%m-%d %H:%M:%S',
                                                                time.gmtime(int(result.name_list_expire_time)))
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
