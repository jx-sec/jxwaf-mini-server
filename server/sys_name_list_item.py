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


def waf_get_sys_name_list_item_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_uuid = json_data['name_list_uuid']
        try:
            page = json_data['page']
        except:
            page = 1
        results = sys_name_list_item.objects.filter(user_id=user_id).filter(name_list_uuid=name_list_uuid)
        paginator = Paginator(results, 50)
        is_error = False
        try:
            page_results = paginator.page(int(page))
        except:
            is_error = True
            page_results = paginator.page(1)
        for result in page_results.object_list:
            data.append({'name_list_uuid': result.name_list_uuid,
                         'name_list_item': result.name_list_item,
                         'name_list_item_create_time': result.name_list_item_create_time,
                         'name_list_item_expire_time': result.name_list_item_expire_time
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
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_sys_name_list_item(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_uuid = json_data['name_list_uuid']
        name_list_item = json_data['name_list_item']
        action_ip = request.META['REMOTE_ADDR']
        try:
            name_list_result = sys_name_list.objects.get(Q(user_id=user_id) & Q(name_list_uuid=name_list_uuid))
            sys_name_list_item.objects.filter(user_id=user_id).filter(name_list_uuid=name_list_uuid).filter(
                name_list_item=name_list_item).delete()
            report_name_list_item_action_log.objects.create(user_id=user_id, name_list_item=name_list_item,
                                                            name_list_uuid=name_list_uuid,
                                                            name_list_name=name_list_result.name_list_name,
                                                            name_list_item_action_ip=action_ip,
                                                            name_list_item_action_time=int(time.time()),
                                                            name_list_item_action="web_del")
            return_result['result'] = True
            return_result['message'] = 'del success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'del error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_create_sys_name_list_item(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_uuid = json_data['name_list_uuid']
        name_list_item = json_data['name_list_item']
        action_ip = request.META['REMOTE_ADDR']
        name_list_item_all_count = sys_name_list_item.objects.filter(user_id=user_id).filter(
            name_list_uuid=name_list_uuid).count()
        name_list_item_count = sys_name_list_item.objects.filter(user_id=user_id).filter(
            name_list_uuid=name_list_uuid).filter(
            name_list_item=name_list_item).count()
        name_list_result = sys_name_list.objects.get(Q(user_id=user_id) & Q(name_list_uuid=name_list_uuid))
        if name_list_item_all_count <= int(name_list_result.name_list_limit):
            name_list_expire_time = int(time.time()) + int(name_list_result.name_list_expire_time)
            if name_list_item_count != 0:
                sys_name_list_item.objects.filter(user_id=user_id).filter(name_list_uuid=name_list_uuid).filter(
                    name_list_item=name_list_item).update(name_list_item_create_time=int(time.time()),
                                                          name_list_item_expire_time=name_list_expire_time)
                return_result['result'] = True
                return_result['message'] = 'update success'
                return JsonResponse(return_result, safe=False)
            sys_name_list_item.objects.create(user_id=user_id, name_list_item=name_list_item,
                                              name_list_uuid=name_list_uuid,
                                              name_list_item_create_time=int(time.time()),
                                              name_list_item_expire_time=name_list_expire_time)
            report_name_list_item_action_log.objects.create(user_id=user_id, name_list_item=name_list_item,
                                                            name_list_uuid=name_list_uuid,
                                                            name_list_name=name_list_result.name_list_name,
                                                            name_list_item_action_ip=action_ip,
                                                            name_list_item_action_time=int(time.time()),
                                                            name_list_item_action="web_add")
        else:
            return_result['result'] = False
            return_result['message'] = 'create fail,excess name_list_limit count limit'
            return JsonResponse(return_result, safe=False)
        return_result['message'] = 'create success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_search_sys_name_list_item(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_uuid = json_data['name_list_uuid']
        search_value = json_data['search_value']
        try:
            page = json_data['page']
        except:
            page = 1
        results = sys_name_list_item.objects.filter(user_id=user_id).filter(name_list_uuid=name_list_uuid).filter(
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
                         'name_list_uuid': result.name_list_uuid,
                         'name_list_item_create_time': result.name_list_item_create_time,
                         'name_list_item_expire_time': result.name_list_item_expire_time
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
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
