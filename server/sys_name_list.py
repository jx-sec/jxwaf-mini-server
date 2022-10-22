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


def waf_get_sys_name_list_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        results = sys_name_list.objects.filter(user_id=user_id)
        for result in results:
            waf_domain_count = waf_name_list.objects.filter(user_id=user_id).filter(
                name_list_uuid=result.name_list_uuid).count()
            waf_group_domain_count = waf_group_name_list.objects.filter(user_id=user_id).filter(
                name_list_uuid=result.name_list_uuid).count()
            data.append({'name_list_uuid': result.name_list_uuid,
                         'name_list_name': result.name_list_name,
                         'name_list_detail': result.name_list_detail,
                         'name_list_limit': result.name_list_limit,
                         'name_list_expire_time': result.name_list_expire_time,
                         'name_list_rule': result.name_list_rule,
                         'name_list_action': result.name_list_action,
                         'action_value': result.action_value,
                         'repeated_writing_suppression': result.repeated_writing_suppression,
                         'waf_domain_count': waf_domain_count,
                         'waf_group_domain_count': waf_group_domain_count
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

def waf_get_sys_name_list(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_uuid = json_data['name_list_uuid']
        result = sys_name_list.objects.get(Q(user_id=user_id) & Q(name_list_uuid=name_list_uuid))
        data['name_list_uuid'] = result.name_list_uuid
        data['name_list_name'] = result.name_list_name
        data['name_list_detail'] = result.name_list_detail
        data['name_list_rule'] = result.name_list_rule
        data['name_list_limit'] = result.name_list_limit
        data['name_list_expire_time'] = result.name_list_expire_time
        data['name_list_action'] = result.name_list_action
        data['action_value'] = result.action_value
        data['repeated_writing_suppression'] = result.repeated_writing_suppression
        return_result['message'] = data
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)

def waf_del_sys_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_uuid = json_data['name_list_uuid']
        try:
            sys_name_list.objects.filter(user_id=user_id).filter(name_list_uuid=name_list_uuid).delete()
            sys_name_list_item.objects.filter(user_id=user_id).filter(name_list_uuid=name_list_uuid).delete()
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


def waf_edit_sys_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_uuid = json_data['name_list_uuid']
        name_list_detail = json_data['name_list_detail']
        name_list_limit = json_data['name_list_limit']
        name_list_expire_time = json_data['name_list_expire_time']
        name_list_rule = json_data['name_list_rule']
        name_list_action = json_data['name_list_action']
        action_value = json_data['action_value']
        repeated_writing_suppression = json_data['repeated_writing_suppression']
        try:
            sys_name_list.objects.filter(name_list_uuid=name_list_uuid).filter(user_id=user_id).update(
                name_list_detail=name_list_detail, name_list_limit=name_list_limit,
                name_list_expire_time=name_list_expire_time, action_value=action_value,
                name_list_rule=name_list_rule, name_list_action=name_list_action,
                repeated_writing_suppression=repeated_writing_suppression)
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_create_sys_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        name_list_detail = json_data['name_list_detail']
        name_list_limit = json_data['name_list_limit']
        name_list_expire_time = json_data['name_list_expire_time']
        name_list_rule = json_data['name_list_rule']
        name_list_action = json_data['name_list_action']
        action_value = json_data['action_value']
        repeated_writing_suppression = json_data['repeated_writing_suppression']
        result = sys_name_list.objects.filter(user_id=user_id).filter(name_list_name=name_list_name)
        if len(result) != 0:
            return_result['result'] = False
            return_result['message'] = 'create error,shared_dict_name is exist'
            return JsonResponse(return_result, safe=False)
        sys_name_list.objects.create(user_id=user_id, name_list_name=name_list_name, name_list_detail=name_list_detail,
                                     name_list_limit=name_list_limit, name_list_expire_time=name_list_expire_time,
                                     name_list_rule=name_list_rule, name_list_action=name_list_action,
                                     repeated_writing_suppression=repeated_writing_suppression,
                                     action_value=action_value)
        return_result['message'] = 'create success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_search_sys_name_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        search_type = json_data['search_type']
        search_value = json_data['search_value']
        try:
            page = json_data['page']
        except:
            page = 1
        if search_type == "name_list_uuid":
            results = sys_name_list.objects.filter(user_id=user_id).filter(rule_uuid__contains=search_value)
        elif search_type == "name_list_name":
            results = sys_name_list.objects.filter(user_id=user_id).filter(rule_name__contains=search_value)
        else:
            results = sys_name_list.objects.filter(user_id=user_id)
        paginator = Paginator(results, 50)
        is_error = False
        try:
            page_results = paginator.page(int(page))
        except:
            is_error = True
            page_results = paginator.page(1)
        for result in page_results.object_list:
            data.append({'name_list_uuid': result.name_list_uuid,
                         'name_list_name': result.name_list_name,
                         'name_list_detail': result.name_list_detail,
                         'name_list_limit': result.name_list_limit,
                         'name_list_expire_time': result.name_list_expire_time,
                         'name_list_rule': result.name_list_rule,
                         'name_list_action': result.name_list_action,
                         'action_value': result.action_value,
                         'repeated_writing_suppression': result.repeated_writing_suppression,
                         'name_list_version': result.name_list_version
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
