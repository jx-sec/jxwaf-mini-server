# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
import sys
import time
import traceback
from django.db.models import Q

reload(sys)
sys.setdefaultencoding('utf8')


def api_add_sys_name_list_item(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        api_key = json_data['api_key']
        api_password = json_data['api_password']
        name_list_uuid = json_data['name_list_uuid']
        name_list_item = json_data['name_list_item']
        action_ip = request.META['REMOTE_ADDR']
    except Exception, e:
        return_result['result'] = False
        return_result['errCode'] = 400
        return_result['message'] = "param error"
        return JsonResponse(return_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(api_key=api_key) & Q(api_password=api_password))
    except:
        return_result['result'] = False
        return_result['message'] = "api_key or api_password error"
        return JsonResponse(return_result, safe=False)
    try:
        name_list_result = sys_name_list.objects.get(Q(user_id=user_result.api_key) & Q(name_list_uuid=name_list_uuid))
    except:
        return_result['result'] = False
        return_result['message'] = "name_list  error"
        return JsonResponse(return_result, safe=False)
    try:
        name_list_item_all_count = sys_name_list_item.objects.filter(user_id=user_result.api_key).filter(
            name_list_uuid=name_list_uuid).count()
        name_list_item_count = sys_name_list_item.objects.filter(user_id=user_result.api_key).filter(
            name_list_uuid=name_list_uuid).filter(
            name_list_item=name_list_item).count()
        if name_list_item_all_count <= int(name_list_result.name_list_limit):
            name_list_item_expire_time = int(time.time()) + int(name_list_result.name_list_expire_time)
            if name_list_item_count != 0:
                sys_name_list_item.objects.filter(user_id=user_result.api_key).filter(
                    name_list_uuid=name_list_uuid).filter(
                    name_list_item=name_list_item).update(name_list_item_create_time=int(time.time()),
                                                          name_list_item_expire_time=name_list_item_expire_time)
                return_result['result'] = True
                return_result['message'] = 'update success'
                return JsonResponse(return_result, safe=False)
            sys_name_list_item.objects.create(user_id=user_result.api_key, name_list_item=name_list_item,
                                              name_list_uuid=name_list_uuid,
                                              name_list_item_create_time=int(time.time()),
                                              name_list_item_expire_time=name_list_item_expire_time)
            report_name_list_item_action_log.objects.create(user_id=user_result.api_key, name_list_item=name_list_item,
                                                            name_list_uuid=name_list_uuid,
                                                            name_list_name=name_list_result.name_list_name,
                                                            name_list_item_action_ip=action_ip,
                                                            name_list_item_action_time=int(time.time()),
                                                            name_list_item_action="api_add")
        else:
            return_result['message'] = 'create fail,excess name_list_limit count limit'
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        return_result['message'] = 'create success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['errCode'] = 504
        return_result['message'] = str(e)
        return_result['detail'] = str(traceback.format_exc())
        return JsonResponse(return_result, safe=False)
