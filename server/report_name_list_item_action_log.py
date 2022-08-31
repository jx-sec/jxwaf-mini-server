# -*- coding:utf-8 –*-
import sys
from django.conf import settings
import requests
import traceback
import time
from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
from django.core.paginator import Paginator

reload(sys)
sys.setdefaultencoding('utf8')


def report_get_name_list_item_action_log(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        try:
            page = json_data['page']
        except:
            page = 1
        results = report_name_list_item_action_log.objects.filter(user_id=user_id)
        paginator = Paginator(results, 50)
        is_error = False
        try:
            page_results = paginator.page(int(page))
        except:
            is_error = True
            page_results = paginator.page(1)
        for result in page_results.object_list:
            data.append({'name_list_name': result.name_list_name,
                         'name_list_item': result.name_list_item,
                         'name_list_item_action_ip': result.name_list_item_action_ip,
                         'name_list_item_action_time': result.name_list_item_action_time,
                         'name_list_item_action': result.name_list_item_action
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
