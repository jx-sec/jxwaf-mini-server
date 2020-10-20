# -*- coding:utf-8 –*-
from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q
import datetime

def waf_get_monitor_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        waf_monitor_results = waf_monitor_log.objects.filter(user_id=user_id)
        for result in waf_monitor_results:
            data.append({'waf_monitor_node_uuid': result.waf_monitor_node_uuid,
                         'waf_monitor_node_detail': result.waf_monitor_node_detail,
                         'waf_monitor_node_status': result.waf_monitor_node_status,
                         'waf_monitor_node_alert': result.waf_monitor_node_alert,
                         'waf_monitor_node_time': result.waf_monitor_node_time.strftime("%Y-%m-%d %H:%M:%S")
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 401
        return JsonResponse(return_result, safe=False)


def waf_edit_monitor_alert(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        waf_monitor_node_uuid = json_data['waf_monitor_node_uuid']
        waf_monitor_node_alert = json_data['waf_monitor_node_alert']
        waf_monitor_log.objects.filter(user_id=user_id).filter(waf_monitor_node_uuid=waf_monitor_node_uuid).update(
            waf_monitor_node_alert=waf_monitor_node_alert)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_delete_monitor(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        waf_monitor_node_uuid = json_data['waf_monitor_node_uuid']
        waf_monitor_log.objects.filter(user_id=user_id).filter(waf_monitor_node_uuid=waf_monitor_node_uuid).delete()
        return_result['result'] = True
        return_result['message'] = 'delete success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)

