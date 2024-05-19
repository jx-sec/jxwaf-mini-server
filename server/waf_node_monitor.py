# -*- coding:utf-8 –*-
from django.http import JsonResponse
import json
from server.models import *
import time


def waf_get_node_monitor_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        node_monitor_results = waf_node_monitor.objects.filter(user_id=user_id)
        for result in node_monitor_results:
            node_status_update_time = result.node_status_update_time
            if len(node_status_update_time) > 0:
                node_status_update_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                                        time.localtime(int(node_status_update_time)))
            node_status = "true"
            if int(time.time()) - int(result.node_status_update_time) > 300:
                node_status = "false"
            data.append({'node_uuid': result.node_uuid,
                         'node_hostname': result.node_hostname,
                         'node_ip': result.node_ip,
                         'node_status_update_time': node_status_update_time,
                         'node_status': node_status
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 401
        return JsonResponse(return_result, safe=False)


def waf_del_node_monitor(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        node_uuid = json_data['node_uuid']
        waf_node_monitor.objects.filter(user_id=user_id).filter(node_uuid=node_uuid).delete()
        return_result['result'] = True
        return_result['message'] = 'delete success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
