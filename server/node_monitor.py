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
        node_monitor_results = node_monitor.objects.filter(user_id=user_id)
        for result in node_monitor_results:
            node_waf_conf_update_time = result.node_waf_conf_update_time
            node_name_list_data_update_time = result.node_name_list_data_update_time
            node_status_update_time = result.node_status_update_time
            if len(node_waf_conf_update_time) > 0:
                node_waf_conf_update_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                                          time.localtime(int(node_waf_conf_update_time)))
            if len(node_name_list_data_update_time) > 0:
                node_name_list_data_update_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                                                time.localtime(int(node_name_list_data_update_time)))
            if len(node_status_update_time) > 0:
                node_status_update_time = time.strftime("%Y-%m-%d %H:%M:%S",
                                                        time.localtime(int(node_status_update_time)))
            node_status = result.node_status
            if node_status == "true":
                if int(time.time()) - int(result.node_status_update_time) > 60:
                    node_status = "false"
            data.append({'node_uuid': result.node_uuid,
                         'node_hostname': result.node_hostname,
                         'node_ip': result.node_ip,
                         'node_waf_conf_update': result.node_waf_conf_update,
                         'node_waf_conf_update_time': node_waf_conf_update_time,
                         'node_name_list_data_update': result.node_name_list_data_update,
                         'node_name_list_data_update_time': node_name_list_data_update_time,
                         'node_status': node_status,
                         'node_status_update_time': node_status_update_time
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


def waf_edit_node_conf_status(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        node_uuid = json_data['node_uuid']
        node_waf_conf_update = json_data['node_waf_conf_update']
        node_name_list_data_update = json_data['node_name_list_data_update']
        node_monitor.objects.filter(user_id=user_id).filter(node_uuid=node_uuid).update(
            node_waf_conf_update=node_waf_conf_update,node_name_list_data_update=node_name_list_data_update)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_node_monitor(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        node_uuid = json_data['node_uuid']
        node_monitor.objects.filter(user_id=user_id).filter(node_uuid=node_uuid).delete()
        return_result['result'] = True
        return_result['message'] = 'delete success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
