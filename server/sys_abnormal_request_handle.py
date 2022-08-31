from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_sys_abnormal_handle(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        bypass_check = json_data['bypass_check']
        same_name_args_check = json_data['same_name_args_check']
        truncated_agrs_check = json_data['truncated_agrs_check']
        ssl_attack_check = json_data['ssl_attack_check']
        ssl_attack_count = json_data['ssl_attack_count']
        ssl_attack_count_stat_time_period = json_data['ssl_attack_count_stat_time_period']
        ssl_attack_block_name_list_uuid = json_data['ssl_attack_block_name_list_uuid']
        sys_abnormal_handle.objects.filter(user_id=user_id).update(
            bypass_check=bypass_check,
            same_name_args_check=same_name_args_check, truncated_agrs_check=truncated_agrs_check, ssl_attack_check=ssl_attack_check,
            ssl_attack_count=ssl_attack_count, ssl_attack_count_stat_time_period=ssl_attack_count_stat_time_period,
            ssl_attack_block_name_list_uuid=ssl_attack_block_name_list_uuid)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_abnormal_handle(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        sys_abnormal_handle_result = sys_abnormal_handle.objects.get(user_id=user_id)
        data['bypass_check'] = sys_abnormal_handle_result.bypass_check
        data['same_name_args_check'] = sys_abnormal_handle_result.same_name_args_check
        data['truncated_agrs_check'] = sys_abnormal_handle_result.truncated_agrs_check
        data['ssl_attack_check'] = sys_abnormal_handle_result.ssl_attack_check
        data['ssl_attack_count'] = sys_abnormal_handle_result.ssl_attack_count
        data['ssl_attack_count_stat_time_period'] = sys_abnormal_handle_result.ssl_attack_count_stat_time_period
        data['ssl_attack_block_name_list_uuid'] = sys_abnormal_handle_result.ssl_attack_block_name_list_uuid
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)