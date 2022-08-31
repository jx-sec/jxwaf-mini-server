from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_group_flow_engine_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        high_freq_cc_check = json_data['high_freq_cc_check']
        req_count = json_data['req_count']
        req_count_stat_time_period = json_data['req_count_stat_time_period']
        req_count_block_mode = json_data['req_count_block_mode']
        req_count_block_mode_extra_parameter = json_data['req_count_block_mode_extra_parameter']
        req_rate = json_data['req_rate']
        req_rate_block_mode = json_data['req_rate_block_mode']
        req_rate_block_mode_extra_parameter = json_data['req_rate_block_mode_extra_parameter']
        slow_cc_check = json_data['slow_cc_check']
        domain_rate = json_data['domain_rate']
        slow_cc_block_mode = json_data['slow_cc_block_mode']
        slow_cc_block_mode_extra_parameter = json_data['slow_cc_block_mode_extra_parameter']
        ip_count = json_data['ip_count']
        ip_count_stat_time_period = json_data['ip_count_stat_time_period']
        ip_count_block_mode = json_data['ip_count_block_mode']
        ip_count_block_mode_extra_parameter = json_data['ip_count_block_mode_extra_parameter']
        emergency_mode_check = json_data['emergency_mode_check']
        emergency_mode_block_mode = json_data['emergency_mode_block_mode']
        emergency_mode_block_mode_extra_parameter = json_data['emergency_mode_block_mode_extra_parameter']
        waf_group_flow_engine_protection.objects.filter(user_id=user_id).filter(group_id=group_id).update(
            high_freq_cc_check=high_freq_cc_check,
            req_count=req_count, req_count_stat_time_period=req_count_stat_time_period,
            req_count_block_mode=req_count_block_mode,
            req_count_block_mode_extra_parameter=req_count_block_mode_extra_parameter, req_rate=req_rate,
            req_rate_block_mode=req_rate_block_mode,
            req_rate_block_mode_extra_parameter=req_rate_block_mode_extra_parameter, slow_cc_check=slow_cc_check,
            domain_rate=domain_rate, slow_cc_block_mode=slow_cc_block_mode,
            slow_cc_block_mode_extra_parameter=slow_cc_block_mode_extra_parameter,
            emergency_mode_check=emergency_mode_check, emergency_mode_block_mode=emergency_mode_block_mode,
            emergency_mode_block_mode_extra_parameter=emergency_mode_block_mode_extra_parameter, ip_count=ip_count,
            ip_count_stat_time_period=ip_count_stat_time_period, ip_count_block_mode=ip_count_block_mode,
            ip_count_block_mode_extra_parameter=ip_count_block_mode_extra_parameter)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_group_flow_engine_protection(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        try:
            waf_group_flow_engine_protection_results = waf_group_flow_engine_protection.objects.get(
                Q(group_id=group_id) & Q(user_id=user_id))
        except:
            waf_group_flow_engine_protection.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_flow_engine_protection.objects.create(user_id=user_id, group_id=group_id)
            waf_group_flow_engine_protection_results = waf_group_flow_engine_protection.objects.get(
                Q(group_id=group_id) & Q(user_id=user_id))
        data['high_freq_cc_check'] = waf_group_flow_engine_protection_results.high_freq_cc_check
        data['req_count'] = waf_group_flow_engine_protection_results.req_count
        data['req_count_stat_time_period'] = waf_group_flow_engine_protection_results.req_count_stat_time_period
        data['req_count_block_mode'] = waf_group_flow_engine_protection_results.req_count_block_mode
        data[
            'req_count_block_mode_extra_parameter'] = waf_group_flow_engine_protection_results.req_count_block_mode_extra_parameter
        data['req_rate'] = waf_group_flow_engine_protection_results.req_rate
        data['req_rate_block_mode'] = waf_group_flow_engine_protection_results.req_rate_block_mode

        data[
            'req_rate_block_mode_extra_parameter'] = waf_group_flow_engine_protection_results.req_rate_block_mode_extra_parameter
        data['slow_cc_check'] = waf_group_flow_engine_protection_results.slow_cc_check
        data['domain_rate'] = waf_group_flow_engine_protection_results.domain_rate
        data['slow_cc_block_mode'] = waf_group_flow_engine_protection_results.slow_cc_block_mode
        data[
            'slow_cc_block_mode_extra_parameter'] = waf_group_flow_engine_protection_results.slow_cc_block_mode_extra_parameter
        data['emergency_mode_check'] = waf_group_flow_engine_protection_results.emergency_mode_check
        data['emergency_mode_block_mode'] = waf_group_flow_engine_protection_results.emergency_mode_block_mode
        data[
            'emergency_mode_block_mode_extra_parameter'] = waf_group_flow_engine_protection_results.emergency_mode_block_mode_extra_parameter
        data[
            'ip_count'] = waf_group_flow_engine_protection_results.ip_count
        data['ip_count_stat_time_period'] = waf_group_flow_engine_protection_results.ip_count_stat_time_period
        data['ip_count_block_mode'] = waf_group_flow_engine_protection_results.ip_count_block_mode
        data[
            'ip_count_block_mode_extra_parameter'] = waf_group_flow_engine_protection_results.ip_count_block_mode_extra_parameter
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
