from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q


def api_get_cc_protection(request):
    return_result = {}
    data = {}
    try:
        json_data = json.loads(request.body)
        api_key = json_data['api_key']
        api_password = json_data['api_password']
        user_result = jxwaf_user.objects.get(Q(user_id=api_key) & Q(api_password=api_password))
        user_id = user_result.user_id
    except:
        return_result['result'] = False
        return_result['errCode'] = 401
        return_result['message'] = "api_key or api_password error"
        return JsonResponse(return_result, safe=False)
    try:
        json_data = json.loads(request.body)
        domain = json_data['domain']
        try:
            result = waf_cc_protection.objects.get(Q(user_id=user_id) & Q(domain=domain))
        except:
            waf_cc_protection.objects.create(user_id=user_id, domain=domain)
            result = waf_cc_protection.objects.get(Q(user_id=user_id) & Q(domain=domain))
        data['count'] = result.count
        data['black_ip_time'] = result.black_ip_time
        data['ip_qps'] = result.ip_qps
        data['count_check'] = result.count_check
        data['qps_check'] = result.qps_check
        data['ip_expire_qps'] = result.ip_expire_qps
        data['req_count_handle_mode'] = result.req_count_handle_mode
        data['req_freq_handle_mode'] = result.req_freq_handle_mode
        data['domain_qps_check'] = result.domain_qps_check
        data['domain_qps'] = result.domain_qps
        data['domin_qps_handle_mode'] = result.domin_qps_handle_mode
        data['bot_check_mode'] = result.bot_check_mode
        data['emergency_mode_check'] = result.emergency_mode_check
        data['emergency_handle_mode'] = result.emergency_handle_mode
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)


def api_edit_cc_protection(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        api_key = json_data['api_key']
        api_password = json_data['api_password']
        user_result = jxwaf_user.objects.get(Q(user_id=api_key) & Q(api_password=api_password))
        user_id = user_result.user_id
    except:
        return_result['result'] = False
        return_result['errCode'] = 401
        return_result['message'] = "api_key or api_password error"
        return JsonResponse(return_result, safe=False)
    try:
        json_data = json.loads(request.body)
        domain = json_data['domain']
        count = json_data['count']
        count_check = json_data['count_check']
        qps_check = json_data['qps_check']
        black_ip_time = json_data['black_ip_time']
        ip_qps = json_data['ip_qps']
        ip_expire_qps = json_data['ip_expire_qps']
        req_count_handle_mode = json_data['req_count_handle_mode']
        req_freq_handle_mode = json_data['req_freq_handle_mode']
        domain_qps_check = json_data['domain_qps_check']
        domain_qps = json_data['domain_qps']
        domin_qps_handle_mode = json_data['domin_qps_handle_mode']
        bot_check_mode = json_data['bot_check_mode']
        emergency_mode_check = json_data['emergency_mode_check']
        emergency_handle_mode = json_data['emergency_handle_mode']
        waf_cc_protection.objects.filter(user_id=user_id).filter(domain=domain).update(
            req_count_handle_mode=req_count_handle_mode, req_freq_handle_mode=req_freq_handle_mode,
            domain_qps_check=domain_qps_check,
            count=count,
            black_ip_time=black_ip_time, ip_qps=ip_qps, ip_expire_qps=ip_expire_qps, domain_qps=domain_qps,
            domin_qps_handle_mode=domin_qps_handle_mode,
            bot_check_mode=bot_check_mode, emergency_mode_check=emergency_mode_check,
            emergency_handle_mode=emergency_handle_mode,count_check=count_check,qps_check=qps_check)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)