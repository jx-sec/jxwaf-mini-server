from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q


def waf_get_cc_attack_ip(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        try:
            result = waf_cc_attack_ip_conf.objects.get(Q(user_id=user_id) & Q(domain=domain))
        except:
            waf_cc_attack_ip_conf.objects.create(user_id=user_id,domain=domain)
            result = waf_cc_attack_ip_conf.objects.get(Q(user_id=user_id) & Q(domain=domain))
        data['block_option'] = result.block_option
        data['check_period'] = result.check_period
        data['check_count'] = result.check_count
        data['block_time'] = result.block_time
        data['block_mode'] = result.block_mode
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_cc_attack_ip(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        block_option = json_data['block_option']
        check_period = json_data['check_period']
        check_count = json_data['check_count']
        block_time = json_data['block_time']
        block_mode = json_data['block_mode']
        waf_cc_attack_ip_conf.objects.filter(user_id=user_id).filter(domain=domain).update(
            block_option=block_option, check_period=check_period,
            check_count=check_count,
            block_time=block_time,
            block_mode=block_mode)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)