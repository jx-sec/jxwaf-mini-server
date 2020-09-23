from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q


def waf_get_evil_ip_handle(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        try:
            result = waf_evil_ip_conf.objects.get(Q(user_id=user_id) & Q(domain=domain))
        except:
            waf_evil_ip_conf.objects.create(user_id=user_id, domain=domain)
            result = waf_evil_ip_conf.objects.get(Q(user_id=user_id) & Q(domain=domain))
        data['period'] = result.period
        data['count'] = result.count
        data['mode'] = result.mode
        data['handle'] = result.handle
        data['block_option'] = result.block_option
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)


def waf_edit_evil_ip_handle(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        period = json_data['period']
        count = json_data['count']
        mode = json_data['mode']
        handle = json_data['handle']
        block_option = json_data['block_option']
        waf_evil_ip_conf.objects.filter(user_id=user_id).filter(domain=domain).update(
            period=period, mode=mode, handle=handle, count=count,block_option=block_option)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)
