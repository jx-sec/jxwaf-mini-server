from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q


def waf_edit_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        owasp_protection = json_data['owasp_protection']
        cc_protection = json_data['cc_protection']
        cc_attack_ip_protection = json_data['cc_attack_ip_protection']
        custom_protection = json_data['custom_protection']
        page_custom = json_data['page_custom']
        evil_ip_handle = json_data['evil_ip_handle']
        ip_config = json_data['ip_config']
        data_mask = json_data['data_mask']
        rule_engine = json_data['rule_engine']
        try:
            waf_protection.objects.get(Q(domain=domain) & Q(user_id=user_id))
            user = jxwaf_user.objects.get(user_id=user_id)
            waf_protection.objects.filter(domain=domain).filter(user_id=user_id).update(
                owasp_protection=owasp_protection, cc_protection=cc_protection,
                cc_attack_ip_protection=cc_attack_ip_protection,
                custom_protection=custom_protection,
                page_custom=page_custom, email=user.email, evil_ip_handle=evil_ip_handle, ip_config=ip_config,
                data_mask=data_mask, rule_engine=rule_engine)
            return_result['result'] = True
            return_result['message'] = 'edit success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_protection(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        waf_protection_result = waf_protection.objects.get(Q(domain=domain) & Q(user_id=user_id))
        data['domain'] = waf_protection_result.domain
        data['owasp_protection'] = waf_protection_result.owasp_protection
        data['cc_attack_ip_protection'] = waf_protection_result.cc_attack_ip_protection
        data['custom_protection'] = waf_protection_result.custom_protection
        data['page_custom'] = waf_protection_result.page_custom
        data['cc_protection'] = waf_protection_result.cc_protection
        data['evil_ip_handle'] = waf_protection_result.evil_ip_handle
        data['ip_config'] = waf_protection_result.ip_config
        data['data_mask'] = waf_protection_result.data_mask
        data['rule_engine'] = waf_protection_result.rule_engine
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
