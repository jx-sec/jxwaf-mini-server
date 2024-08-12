from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        web_engine_protection = json_data['web_engine_protection']
        web_rule_protection = json_data['web_rule_protection']
        web_white_rule = json_data['web_white_rule']
        flow_engine_protection = json_data['flow_engine_protection']
        flow_rule_protection = json_data['flow_rule_protection']
        flow_white_rule = json_data['flow_white_rule']
        flow_ip_region_block = json_data['flow_ip_region_block']
        scan_attack_protection = json_data['scan_attack_protection']
        web_page_tamper_proof = json_data['web_page_tamper_proof']
        flow_black_ip = json_data['flow_black_ip']
        try:
            waf_protection.objects.get(Q(domain=domain) & Q(user_id=user_id))
            waf_protection.objects.filter(domain=domain).filter(user_id=user_id).update(
                web_engine_protection=web_engine_protection, web_rule_protection=web_rule_protection,
                web_white_rule=web_white_rule,
                flow_ip_region_block=flow_ip_region_block,
                flow_engine_protection=flow_engine_protection,
                flow_rule_protection=flow_rule_protection, flow_white_rule=flow_white_rule,
                scan_attack_protection=scan_attack_protection,web_page_tamper_proof=web_page_tamper_proof,
                flow_black_ip=flow_black_ip
            )
            return_result['result'] = True
            return_result['message'] = 'edit success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
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
        try:
            waf_protection_result = waf_protection.objects.get(Q(domain=domain) & Q(user_id=user_id))
        except:
            waf_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_protection.objects.create(user_id=user_id, domain=domain)
            waf_protection_result = waf_protection.objects.get(Q(domain=domain) & Q(user_id=user_id))
        data['domain'] = waf_protection_result.domain
        data['web_engine_protection'] = waf_protection_result.web_engine_protection
        data['web_rule_protection'] = waf_protection_result.web_rule_protection
        data['web_white_rule'] = waf_protection_result.web_white_rule
        data['flow_engine_protection'] = waf_protection_result.flow_engine_protection
        data['flow_rule_protection'] = waf_protection_result.flow_rule_protection
        data['flow_white_rule'] = waf_protection_result.flow_white_rule
        data['flow_ip_region_block'] = waf_protection_result.flow_ip_region_block
        data['scan_attack_protection'] = waf_protection_result.scan_attack_protection
        data['web_page_tamper_proof'] = waf_protection_result.web_page_tamper_proof
        data['flow_black_ip'] = waf_protection_result.flow_black_ip
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
