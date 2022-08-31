from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_group_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        web_engine_protection = json_data['web_engine_protection']
        web_rule_protection = json_data['web_rule_protection']
        web_white_rule = json_data['web_white_rule']
        web_deny_page = json_data['web_deny_page']
        flow_engine_protection = json_data['flow_engine_protection']
        flow_rule_protection = json_data['flow_rule_protection']
        flow_white_rule = json_data['flow_white_rule']
        flow_deny_page = json_data['flow_deny_page']
        name_list = json_data['name_list']
        try:
            waf_group_protection.objects.get(Q(group_id=group_id) & Q(user_id=user_id))
            waf_group_protection.objects.filter(group_id=group_id).filter(user_id=user_id).update(
                web_engine_protection=web_engine_protection, web_rule_protection=web_rule_protection,
                web_white_rule=web_white_rule,
                web_deny_page=web_deny_page,
                flow_engine_protection=flow_engine_protection,
                flow_rule_protection=flow_rule_protection, flow_white_rule=flow_white_rule,
                flow_deny_page=flow_deny_page, name_list=name_list)
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


def waf_get_group_protection(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        waf_group_protection_result = waf_group_protection.objects.get(Q(group_id=group_id) & Q(user_id=user_id))
        data['web_engine_protection'] = waf_group_protection_result.web_engine_protection
        data['web_rule_protection'] = waf_group_protection_result.web_rule_protection
        data['web_white_rule'] = waf_group_protection_result.web_white_rule
        data['web_deny_page'] = waf_group_protection_result.web_deny_page
        data['flow_engine_protection'] = waf_group_protection_result.flow_engine_protection
        data['flow_rule_protection'] = waf_group_protection_result.flow_rule_protection
        data['flow_white_rule'] = waf_group_protection_result.flow_white_rule
        data['flow_deny_page'] = waf_group_protection_result.flow_deny_page
        data['name_list'] = waf_group_protection_result.name_list
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
