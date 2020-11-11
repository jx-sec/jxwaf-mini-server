from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q
import time


def waf_get_rule_engine_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        waf_rule_engine_results = waf_rule_engine.objects.filter(user_id=user_id).filter(domain=domain)
        for result in waf_rule_engine_results:
            data.append({'rule_name': result.rule_name,
                         'detail': result.detail,
                         'check_uri': result.check_uri,
                         'check_content': result.check_content,
                         'content_handle': result.content_handle,
                         'content_match': result.content_match,
                         'match_action': result.match_action,
                         'white_url': result.white_url,
                         'flow_filter': result.flow_filter
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_rule_engine(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        try:
            waf_rule_engine.objects.filter(user_id=user_id).filter(domain=domain).filter(rule_name=rule_name).delete()
            return_result['result'] = True
            return_result['message'] = 'del success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'del error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_rule_engine(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        detail = json_data['detail']
        check_uri = json_data['check_uri']
        check_content = json_data['check_content']
        content_handle = json_data['content_handle']
        content_match = json_data['content_match']
        match_action = json_data['match_action']
        white_url = json_data['white_url']
        flow_filter = json_data['flow_filter']
        try:
            waf_rule_engine.objects.filter(domain=domain).filter(user_id=user_id).filter(rule_name=rule_name).update(
                detail=detail, check_uri=check_uri, check_content=check_content, content_handle=content_handle,
                content_match=content_match, match_action=match_action, white_url=white_url,flow_filter=flow_filter)
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
