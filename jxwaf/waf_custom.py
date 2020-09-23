from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q
import time


def waf_get_custom_rule_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        waf_custom_results = waf_custom_rule.objects.filter(user_id=user_id).filter(domain=domain)
        for result in waf_custom_results:
            data.append({'rule_id': result.rule_id,
                         'rule_action': result.rule_action,
                         'rule_level': result.rule_level,
                         'rule_name': result.rule_name,
                         'rule_log': result.rule_log,
                         'rule_matchs': result.rule_matchs
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def waf_api_get_custom_rule_list(request):
    return_result = {}
    data = []
    try:
        json_data = json.loads(request.body)
        waf_api_key = json_data['api_key']
        waf_api_password = json_data['api_password']
        user_result = jxwaf_user.objects.get(Q(user_id=waf_api_key) & Q(api_password=waf_api_password))
        user_id = user_result.user_id
        domain = json_data['domain']
        waf_custom_results = waf_custom_rule.objects.filter(user_id=user_id).filter(domain=domain)
        for result in waf_custom_results:
            data.append({'rule_id': result.rule_id,
                         'rule_action': result.rule_action,
                         'rule_level': result.rule_level,
                         'rule_name': result.rule_name,
                         'rule_log': result.rule_log,
                         'rule_matchs': result.rule_matchs
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def waf_del_custom_rule(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_id = json_data['rule_id']
        try:
            waf_custom_rule.objects.filter(user_id=user_id).filter(domain=domain).filter(rule_id=rule_id).delete()
            return_result['result'] = True
            return_result['message'] = 'del success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'del error'
            return_result['errCode'] = 108
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def waf_api_del_custom_rule(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        waf_api_key = json_data['api_key']
        waf_api_password = json_data['api_password']
        user_result = jxwaf_user.objects.get(Q(user_id=waf_api_key) & Q(api_password=waf_api_password))
        user_id = user_result.user_id
        domain = json_data['domain']
        rule_id = json_data['rule_id']
        try:
            waf_custom_rule.objects.filter(user_id=user_id).filter(domain=domain).filter(rule_id=rule_id).delete()
            return_result['result'] = True
            return_result['message'] = 'del success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'del error'
            return_result['errCode'] = 108
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)


def waf_create_custom_rule(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_action = json_data['rule_action']
        rule_level = json_data['rule_level']
        rule_name = json_data['rule_name']
        rule_log = json_data['rule_log']
        rule_matchs = json_data['rule_matchs']
        try:
            waf_custom_rule.objects.create(user_id=user_id, domain=domain, rule_action=rule_action,
                                           rule_level=rule_level,
                                           rule_name=rule_name,
                                           rule_log=rule_log, rule_matchs=rule_matchs,rule_id=int(time.time()))
            return_result['result'] = True
            return_result['message'] = 'create success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return_result['errCode'] = 108
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def waf_api_create_custom_rule(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        waf_api_key = json_data['api_key']
        waf_api_password = json_data['api_password']
        user_result = jxwaf_user.objects.get(Q(user_id=waf_api_key) & Q(api_password=waf_api_password))
        user_id = user_result.user_id
        domain = json_data['domain']
        rule_action = json_data['rule_action']
        rule_level = json_data['rule_level']
        rule_name = json_data['rule_name']
        rule_log = json_data['rule_log']
        rule_matchs = json_data['rule_matchs']
        try:
            waf_custom_rule.objects.create(user_id=user_id, domain=domain, rule_action=rule_action,
                                           rule_level=rule_level,
                                           rule_name=rule_name,
                                           rule_log=rule_log, rule_matchs=rule_matchs,rule_id=int(time.time()))
            return_result['result'] = True
            return_result['message'] = 'create success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return_result['errCode'] = 108
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def waf_edit_custom_rule(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_action = json_data['rule_action']
        rule_level = json_data['rule_level']
        rule_name = json_data['rule_name']
        rule_log = json_data['rule_log']
        rule_matchs = json_data['rule_matchs']
        rule_id = json_data['rule_id']
        try:
            waf_custom_rule.objects.filter(domain=domain).filter(user_id=user_id).filter(rule_id=rule_id).update(
                rule_action=rule_action, rule_level=rule_level, rule_name=rule_name, rule_log=rule_log,
                rule_matchs=rule_matchs)
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 108
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def waf_api_edit_custom_rule(request):
    return_result = {}
    try:
        json_data = json.loads(request.body)
        waf_api_key = json_data['api_key']
        waf_api_password = json_data['api_password']
        user_result = jxwaf_user.objects.get(Q(user_id=waf_api_key) & Q(api_password=waf_api_password))
        user_id = user_result.user_id
        domain = json_data['domain']
        rule_action = json_data['rule_action']
        rule_level = json_data['rule_level']
        rule_name = json_data['rule_name']
        rule_log = json_data['rule_log']
        rule_matchs = json_data['rule_matchs']
        rule_id = json_data['rule_id']
        try:
            waf_custom_rule.objects.filter(domain=domain).filter(user_id=user_id).filter(rule_id=rule_id).update(
                rule_action=rule_action, rule_level=rule_level, rule_name=rule_name, rule_log=rule_log,
                rule_matchs=rule_matchs)
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 108
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def waf_get_custom_rule(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_id = json_data['rule_id']
        waf_custom_rule_result = waf_custom_rule.objects.get(Q(domain=domain) & Q(user_id=user_id) & Q(rule_id=rule_id))
        data['domain'] = waf_custom_rule_result.domain
        data['rule_id'] = waf_custom_rule_result.rule_id
        data['rule_matchs'] = waf_custom_rule_result.rule_matchs
        data['rule_log'] = waf_custom_rule_result.rule_log
        data['rule_name'] = waf_custom_rule_result.rule_name
        data['rule_level'] = waf_custom_rule_result.rule_level
        data['rule_action'] = waf_custom_rule_result.rule_action
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def waf_api_get_custom_rule(request):
    return_result = {}
    data = {}
    try:
        json_data = json.loads(request.body)
        waf_api_key = json_data['api_key']
        waf_api_password = json_data['api_password']
        user_result = jxwaf_user.objects.get(Q(user_id=waf_api_key) & Q(api_password=waf_api_password))
        user_id = user_result.user_id
        domain = json_data['domain']
        rule_id = json_data['rule_id']
        waf_custom_rule_result = waf_custom_rule.objects.get(Q(domain=domain) & Q(user_id=user_id) & Q(rule_id=rule_id))
        data['domain'] = waf_custom_rule_result.domain
        data['rule_id'] = waf_custom_rule_result.rule_id
        data['rule_matchs'] = waf_custom_rule_result.rule_matchs
        data['rule_log'] = waf_custom_rule_result.rule_log
        data['rule_name'] = waf_custom_rule_result.rule_name
        data['rule_level'] = waf_custom_rule_result.rule_level
        data['rule_action'] = waf_custom_rule_result.rule_action
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)