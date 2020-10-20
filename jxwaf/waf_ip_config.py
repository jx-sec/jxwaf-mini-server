from django.http import JsonResponse
import json
from jxwaf.models import *


def waf_get_ip_rule_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        domain = json_date['domain']
        waf_ip_results = waf_ip_rule.objects.filter(user_id=user_id).filter(domain=domain)
        for result in waf_ip_results:
            data.append({'ip': result.ip,
                         'time': result.time,
                         'rule_action': result.rule_action
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


def waf_del_ip_rule(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        domain = json_date['domain']
        ip = json_date['ip']
        try:
            waf_ip_rule.objects.filter(user_id=user_id).filter(domain=domain).filter(ip=ip).delete()
            return_result['result'] = True
            return_result['message'] = 'del success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_create_ip_rule(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        ip = json_date['ip']
        rule_action = json_date['rule_action']
        domain = json_date['domain']
        ip_result = waf_ip_rule.objects.filter(user_id=user_id).filter(domain=domain).filter(ip=ip)
        if len(ip_result) != 0:
            return_result['result'] = False
            return_result['message'] = "ip is exist"
            return_result['errCode'] = 409
            return JsonResponse(return_result, safe=False)
        try:
            waf_ip_rule.objects.create(user_id=user_id, domain=domain, ip=ip,
                                           rule_action=rule_action, time=datetime.datetime.now())
            return_result['result'] = True
            return_result['message'] = 'create success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_ip_rule(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        ip = json_date['ip']
        rule_action = json_date['rule_action']
        domain = json_date['domain']
        try:
            waf_ip_rule.objects.filter(user_id=user_id).filter(domain=domain).filter(
                ip=ip).update(rule_action=rule_action)
            return_result['result'] = True
            return_result['message'] = 'edit success'
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
