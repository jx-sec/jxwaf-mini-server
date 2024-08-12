from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import time
from django.http import HttpResponse


def waf_get_scan_attack_protection_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        results = waf_scan_attack_protection.objects.filter(user_id=user_id).filter(
            domain=domain).order_by('rule_order_time')
        for result in results:
            data.append({'rule_name': result.rule_name,
                         'rule_detail': result.rule_detail,
                         'rule_module': result.rule_module,
                         'statics_object': result.statics_object,
                         'statics_time': result.statics_time,
                         'statics_count': result.statics_count,
                         'rule_action': result.rule_action,
                         'action_value': result.action_value,
                         'status': result.status,
                         'rule_order_time': result.rule_order_time
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_scan_attack_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        try:
            waf_scan_attack_protection.objects.filter(user_id=user_id).filter(domain=domain).filter(
                rule_name=rule_name).delete()
            return_result['result'] = True
            return_result['message'] = 'del_success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'del_error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_scan_attack_protection_status(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        status = json_data['status']
        try:
            waf_scan_attack_protection.objects.filter(rule_name=rule_name).filter(user_id=user_id).filter(
                domain=domain).update(
                status=status)
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = 'edit_error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_scan_attack_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        rule_detail = json_data['rule_detail']
        rule_module = json_data['rule_module']
        statics_object = json_data['statics_object']
        statics_time = json_data['statics_time']
        statics_count = json_data['statics_count']
        rule_action = json_data['rule_action']
        action_value = json_data['action_value']
        try:
            waf_scan_attack_protection.objects.filter(domain=domain).filter(user_id=user_id).filter(
                rule_name=rule_name).update(
                rule_detail=rule_detail, rule_module=rule_module, statics_object=statics_object,
                statics_time=statics_time, statics_count=statics_count,
                rule_action=rule_action, action_value=action_value
            )
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_scan_attack_protection(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        result = waf_scan_attack_protection.objects.get(Q(user_id=user_id) & Q(domain=domain) & Q(rule_name=rule_name))
        data['rule_detail'] = result.rule_detail
        data['rule_module'] = result.rule_module
        data['statics_object'] = result.statics_object
        data['statics_time'] = result.statics_time
        data['statics_count'] = result.statics_count
        data['rule_action'] = result.rule_action
        data['action_value'] = result.action_value
        data['rule_order_time'] = result.rule_order_time
        return_result['message'] = data
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_create_scan_attack_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        rule_detail = json_data['rule_detail']
        rule_module = json_data['rule_module']
        statics_object = json_data['statics_object']
        statics_time = json_data['statics_time']
        statics_count = json_data['statics_count']
        rule_action = json_data['rule_action']
        action_value = json_data['action_value']
        rule_count = waf_scan_attack_protection.objects.filter(user_id=user_id).filter(domain=domain).filter(
            rule_name=rule_name).count()
        if rule_count != 0:
            return_result['message'] = 'already_exists_rule'
            return_result['result'] = False
            return JsonResponse(return_result, safe=False)
        waf_scan_attack_protection.objects.create(user_id=user_id, rule_name=rule_name, rule_detail=rule_detail,
                                                  rule_module=rule_module, statics_object=statics_object,
                                                  statics_time=statics_time, statics_count=statics_count,
                                                  rule_action=rule_action,
                                                  action_value=action_value,
                                                  rule_order_time=int(time.time()), domain=domain)

        return_result['message'] = 'create_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_exchange_scan_attack_protection_priority(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        type = json_data['type']
        if type == "top":
            rule_name = json_data['rule_name']
            results = waf_scan_attack_protection.objects.filter(domain=domain).filter(
                user_id=user_id).order_by('rule_order_time')
            result = results[0]
            waf_scan_attack_protection.objects.filter(domain=domain).filter(user_id=user_id).filter(
                rule_name=rule_name).update(
                rule_order_time=int(result.rule_order_time) - 1)
        elif type == "exchange":
            rule_name = json_data['rule_name']
            exchange_rule_name = json_data['exchange_rule_name']
            rule_name_result = waf_scan_attack_protection.objects.get(
                Q(domain=domain) & Q(user_id=user_id) & Q(rule_name=rule_name))
            exchange_rule_name_result = waf_scan_attack_protection.objects.get(
                Q(domain=domain) & Q(user_id=user_id) & Q(rule_name=exchange_rule_name))
            waf_scan_attack_protection.objects.filter(domain=domain).filter(user_id=user_id).filter(
                rule_name=rule_name).update(
                rule_order_time=exchange_rule_name_result.rule_order_time)
            waf_scan_attack_protection.objects.filter(domain=domain).filter(user_id=user_id).filter(
                rule_name=exchange_rule_name).update(rule_order_time=rule_name_result.rule_order_time)
        return_result['result'] = True
        return_result['message'] = 'exchange priority success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_load_scan_attack_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rules = json_data['rules']
        for rule in rules:
            rule_name = rule['rule_name']
            rule_detail = rule['rule_detail']
            rule_matchs = rule['rule_matchs']
            rule_action = rule['rule_action']
            action_value = rule['action_value']
            rule_count = waf_scan_attack_protection.objects.filter(user_id=user_id).filter(domain=domain).filter(
                rule_name=rule_name).count()
            if rule_count != 0:
                continue
            waf_scan_attack_protection.objects.create(user_id=user_id, rule_name=rule_name, rule_detail=rule_detail,
                                                      rule_matchs=rule_matchs, rule_action=rule_action,
                                                      action_value=action_value,
                                                      rule_order_time=int(time.time()), domain=domain)
        return_result['message'] = 'load_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_backup_scan_attack_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name_list = json_data['rule_name_list']
        rules = []
        for rule_name in rule_name_list:
            rule_name_result = waf_scan_attack_protection.objects.get(
                Q(user_id=user_id) & Q(domain=domain) & Q(rule_name=rule_name))
            rules.append({
                'rule_name': rule_name_result.rule_name,
                'rule_detail': rule_name_result.rule_detail,
                'rule_matchs': rule_name_result.rule_matchs,
                'rule_action': rule_name_result.rule_action,
                'action_value': rule_name_result.action_value
            }
            )
        response = HttpResponse(json.dumps(rules), content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename="web_white_rule_data.json"'
        return response
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
