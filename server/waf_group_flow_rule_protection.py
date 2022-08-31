from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import time


def waf_get_group_flow_rule_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        waf_group_flow_rule_protection_results = waf_group_flow_rule_protection.objects.filter(user_id=user_id).filter(
            group_id=group_id).order_by('rule_order_time')
        for result in waf_group_flow_rule_protection_results:
            if result.rule_type == "single_rule":
                sys_rule_result = sys_flow_rule_protection.objects.get(
                    Q(user_id=user_id) & Q(rule_uuid=result.uuid))
                data.append({'rule_uuid': result.uuid,
                             'rule_status': result.rule_status,
                             'rule_order_time': result.rule_order_time,
                             'rule_detail': sys_rule_result.rule_detail,
                             'rule_type': result.rule_type,
                             'rule_name': sys_rule_result.rule_name
                             }
                            )
            elif result.rule_type == "group_rule":
                group_sys_rule_result = sys_flow_rule_protection_group.objects.get(
                    Q(user_id=user_id) & Q(rule_group_uuid=result.uuid))
                data.append({'rule_uuid': result.uuid,
                             'rule_status': result.rule_status,
                             'rule_order_time': result.rule_order_time,
                             'rule_detail': group_sys_rule_result.rule_group_detail,
                             'rule_type': result.rule_type,
                             'rule_name': group_sys_rule_result.rule_group_name
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


def waf_del_group_flow_rule(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        rule_uuid = json_data['rule_uuid']
        try:
            waf_group_flow_rule_protection.objects.filter(user_id=user_id).filter(group_id=group_id).filter(
                uuid=rule_uuid).delete()
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


def waf_load_group_flow_rule(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        rule_uuid = json_data['rule_uuid']
        rule_type = json_data['rule_type']
        try:
            if rule_type == "single_rule":
                sys_flow_rule_protection.objects.get(Q(user_id=user_id) & Q(rule_uuid=rule_uuid))
                results = waf_group_flow_rule_protection.objects.filter(user_id=user_id).filter(uuid=rule_uuid)
                if len(results) == 0:
                    waf_group_flow_rule_protection.objects.create(user_id=user_id, group_id=group_id, uuid=rule_uuid,
                                                            rule_type="single_rule", rule_order_time=int(time.time()))
                else:
                    return_result['result'] = True
                    return_result['message'] = 'create fail,rule is exist'
                    return JsonResponse(return_result, safe=False)
            elif rule_type == "group_rule":
                sys_flow_rule_protection_group.objects.get(Q(user_id=user_id) & Q(rule_group_uuid=rule_uuid))
                results = waf_group_flow_rule_protection.objects.filter(user_id=user_id).filter(uuid=rule_uuid)
                if len(results) == 0:
                    waf_group_flow_rule_protection.objects.create(user_id=user_id, group_id=group_id, uuid=rule_uuid,
                                                            rule_type="group_rule", rule_order_time=int(time.time()))
                else:
                    return_result['result'] = True
                    return_result['message'] = 'create fail,rule is exist'
                    return JsonResponse(return_result, safe=False)
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


def waf_edit_group_flow_rule(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        rule_uuid = json_data['rule_uuid']
        rule_status = json_data['rule_status']
        try:
            waf_group_flow_rule_protection.objects.filter(group_id=group_id).filter(user_id=user_id).filter(
                uuid=rule_uuid).update(
                rule_status=rule_status)
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

def waf_exchange_group_flow_rule_priority(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        type = json_data['type']
        if type == "top":
            rule_uuid = json_data['rule_uuid']
            waf_group_flow_rule_protection_results = waf_group_flow_rule_protection.objects.filter(group_id=group_id).filter(
                user_id=user_id).order_by('rule_order_time')
            waf_group_flow_rule_protection_result = waf_group_flow_rule_protection_results[0]
            waf_group_flow_rule_protection.objects.filter(group_id=group_id).filter(user_id=user_id).filter(uuid=rule_uuid).update(
                rule_order_time=int(waf_group_flow_rule_protection_result.rule_order_time) - 1)
        elif type == "exchange":
            rule_uuid = json_data['rule_uuid']
            exchange_rule_uuid = json_data['exchange_rule_uuid']
            rule_uuid_result = waf_group_flow_rule_protection.objects.get(
                Q(group_id=group_id) & Q(user_id=user_id) & Q(uuid=rule_uuid))
            exchange_rule_uuid_result = waf_group_flow_rule_protection.objects.get(
                Q(group_id=group_id) & Q(user_id=user_id) & Q(uuid=exchange_rule_uuid))
            waf_group_flow_rule_protection.objects.filter(group_id=group_id).filter(user_id=user_id).filter(uuid=rule_uuid).update(
                rule_order_time=exchange_rule_uuid_result.rule_order_time)
            waf_group_flow_rule_protection.objects.filter(group_id=group_id).filter(user_id=user_id).filter(
                uuid=exchange_rule_uuid).update(rule_order_time=rule_uuid_result.rule_order_time)
        return_result['result'] = True
        return_result['message'] = 'exchange priority success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
