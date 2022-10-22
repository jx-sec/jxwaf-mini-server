# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
import sys
import time
from django.core.paginator import Paginator
from django.db.models import Q

reload(sys)
sys.setdefaultencoding('utf8')


def waf_get_sys_web_rule_protection_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        rule_type = json_data['rule_type']
        if rule_type == "single_rule":
            results = sys_web_rule_protection.objects.filter(user_id=user_id).filter(rule_type=rule_type)
            for result in results:
                waf_domain_count = waf_web_rule_protection.objects.filter(user_id=user_id).filter(uuid).count()
                waf_group_domain_count = waf_group_web_rule_protection.objects.filter(user_id=user_id).filter(uuid).count()
                data.append({'rule_uuid': result.rule_uuid,
                             'rule_name': result.rule_name,
                             'rule_detail': result.rule_detail,
                             'rule_matchs': result.rule_matchs,
                             'rule_action': result.rule_action,
                             'action_value': result.action_value,
                             'rule_log': result.rule_log,
                             'update_time': result.update_time,
                             'waf_domain_count': waf_domain_count,
                             'waf_group_domain_count': waf_group_domain_count
                             }
                            )
            return_result['result'] = True
            return_result['message'] = data
            return JsonResponse(return_result, safe=False)
        elif rule_type == "group_rule":
            rule_group_uuid = json_data['rule_group_uuid']
            results = sys_web_rule_protection.objects.filter(user_id=user_id).filter(rule_type=rule_type).filter(
                rule_group_uuid=rule_group_uuid).order_by('rule_order_time')
            for result in results:
                data.append({'rule_uuid': result.rule_uuid,
                             'rule_group_uuid': result.rule_group_uuid,
                             'rule_name': result.rule_name,
                             'rule_detail': result.rule_detail,
                             'rule_matchs': result.rule_matchs,
                             'rule_action': result.rule_action,
                             'action_value': result.action_value,
                             'rule_log': result.rule_log,
                             'update_time': result.update_time
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


def waf_get_sys_web_rule_protection(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        rule_uuid = json_data['rule_uuid']
        result = sys_web_rule_protection.objects.get(Q(user_id=user_id) & Q(rule_uuid=rule_uuid))
        data['rule_uuid'] = result.rule_uuid
        data['rule_name'] = result.rule_name
        data['rule_detail'] = result.rule_detail
        data['rule_matchs'] = result.rule_matchs
        data['rule_action'] = result.rule_action
        data['action_value'] = result.action_value
        data['rule_log'] = result.rule_log
        data['update_time'] = result.update_time
        return_result['message'] = data
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_sys_web_rule_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        rule_uuid = json_data['rule_uuid']
        try:
            sys_web_rule_protection.objects.filter(user_id=user_id).filter(rule_uuid=rule_uuid).delete()
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


def waf_edit_sys_web_rule_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        rule_uuid = json_data['rule_uuid']
        rule_detail = json_data['rule_detail']
        rule_matchs = json_data['rule_matchs']
        rule_action = json_data['rule_action']
        action_value = json_data['action_value']
        rule_log = json_data['rule_log']
        try:
            sys_web_rule_protection.objects.filter(rule_uuid=rule_uuid).filter(user_id=user_id).update(
                rule_detail=rule_detail, rule_matchs=rule_matchs, rule_action=rule_action, action_value=action_value,
                rule_log=rule_log, update_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
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


def waf_create_sys_web_rule_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        rule_type = json_data['rule_type']
        rule_name = json_data['rule_name']
        rule_detail = json_data['rule_detail']
        rule_matchs = json_data['rule_matchs']
        rule_action = json_data['rule_action']
        action_value = json_data['action_value']
        rule_log = json_data['rule_log']
        rule_count = sys_web_rule_protection.objects.filter(user_id=user_id).filter(rule_name=rule_name).count()
        if rule_count != 0:
            return_result['message'] = 'already exists rule'
            return_result['result'] = False
            return JsonResponse(return_result, safe=False)
        if rule_type == "single_rule":
            sys_web_rule_protection.objects.create(user_id=user_id, rule_name=rule_name, rule_detail=rule_detail,
                                                   rule_matchs=rule_matchs, rule_action=rule_action,
                                                   action_value=action_value, rule_log=rule_log, rule_type=rule_type,
                                                   update_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
        elif rule_type == "group_rule":
            rule_group_uuid = json_data["rule_group_uuid"]
            sys_web_rule_protection_group_result = sys_web_rule_protection_group.objects.get(
                Q(user_id=user_id) & Q(rule_group_uuid=rule_group_uuid))
            sys_web_rule_protection.objects.create(user_id=user_id, rule_name=rule_name, rule_detail=rule_detail,
                                                   rule_matchs=rule_matchs, rule_action=rule_action,
                                                   action_value=action_value, rule_log=rule_log,
                                                   update_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                                                   rule_group_uuid=rule_group_uuid,
                                                   rule_group_name=sys_web_rule_protection_group_result.rule_group_name,
                                                   rule_order_time=int(time.time()), rule_type=rule_type)
        return_result['message'] = 'create success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_search_sys_web_rule_protection(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        search_type = json_data['search_type']
        search_value = json_data['search_value']
        if search_type == "rule_uuid":
            results = sys_web_rule_protection.objects.filter(user_id=user_id).filter(rule_type="single_rule").filter(
                rule_uuid__contains=search_value)
        elif search_type == "rule_name":
            results = sys_web_rule_protection.objects.filter(user_id=user_id).filter(rule_type="single_rule").filter(
                rule_name__contains=search_value)
        else:
            results = sys_web_rule_protection.objects.filter(user_id=user_id).filter(rule_type="single_rule")
        for result in results:
            data.append({'rule_uuid': result.rule_uuid,
                         'rule_name': result.rule_name,
                         'rule_detail': result.rule_detail,
                         'rule_matchs': result.rule_matchs,
                         'rule_action': result.rule_action,
                         'action_value': result.action_value,
                         'rule_log': result.rule_log,
                         'update_time': result.update_time
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
