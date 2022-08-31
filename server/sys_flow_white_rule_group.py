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


def waf_get_sys_flow_white_rule_group_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        results = sys_flow_white_rule_group.objects.filter(user_id=user_id)
        for result in results:
            sys_flow_white_rule_count = sys_flow_white_rule.objects.filter(user_id=user_id).filter(
                rule_group_uuid=result.rule_group_uuid).count()
            waf_domain_count = waf_flow_rule_protection.objects.filter(user_id=user_id).filter(
                uuid=result.rule_group_uuid).count()
            waf_group_domain_count = waf_group_flow_rule_protection.objects.filter(user_id=user_id).filter(
                uuid=result.rule_group_uuid).count()
            data.append({'rule_group_uuid': result.rule_group_uuid,
                         'rule_group_name': result.rule_group_name,
                         'rule_group_detail': result.rule_group_detail,
                         'rule_count': sys_flow_white_rule_count,
                         'waf_domain_count': waf_domain_count,
                         'waf_group_domain_count': waf_group_domain_count
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


def waf_del_sys_flow_white_rule_group(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        rule_group_uuid = json_data['rule_group_uuid']
        try:
            sys_flow_white_rule_count = sys_flow_white_rule.objects.filter(user_id=user_id).filter(
                rule_group_uuid=rule_group_uuid).count()
            if sys_flow_white_rule_count > 0:
                return_result['result'] = False
                return_result['message'] = 'del error,exist rule'
                return JsonResponse(return_result, safe=False)
            sys_flow_white_rule_group.objects.filter(user_id=user_id).filter(
                rule_group_uuid=rule_group_uuid).delete()
            sys_flow_white_rule.objects.filter(user_id=user_id).filter(
                rule_group_uuid=rule_group_uuid).delete()
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


def waf_edit_sys_flow_white_rule_group(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        rule_group_uuid = json_data['rule_group_uuid']
        rule_group_name = json_data['rule_group_name']
        rule_group_detail = json_data['rule_group_detail']
        try:
            sys_flow_white_rule_group.objects.filter(rule_group_uuid=rule_group_uuid).filter(
                user_id=user_id).filter(rule_group_name=rule_group_name).update(
                rule_group_detail=rule_group_detail)
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


def waf_create_sys_flow_white_rule_group(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        rule_group_name = json_data['rule_group_name']
        rule_group_detail = json_data['rule_group_detail']
        try:
            result = sys_flow_white_rule_group.objects.filter(user_id=user_id).filter(
                rule_group_name=rule_group_name)
            if len(result) == 0:
                sys_flow_white_rule_group.objects.create(user_id=user_id, rule_group_name=rule_group_name,
                                                             rule_group_detail=rule_group_detail)
            else:
                return_result['result'] = False
                return_result['message'] = 'rule_group_name is exist'
                return_result['errCode'] = 504
                return JsonResponse(return_result, safe=False)
            return_result['result'] = True
            return_result['message'] = 'create success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = 'create error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_search_sys_flow_white_rule_group(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        search_type = json_data['search_type']
        search_value = json_data['search_value']
        try:
            page = json_data['page']
        except:
            page = 1
        if search_type == "rule_group_uuid":
            results = sys_flow_white_rule_group.objects.filter(user_id=user_id).filter(
                rule_type="single_rule").filter(
                rule_group_uuid__contains=search_value)
        elif search_type == "rule_group_name":
            results = sys_flow_white_rule_group.objects.filter(user_id=user_id).filter(
                rule_type="single_rule").filter(
                rule_group_name__contains=search_value)
        else:
            results = sys_flow_white_rule_group.objects.filter(user_id=user_id).filter(rule_type="single_rule")
        paginator = Paginator(results, 50)
        is_error = False
        try:
            page_results = paginator.page(int(page))
        except:
            is_error = True
            page_results = paginator.page(1)
        for result in page_results.object_list:
            data.append({'rule_group_uuid': result.rule_group_uuid,
                         'rule_group_name': result.rule_group_name,
                         'rule_group_detail': result.rule_group_detail
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return_result['count'] = paginator.count
        return_result['num_pages'] = paginator.num_pages
        if is_error == True:
            return_result['now_page'] = 1
        else:
            return_result['now_page'] = page_results.number
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)

def waf_get_sys_flow_white_rule_group(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        rule_group_uuid = json_data['rule_group_uuid']
        result = sys_flow_white_rule_group.objects.get(Q(user_id=user_id) & Q(rule_group_uuid=rule_group_uuid))
        data['rule_group_uuid'] = result.rule_group_uuid
        data['rule_group_name'] = result.rule_group_name
        data['rule_group_detail'] = result.rule_group_detail
        return_result['message'] = data
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
