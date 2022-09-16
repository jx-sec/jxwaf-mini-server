# -*- coding:utf-8 –*-
from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import sys

reload(sys)
sys.setdefaultencoding('utf8')


def waf_get_group_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        waf_group_id_results = waf_group_id.objects.filter(user_id=user_id)
        for result in waf_group_id_results:
            try:
                waf_group_protection_result = waf_group_protection.objects.get(
                    Q(user_id=user_id) & Q(group_id=result.group_id))
            except:
                return_result['result'] = True
                return_result['message'] = data
                return JsonResponse(return_result, safe=False)
            waf_group_domain_results = waf_group_domain.objects.filter(user_id=user_id).filter(group_id=result.group_id)
            data.append({'group_id': result.group_id,
                         'group_name': result.group_name,
                         'group_detail': result.group_detail,
                         'web_engine_protection': waf_group_protection_result.web_engine_protection,
                         'web_rule_protection': waf_group_protection_result.web_rule_protection,
                         'flow_engine_protection': waf_group_protection_result.flow_engine_protection,
                         'flow_rule_protection': waf_group_protection_result.flow_rule_protection,
                         'name_list': waf_group_protection_result.name_list,
                         'domain_count': len(waf_group_domain_results)
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


def waf_del_group(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        group_name = json_data['group_name']
        try:
            waf_group_id.objects.get(Q(user_id=user_id) & Q(group_name=group_name) & Q(group_id=group_id))
            waf_group_id.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_protection.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_domain.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_web_engine_protection.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_web_rule_protection.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_web_white_rule.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_web_deny_page.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_flow_engine_protection.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_flow_rule_protection.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_flow_white_rule.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_flow_deny_page.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_name_list.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
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


def waf_create_group(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_name = json_data['group_name']
        group_detail = json_data['group_detail']
        try:
            result = waf_group_id.objects.filter(user_id=user_id).filter(group_name=group_name)
            if len(result) != 0:
                return_result['result'] = False
                return_result['message'] = 'create error,group_name is exist'
                return JsonResponse(return_result, safe=False)
            waf_group_id.objects.create(user_id=user_id, group_name=group_name, group_detail=group_detail)
            waf_group_id_result = waf_group_id.objects.get(Q(user_id=user_id) & Q(group_name=group_name))
            waf_group_protection.objects.filter(user_id=user_id).filter(group_id=waf_group_id_result.group_id).delete()
            waf_group_protection.objects.create(user_id=user_id, group_id=waf_group_id_result.group_id)
            waf_group_web_engine_protection.objects.filter(user_id=user_id).filter(group_id=waf_group_id_result.group_id).delete()
            waf_group_web_engine_protection.objects.create(user_id=user_id, group_id=waf_group_id_result.group_id)
            waf_group_flow_engine_protection.objects.filter(user_id=user_id).filter(group_id=waf_group_id_result.group_id).delete()
            waf_group_flow_engine_protection.objects.create(user_id=user_id, group_id=waf_group_id_result.group_id)
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


def waf_edit_group(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        group_detail = json_data['group_detail']
        try:
            waf_group_id.objects.filter(user_id=user_id).filter(group_id=group_id).update(group_detail=group_detail)
            return_result['result'] = True
            return_result['message'] = 'edit success'
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


def waf_get_group(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        try:
            waf_group_id_result = waf_group_id.objects.get(Q(group_id=group_id) & Q(user_id=user_id))
            data['group_id'] = waf_group_id_result.group_id
            data['group_name'] = waf_group_id_result.group_name
            data['group_detail'] = waf_group_id_result.group_detail
            return_result['result'] = True
            return_result['message'] = data
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
