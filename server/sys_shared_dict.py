from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import time


def waf_get_sys_shared_dict_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        results = sys_shared_dict.objects.filter(user_id=user_id)
        for result in results:
            web_rule_protection_count = sys_web_rule_protection.objects.filter(user_id=user_id).filter(
                Q(rule_matchs__contains=str(result.shared_dict_uuid)) | Q(
                    action_value__contains=str(result.shared_dict_uuid))).count()
            web_white_rule_count = sys_web_white_rule.objects.filter(user_id=user_id).filter(
                Q(rule_matchs__contains=str(result.shared_dict_uuid)) | Q(
                    action_value__contains=str(result.shared_dict_uuid))).count()
            flow_rule_protection_count = sys_flow_rule_protection.objects.filter(user_id=user_id).filter(
                Q(rule_matchs__contains=str(result.shared_dict_uuid)) | Q(
                    action_value__contains=str(result.shared_dict_uuid))).count()
            flow_white_rule_count = sys_flow_white_rule.objects.filter(user_id=user_id).filter(
                Q(rule_matchs__contains=str(result.shared_dict_uuid)) | Q(
                    action_value__contains=str(result.shared_dict_uuid))).count()
            data.append({'shared_dict_uuid': result.shared_dict_uuid,
                         'shared_dict_name': result.shared_dict_name,
                         'shared_dict_detail': result.shared_dict_detail,
                         'shared_dict_key': result.shared_dict_key,
                         'shared_dict_type': result.shared_dict_type,
                         'shared_dict_value': result.shared_dict_value,
                         'shared_dict_expire_time': result.shared_dict_expire_time,
                         'web_rule_protection_count': web_rule_protection_count,
                         'web_white_rule_count': web_white_rule_count,
                         'flow_rule_protection_count': flow_rule_protection_count,
                         'flow_white_rule_count': flow_white_rule_count
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

def waf_get_sys_shared_dict(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        shared_dict_uuid = json_data['shared_dict_uuid']
        result = sys_shared_dict.objects.get(Q(user_id=user_id) & Q(shared_dict_uuid=shared_dict_uuid))
        data['shared_dict_uuid'] = result.shared_dict_uuid
        data['shared_dict_name'] = result.shared_dict_name
        data['shared_dict_detail'] = result.shared_dict_detail
        data['shared_dict_key'] = result.shared_dict_key
        data['shared_dict_type'] = result.shared_dict_type
        data['shared_dict_value'] = result.shared_dict_value
        data['shared_dict_expire_time'] = result.shared_dict_expire_time
        return_result['message'] = data
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)

def waf_del_sys_shared_dict(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        shared_dict_uuid = json_data['shared_dict_uuid']
        try:
            sys_shared_dict.objects.filter(user_id=user_id).filter(shared_dict_uuid=shared_dict_uuid).delete()
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


def waf_edit_sys_shared_dict(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        shared_dict_uuid = json_data['shared_dict_uuid']
        shared_dict_detail = json_data['shared_dict_detail']
        shared_dict_key = json_data['shared_dict_key']
        shared_dict_type = json_data['shared_dict_type']
        shared_dict_value = json_data['shared_dict_value']
        shared_dict_expire_time = json_data['shared_dict_expire_time']
        try:
            sys_shared_dict.objects.filter(user_id=user_id).filter(shared_dict_uuid=shared_dict_uuid).update(
                shared_dict_detail=shared_dict_detail, shared_dict_key=shared_dict_key,
                shared_dict_type=shared_dict_type, shared_dict_value=shared_dict_value,
                shared_dict_expire_time=shared_dict_expire_time)
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


def waf_create_sys_shared_dict(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        shared_dict_name = json_data['shared_dict_name']
        shared_dict_detail = json_data['shared_dict_detail']
        shared_dict_key = json_data['shared_dict_key']
        shared_dict_type = json_data['shared_dict_type']
        shared_dict_value = json_data['shared_dict_value']
        shared_dict_expire_time = json_data['shared_dict_expire_time']
        try:
            result = sys_shared_dict.objects.filter(user_id=user_id).filter(shared_dict_name=shared_dict_name)
            if len(result) != 0:
                return_result['result'] = False
                return_result['message'] = 'create error,shared_dict_name is exist'
                return JsonResponse(return_result, safe=False)
            sys_shared_dict.objects.create(user_id=user_id, shared_dict_name=shared_dict_name,
                                           shared_dict_detail=shared_dict_detail, shared_dict_key=shared_dict_key,
                                           shared_dict_type=shared_dict_type, shared_dict_value=shared_dict_value,
                                           shared_dict_expire_time=shared_dict_expire_time)
            return_result['message'] = 'edit success'
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
