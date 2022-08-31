from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_group_web_engine_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        sql_check = json_data['sql_check']
        xss_check = json_data['xss_check']
        command_inject_check = json_data['command_inject_check']
        webshell_update_check = json_data['webshell_update_check']
        sensitive_file_check = json_data['sensitive_file_check']
        path_traversal_check = json_data['path_traversal_check']
        high_nday_check = json_data['high_nday_check']
        waf_group_web_engine_protection.objects.filter(user_id=user_id).filter(group_id=group_id).update(
            sql_check=sql_check,
            xss_check=xss_check, command_inject_check=command_inject_check, webshell_update_check=webshell_update_check,
            sensitive_file_check=sensitive_file_check, path_traversal_check=path_traversal_check,
            high_nday_check=high_nday_check)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_group_web_engine_protection(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        try:
            waf_group_web_engine_protection_results = waf_group_web_engine_protection.objects.get(
                Q(group_id=group_id) & Q(user_id=user_id))
        except:
            waf_group_web_engine_protection.objects.filter(user_id=user_id).filter(group_id=group_id).delete()
            waf_group_web_engine_protection.objects.create(user_id=user_id, group_id=group_id)
            waf_group_web_engine_protection_results = waf_group_web_engine_protection.objects.get(
                Q(group_id=group_id) & Q(user_id=user_id))
        data['sql_check'] = waf_group_web_engine_protection_results.sql_check
        data['xss_check'] = waf_group_web_engine_protection_results.xss_check
        data['command_inject_check'] = waf_group_web_engine_protection_results.command_inject_check
        data['webshell_update_check'] = waf_group_web_engine_protection_results.webshell_update_check
        data['sensitive_file_check'] = waf_group_web_engine_protection_results.sensitive_file_check
        data['path_traversal_check'] = waf_group_web_engine_protection_results.path_traversal_check
        data['high_nday_check'] = waf_group_web_engine_protection_results.high_nday_check
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)