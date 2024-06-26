from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_web_engine_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        sql_check = json_data['sql_check']
        xss_check = json_data['xss_check']
        cmd_exec_check = json_data['cmd_exec_check']
        code_exec_check = json_data['code_exec_check']
        webshell_update_check = json_data['webshell_update_check']
        sensitive_file_check = json_data['sensitive_file_check']
        path_traversal_check = json_data['path_traversal_check']
        high_nday_check = json_data['high_nday_check']
        waf_web_engine_protection.objects.filter(user_id=user_id).filter(domain=domain).update(
            sql_check=sql_check,
            xss_check=xss_check, cmd_exec_check=cmd_exec_check,
            sensitive_file_check=sensitive_file_check, path_traversal_check=path_traversal_check,
            high_nday_check=high_nday_check, code_exec_check=code_exec_check,
            webshell_update_check=webshell_update_check
        )
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_web_engine_protection(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        try:
            waf_web_engine_protection_results = waf_web_engine_protection.objects.get(
                Q(domain=domain) & Q(user_id=user_id))
        except:
            waf_web_engine_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_web_engine_protection.objects.create(user_id=user_id, domain=domain)
            waf_web_engine_protection_results = waf_web_engine_protection.objects.get(
                Q(domain=domain) & Q(user_id=user_id))
        data['sql_check'] = waf_web_engine_protection_results.sql_check
        data['xss_check'] = waf_web_engine_protection_results.xss_check
        data['cmd_exec_check'] = waf_web_engine_protection_results.cmd_exec_check
        data['code_exec_check'] = waf_web_engine_protection_results.code_exec_check
        data['webshell_update_check'] = waf_web_engine_protection_results.webshell_update_check
        data['sensitive_file_check'] = waf_web_engine_protection_results.sensitive_file_check
        data['path_traversal_check'] = waf_web_engine_protection_results.path_traversal_check
        data['high_nday_check'] = waf_web_engine_protection_results.high_nday_check
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
