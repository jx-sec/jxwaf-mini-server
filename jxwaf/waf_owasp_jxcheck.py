from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q

def waf_edit_owasp_check(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        owasp_protection_mode = json_data['owasp_protection_mode']
        sql_check = json_data['sql_check']
        xss_check = json_data['xss_check']
        command_inject_check = json_data['command_inject_check']
        directory_traversal_check = json_data['directory_traversal_check']
        code_exec_check = json_data['code_exec_check']
        sensitive_file_check = json_data['sensitive_file_check']
        upload_check = json_data['upload_check']
        upload_check_rule = json_data['upload_check_rule']
        waf_owasp_check.objects.filter(user_id=user_id).filter(domain=domain).update(
            owasp_protection_mode=owasp_protection_mode,
            sql_check=sql_check, xss_check=xss_check, command_inject_check=command_inject_check,
            directory_traversal_check=directory_traversal_check, upload_check=upload_check,
            upload_check_rule=upload_check_rule,
            code_exec_check=code_exec_check,
            sensitive_file_check=sensitive_file_check)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_owasp_check(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        try:
            waf_owasp_check_results = waf_owasp_check.objects.get(Q(domain=domain) & Q(user_id=user_id))
        except:
            waf_owasp_check.objects.create(user_id=user_id,domain=domain)
            waf_owasp_check_results = waf_owasp_check.objects.get(Q(domain=domain) & Q(user_id=user_id))
        data['owasp_protection_mode'] = waf_owasp_check_results.owasp_protection_mode
        data['sql_check'] = waf_owasp_check_results.sql_check
        data['xss_check'] = waf_owasp_check_results.xss_check
        data['command_inject_check'] = waf_owasp_check_results.command_inject_check
        data['directory_traversal_check'] = waf_owasp_check_results.directory_traversal_check
        data['upload_check'] = waf_owasp_check_results.upload_check
        data['upload_check_rule'] = waf_owasp_check_results.upload_check_rule
        data['code_exec_check'] = waf_owasp_check_results.code_exec_check
        data['sensitive_file_check'] = waf_owasp_check_results.sensitive_file_check
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
