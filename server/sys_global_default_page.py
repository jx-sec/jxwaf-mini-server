from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_sys_global_default_page(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        web_deny_code = json_data['web_deny_code']
        web_deny_html = json_data['web_deny_html']
        flow_deny_code = json_data['flow_deny_code']
        flow_deny_html = json_data['flow_deny_html']
        name_list_deny_code = json_data['name_list_deny_code']
        name_list_deny_html = json_data['name_list_deny_html']
        domain_404_code = json_data['domain_404_code']
        domain_404_html = json_data['domain_404_html']
        sys_global_default_page.objects.filter(user_id=user_id).update(
            web_deny_code=web_deny_code, web_deny_html=web_deny_html, flow_deny_code=flow_deny_code,
            flow_deny_html=flow_deny_html, domain_404_code=domain_404_code, domain_404_html=domain_404_html,
            name_list_deny_code=name_list_deny_code, name_list_deny_html=name_list_deny_html)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_global_default_page(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        try:
            sys_global_default_page_result = sys_global_default_page.objects.get(user_id=user_id)
        except:
            sys_global_default_page.objects.filter(user_id=user_id).delete()
            sys_global_default_page.objects.create(user_id=user_id)
            sys_global_default_page_result = sys_global_default_page.objects.get(user_id=user_id)
        data['web_deny_code'] = sys_global_default_page_result.web_deny_code
        data['web_deny_html'] = sys_global_default_page_result.web_deny_html
        data['flow_deny_code'] = sys_global_default_page_result.flow_deny_code
        data['flow_deny_html'] = sys_global_default_page_result.flow_deny_html
        data['name_list_deny_code'] = sys_global_default_page_result.name_list_deny_code
        data['name_list_deny_html'] = sys_global_default_page_result.name_list_deny_html
        data['domain_404_code'] = sys_global_default_page_result.domain_404_code
        data['domain_404_html'] = sys_global_default_page_result.domain_404_html
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
