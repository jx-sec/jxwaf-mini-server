from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q


def waf_edit_page_custom(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        owasp_code = json_data['owasp_code']
        owasp_html = json_data['owasp_html']
        waf_page_custom.objects.filter(user_id=user_id).filter(domain=domain).update(
            owasp_code=owasp_code, owasp_html=owasp_html)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)

def waf_get_page_custom(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        waf_page_custom_results = waf_page_custom.objects.get(Q(domain=domain) & Q(user_id=user_id))
        data['owasp_code'] = waf_page_custom_results.owasp_code
        data['owasp_html'] = waf_page_custom_results.owasp_html
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)

