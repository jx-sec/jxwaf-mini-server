from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q


def waf_get_data_mask_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        domain = json_date['domain']
        waf_data_mask_rule_results = waf_data_mask_rule.objects.filter(user_id=user_id).filter(domain=domain)
        for result in waf_data_mask_rule_results:
            data.append({'uri': result.uri,
                         'get': result.get,
                         'post': result.post,
                         'header': result.header
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


def waf_del_data_mask_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        domain = json_date['domain']
        uri = json_date['uri']
        try:
            waf_data_mask_rule.objects.filter(user_id=user_id).filter(domain=domain).filter(uri=uri).delete()
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


def waf_create_data_mask_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        uri = json_date['uri']
        get = json_date['get']
        post = json_date['post']
        header = json_date['header']
        domain = json_date['domain']
        result = waf_data_mask_rule.objects.filter(user_id=user_id).filter(domain=domain).filter(uri=uri)
        if len(result) != 0:
            return_result['result'] = False
            return_result['message'] = "uri is exist"
            return_result['errCode'] = 409
            return JsonResponse(return_result, safe=False)
        try:
            waf_data_mask_rule.objects.create(user_id=user_id, domain=domain, uri=uri,
                                              get=get, post=post, header=header)
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


def waf_edit_data_mask_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        uri = json_date['uri']
        get = json_date['get']
        post = json_date['post']
        header = json_date['header']
        domain = json_date['domain']
        try:
            waf_data_mask_rule.objects.filter(user_id=user_id).filter(domain=domain).filter(
                uri=uri).update(get=get, post=post, header=header)
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


def waf_edit_data_mask_global(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        get = json_date['get']
        post = json_date['post']
        header = json_date['header']
        domain = json_date['domain']
        try:
            waf_data_mask_global.objects.filter(user_id=user_id).filter(domain=domain).update(get=get, post=post,
                                                                                              header=header)
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


def waf_get_data_mask_global(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_date = json.loads(request.body)
        domain = json_date['domain']
        try:
            result = waf_data_mask_global.objects.get(Q(user_id=user_id) & Q(domain=domain))
        except:
            waf_data_mask_global.objects.create(user_id=user_id, domain=domain)
            result = waf_data_mask_global.objects.get(Q(user_id=user_id) & Q(domain=domain))
        data['get'] = result.get
        data['post'] = result.post
        data['header'] = result.header
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
