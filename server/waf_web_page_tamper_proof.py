from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import time
from django.http import HttpResponse
import requests


def waf_get_web_page_tamper_proof_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        results = waf_web_page_tamper_proof.objects.filter(user_id=user_id).filter(
            domain=domain).order_by('rule_order_time')
        for result in results:
            data.append({'rule_name': result.rule_name,
                         'rule_detail': result.rule_detail,
                         'rule_matchs': result.rule_matchs,
                         'cache_page_url': result.cache_page_url,
                         'cache_content_type': result.cache_content_type,
                         'cache_page_content': result.cache_page_content,
                         'status': result.status,
                         'rule_order_time': result.rule_order_time
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_web_page_tamper_proof(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        try:
            waf_web_page_tamper_proof.objects.filter(user_id=user_id).filter(domain=domain).filter(
                rule_name=rule_name).delete()
            return_result['result'] = True
            return_result['message'] = 'del_success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'del_error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_web_page_tamper_proof_status(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        status = json_data['status']
        try:
            waf_web_page_tamper_proof.objects.filter(rule_name=rule_name).filter(user_id=user_id).filter(
                domain=domain).update(
                status=status)
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = 'edit_error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_web_page_tamper_proof(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        rule_detail = json_data['rule_detail']
        rule_matchs = json_data['rule_matchs']
        cache_page_url = json_data['cache_page_url']
        cache_content_type = json_data['cache_content_type']
        cache_page_content = json_data['cache_page_content']
        try:
            waf_web_page_tamper_proof.objects.filter(domain=domain).filter(user_id=user_id).filter(
                rule_name=rule_name).update(
                rule_detail=rule_detail, rule_matchs=rule_matchs, cache_page_url=cache_page_url,
                cache_content_type=cache_content_type, cache_page_content=cache_page_content
            )
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_web_page_tamper_proof(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        result = waf_web_page_tamper_proof.objects.get(Q(user_id=user_id) & Q(domain=domain) & Q(rule_name=rule_name))
        data['rule_detail'] = result.rule_detail
        data['rule_matchs'] = result.rule_matchs
        data['cache_page_url'] = result.cache_page_url
        data['cache_content_type'] = result.cache_content_type
        data['cache_page_content'] = result.cache_page_content
        data['rule_order_time'] = result.rule_order_time
        return_result['message'] = data
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_create_web_page_tamper_proof(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        rule_detail = json_data['rule_detail']
        rule_matchs = json_data['rule_matchs']
        cache_page_url = json_data['cache_page_url']
        cache_content_type = json_data['cache_content_type']
        cache_page_content = json_data['cache_page_content']
        rule_count = waf_web_page_tamper_proof.objects.filter(user_id=user_id).filter(domain=domain).filter(
            rule_name=rule_name).count()
        if rule_count != 0:
            return_result['message'] = 'already_exists_rule'
            return_result['result'] = False
            return JsonResponse(return_result, safe=False)
        waf_web_page_tamper_proof.objects.create(user_id=user_id, rule_name=rule_name, rule_detail=rule_detail,
                                                 rule_matchs=rule_matchs, cache_page_url=cache_page_url,
                                                 cache_content_type=cache_content_type,
                                                 cache_page_content=cache_page_content,
                                                 rule_order_time=int(time.time()), domain=domain)

        return_result['message'] = 'create_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_cache_page_url(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        cache_page_url = json_data['cache_page_url']
        response = requests.get(cache_page_url)
        cache_page_content = response.content
        cache_content_type = response.headers.get('Content-Type')
        return_result['cache_page_content'] = cache_page_content
        return_result['cache_content_type'] = cache_content_type
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_exchange_web_page_tamper_proof_priority(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        type = json_data['type']
        if type == "top":
            rule_name = json_data['rule_name']
            results = waf_web_page_tamper_proof.objects.filter(domain=domain).filter(
                user_id=user_id).order_by('rule_order_time')
            result = results[0]
            waf_web_page_tamper_proof.objects.filter(domain=domain).filter(user_id=user_id).filter(
                rule_name=rule_name).update(
                rule_order_time=int(result.rule_order_time) - 1)
        elif type == "exchange":
            rule_name = json_data['rule_name']
            exchange_rule_name = json_data['exchange_rule_name']
            rule_name_result = waf_web_page_tamper_proof.objects.get(
                Q(domain=domain) & Q(user_id=user_id) & Q(rule_name=rule_name))
            exchange_rule_name_result = waf_web_page_tamper_proof.objects.get(
                Q(domain=domain) & Q(user_id=user_id) & Q(rule_name=exchange_rule_name))
            waf_web_page_tamper_proof.objects.filter(domain=domain).filter(user_id=user_id).filter(
                rule_name=rule_name).update(
                rule_order_time=exchange_rule_name_result.rule_order_time)
            waf_web_page_tamper_proof.objects.filter(domain=domain).filter(user_id=user_id).filter(
                rule_name=exchange_rule_name).update(rule_order_time=rule_name_result.rule_order_time)
        return_result['result'] = True
        return_result['message'] = 'exchange_priority_success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_load_web_page_tamper_proof(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rules = json_data['rules']
        for rule in rules:
            rule_name = rule['rule_name']
            rule_detail = rule['rule_detail']
            rule_matchs = rule['rule_matchs']
            cache_page_url = rule['cache_page_url']
            cache_content_type = rule['cache_content_type']
            cache_page_content = rule['cache_page_content']
            rule_count = waf_web_page_tamper_proof.objects.filter(user_id=user_id).filter(domain=domain).filter(
                rule_name=rule_name).count()
            if rule_count != 0:
                continue
            waf_web_page_tamper_proof.objects.create(user_id=user_id, rule_name=rule_name, rule_detail=rule_detail,
                                                     rule_matchs=rule_matchs, cache_page_url=cache_page_url,
                                                     cache_content_type=cache_content_type,
                                                     cache_page_content=cache_page_content,
                                                     rule_order_time=int(time.time()), domain=domain)
        return_result['message'] = 'load_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_backup_web_page_tamper_proof(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name_list = json_data['rule_name_list']
        rules = []
        for rule_name in rule_name_list:
            rule_name_result = waf_web_page_tamper_proof.objects.get(
                Q(user_id=user_id) & Q(domain=domain) & Q(rule_name=rule_name))
            rules.append({
                'rule_name': rule_name_result.rule_name,
                'rule_detail': rule_name_result.rule_detail,
                'rule_matchs': rule_name_result.rule_matchs,
                'cache_page_url': rule_name_result.cache_page_url,
                'cache_content_type': rule_name_result.cache_content_type,
                'cache_page_content': rule_name_result.cache_page_content
            }
            )
        response = HttpResponse(json.dumps(rules), content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename="web_page_tamper_proof_data.json"'
        return response
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
