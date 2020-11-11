from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q
import requests


def waf_sync_update_get_jxcheck_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        try:
            r = requests.get('https://api.jxwaf.com/open/waf_get_open_jxcheck')
            result = r.json()
            if result['result'] == True:
                now_version = ''
                try:
                    jxcheck_result = waf_jxcheck.objects.get(user_id='jxwaf')
                    now_version = jxcheck_result.version
                except:
                    now_version = ''
                return_result['result'] = True
                return_result['message'] = result['message']
                return_result['now_version'] = now_version
                return JsonResponse(return_result, safe=False)
            else:
                return_result['result'] = False
                return_result['errCode'] = 504
                return_result['message'] = "https://api.jxwaf.com/open/waf_get_open_jxcheck response result is false"
                return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['errCode'] = 500
            return_result['message'] = "get https://api.jxwaf.com/open/waf_get_open_jxcheck failed"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 401
        return JsonResponse(return_result, safe=False)


def waf_sync_update_get_jxcheck_update(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        jxcheck_code = json_data['jxcheck_code']
        version = json_data['version']
        try:
            waf_jxcheck.objects.get(user_id='jxwaf')
            waf_jxcheck.objects.filter(user_id='jxwaf').update(jxcheck_code=jxcheck_code, version=version)
            return_result['result'] = True
            return_result['message'] = "update success"
            return JsonResponse(return_result, safe=False)
        except:
            waf_jxcheck.objects.create(user_id='jxwaf', jxcheck_code=jxcheck_code, version=version)
            return_result['result'] = True
            return_result['message'] = "create success"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_sync_update_get_keycheck_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        try:
            r = requests.get('https://api.jxwaf.com/open/waf_get_open_keycheck')
            result = r.json()
            if result['result'] == True:
                now_version = ''
                try:
                    keycheck_result = waf_keycheck.objects.get(user_id='jxwaf')
                    now_version = keycheck_result.version
                except:
                    now_version = ''
                return_result['result'] = True
                return_result['message'] = result['message']
                return_result['now_version'] = now_version
                return JsonResponse(return_result, safe=False)
            else:
                return_result['result'] = False
                return_result['errCode'] = 504
                return_result['message'] = "https://api.jxwaf.com/open/waf_get_open_keycheck response result is false"
                return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['errCode'] = 500
            return_result['message'] = "get https://api.jxwaf.com/open/waf_get_open_keycheck failed"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 401
        return JsonResponse(return_result, safe=False)


def waf_sync_update_get_keycheck_update(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        keycheck_code = json_data['keycheck_code']
        version = json_data['version']
        try:
            waf_keycheck.objects.get(user_id='jxwaf')
            waf_keycheck.objects.filter(user_id='jxwaf').update(keycheck_code=keycheck_code, version=version)
            return_result['result'] = True
            return_result['message'] = "update success"
            return JsonResponse(return_result, safe=False)
        except:
            waf_keycheck.objects.create(user_id='jxwaf', keycheck_code=keycheck_code, version=version)
            return_result['result'] = True
            return_result['message'] = "create success"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_sync_update_get_botcheck_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        try:
            r = requests.get('https://api.jxwaf.com/open/waf_get_open_botcheck')
            result = r.json()
            if result['result'] == True:
                now_version = ''
                try:
                    botcheck_result = waf_botcheck.objects.get(user_id='jxwaf')
                    now_version = botcheck_result.version
                except:
                    now_version = ''
                return_result['result'] = True
                return_result['message'] = result['message']
                return_result['now_version'] = now_version
                return JsonResponse(return_result, safe=False)
            else:
                return_result['result'] = False
                return_result['errCode'] = 504
                return_result['message'] = "https://api.jxwaf.com/open/waf_get_open_botcheck response result is false"
                return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['errCode'] = 500
            return_result['message'] = "get https://api.jxwaf.com/open/waf_get_open_botcheck failed"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 401
        return JsonResponse(return_result, safe=False)


def waf_sync_update_get_botcheck_update(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        botcheck_code = json_data['botcheck_code']
        version = json_data['version']
        try:
            waf_botcheck.objects.get(user_id='jxwaf')
            waf_botcheck.objects.filter(user_id='jxwaf').update(botcheck_code=botcheck_code, version=version)
            return_result['result'] = True
            return_result['message'] = "update success"
            return JsonResponse(return_result, safe=False)
        except:
            waf_botcheck.objects.create(user_id='jxwaf', botcheck_code=botcheck_code, version=version)
            return_result['result'] = True
            return_result['message'] = "create success"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_sync_update_get_botcheck_key_update(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        try:
            waf_cc_bot_html_key.objects.filter(user_id="jxwaf").delete()
            r = requests.get('https://api.jxwaf.com/open/waf_get_open_botcheck_key')
            result = r.json()
            if result['result'] == True:
                for bot_key in result['message']:
                    uuid = bot_key['uuid']
                    key = bot_key['key']
                    bot_check_mode = bot_key['bot_check_mode']
                    try:
                        waf_cc_bot_html_key.objects.get(Q(key=key) & Q(uuid=uuid))
                    except:
                        waf_cc_bot_html_key.objects.create(user_id="jxwaf", uuid=uuid, key=key,
                                                           bot_check_mode=bot_check_mode)
                return_result['result'] = True
                return_result['message'] = len(result['message'])
                return JsonResponse(return_result, safe=False)
            else:
                return_result['result'] = False
                return_result['errCode'] = 504
                return_result[
                    'message'] = "https://api.jxwaf.com/open/waf_get_open_botcheck_key response result is false"
                return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return_result['errCode'] = 500
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 401
        return JsonResponse(return_result, safe=False)


def waf_sync_update_get_rule_engine_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        try:
            waf_cc_bot_html_key.objects.filter(user_id="jxwaf").delete()
            r = requests.get('https://api.jxwaf.com/open/waf_get_rule_engine_list')
            result = r.json()
            if result['result'] == True:
                return_result['result'] = True
                return_result['message'] = result['message']
                return JsonResponse(return_result, safe=False)
            else:
                return_result['result'] = False
                return_result['errCode'] = 504
                return_result[
                    'message'] = "https://api.jxwaf.com/open/waf_get_rule_engine_list response result is false"
                return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return_result['errCode'] = 500
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 401
        return JsonResponse(return_result, safe=False)


def waf_sync_update_create_rule_engine(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        rule_name = json_data['rule_name']
        detail = json_data['detail']
        check_uri = json_data['check_uri']
        check_content = json_data['check_content']
        content_handle = json_data['content_handle']
        content_match = json_data['content_match']
        match_action = json_data['match_action']
        white_url = json_data['white_url']
        flow_filter = json_data['flow_filter']
        if domain == '':
            waf_domain_results = waf_domain.objects.filter(user_id=user_id)
            for domain_result in waf_domain_results:
                count = waf_rule_engine.objects.filter(user_id=user_id).filter(domain=domain_result.domain).filter(rule_name=rule_name).count()
                if count == 0:
                    waf_rule_engine.objects.create(user_id=user_id, domain=domain_result.domain, rule_name=rule_name,
                                                   detail=detail, check_uri=check_uri, check_content=check_content,
                                                   content_handle=content_handle, content_match=content_match,
                                                   match_action=match_action, white_url=white_url,
                                                   flow_filter=flow_filter)
                else:
                    waf_rule_engine.objects.filter(user_id=user_id).filter(domain=domain_result.domain).filter(rule_name=rule_name).update(
                        detail=detail, check_uri=check_uri, check_content=check_content, content_handle=content_handle,
                        content_match=content_match, match_action=match_action, white_url=white_url,
                        flow_filter=flow_filter)
            return_result['message'] = 'create success'
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        else:
            try:
                count = waf_rule_engine.objects.filter(user_id=user_id).filter(domain=domain).filter(rule_name=rule_name).count()
                if count == 0:
                    waf_rule_engine.objects.create(user_id=user_id, domain=domain,
                                                   rule_name=rule_name,
                                                   detail=detail, check_uri=check_uri, check_content=check_content,
                                                   content_handle=content_handle, content_match=content_match,
                                                   match_action=match_action, white_url=white_url,
                                                   flow_filter=flow_filter)
                else:
                    waf_rule_engine.objects.filter(user_id=user_id).filter(domain=domain).filter(rule_name=rule_name).update(
                        detail=detail, check_uri=check_uri, check_content=check_content,
                        content_handle=content_handle,
                        content_match=content_match, match_action=match_action, white_url=white_url,
                        flow_filter=flow_filter)
                return_result['message'] = 'create success'
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
