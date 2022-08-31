# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
import sys
import time
from django.core.paginator import Paginator
from django.db.models import Q
import requests
import traceback

reload(sys)
sys.setdefaultencoding('utf8')

'''
def waf_get_service_center_engine_update_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        service_center_engine_update_results = service_center_engine_update.objects.filter(user_id=user_id)
        for service_center_engine_update_result in service_center_engine_update_results:
            data.append({
                'code': service_center_engine_update_result.code,
                'name': service_center_engine_update_result.name,
                'detail': service_center_engine_update_result.detail,
                'source': service_center_engine_update_result.source,
                'share_user': service_center_engine_update_result.share_user
            })
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_delete_service_center_engine_update(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        service_center_engine_update.objects.filter(user_id=user_id).filter(name=name).delete()
        return_result['result'] = True
        return_result['message'] = "delete success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
'''


def waf_get_remote_service_center_engine_list(request):
    return_result = {}
    data = []
    proxies = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        type = json_data['type']
        try:
            base_conf_result = sys_base_conf.objects.get(user_id=user_id)
        except:
            sys_base_conf.objects.filter(user_id=user_id).delete()
            sys_base_conf.objects.create(user_id=user_id)
            base_conf_result = sys_base_conf.objects.get(user_id=user_id)
        if type == "jxwaf":
            try:
                service_center_engine = "https://api.jxwaf.com/jxwaf/get_service_center_engine_list"
                payload = {'type': "jxwaf"}
                if base_conf_result.proxie == "true":
                    proxies['http'] = base_conf_result.proxie_site
                    proxies['https'] = base_conf_result.proxie_site
                    r = requests.post(service_center_engine, data=json.dumps(payload), proxies=proxies)
                else:
                    r = requests.post(service_center_engine, data=json.dumps(payload))
                result = r.json()
                if result['result'] == True:
                    return_result['result'] = True
                    return_result['message'] = result['message']
                    return JsonResponse(return_result, safe=False)
                else:
                    return_result['result'] = False
                    return_result['message'] = result['message']
                    return JsonResponse(return_result, safe=False)
            except:
                return_result['result'] = False
                return_result['message'] = "network_error"
                return JsonResponse(return_result, safe=False)
        elif type == "custom":
            try:
                service_center_engine = "https://api.jxwaf.com/custom/get_service_center_engine_list"
                if base_conf_result.jxwaf_login == "false":
                    return_result['result'] = False
                    return_result['message'] = "jxwaf_login is false"
                    return JsonResponse(return_result, safe=False)
                payload = {'type': "custom", "jxwaf_login_token": base_conf_result.jxwaf_login_token}
                if base_conf_result.proxie == "true":
                    proxies['http'] = base_conf_result.proxie_site
                    proxies['https'] = base_conf_result.proxie_site
                    r = requests.post(service_center_engine, data=json.dumps(payload), proxies=proxies)
                else:
                    r = requests.post(service_center_engine, data=json.dumps(payload))
                result = r.json()
                if result['result'] == True:
                    return_result['result'] = True
                    return_result['message'] = result['message']
                    return JsonResponse(return_result, safe=False)
                else:
                    return_result['result'] = False
                    return_result['message'] = result['message']
                    return JsonResponse(return_result, safe=False)
            except:
                return_result['result'] = False
                return_result['message'] = "network_error"
                return JsonResponse(return_result, safe=False)
        return_result['result'] = True
        return_result['message'] = "delete success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_load_remote_service_center_engine(request):
    return_result = {}
    data = []
    proxies = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        code = json_data['code']
        engine_type = json_data['engine_type']
        name = json_data['name']
        detail = json_data['detail']
        if engine_type == "web_engine":
            try:
                sys_web_engine_protection.objects.get(Q(user_id=user_id) & Q(name=name))
                sys_web_engine_protection.objects.filter(user_id=user_id).filter(name=name).update(code=code,
                                                                                                   detail=detail,
                                                                                                   update_time=int(time.time()))
            except:
                sys_web_engine_protection.objects.create(user_id=user_id, code=code, name=name, detail=detail,
                                                         default='false', update_time=int(time.time()))
        elif engine_type == "flow_engine":
            try:
                sys_flow_engine_protection.objects.get(Q(user_id=user_id) & Q(name=name))
                sys_flow_engine_protection.objects.filter(user_id=user_id).filter(name=name).update(code=code,
                                                                                                    detail=detail,
                                                                                                    update_time=int(time.time()))
            except:
                sys_flow_engine_protection.objects.create(user_id=user_id, code=code, name=name, detail=detail,
                                                          default='false',
                                                          update_time=int(time.time()))

        return_result['result'] = True
        return_result['message'] = "load success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
