from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q
import requests

def waf_edit_global(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        auto_update = json_data['auto_update']
        auto_update_period = json_data['auto_update_period']
        api_password = json_data['api_password']
        monitor = json_data['monitor']
        monitor_alert_period = json_data['monitor_alert_period']
        log_local = json_data['log_local']
        log_remote = json_data['log_remote']
        log_ip = json_data['log_ip']
        log_port = json_data['log_port']
        all_request_log = json_data['all_request_log']
        aliyun_access_id = json_data['aliyun_access_id']
        aliyun_access_secret = json_data['aliyun_access_secret']
        aliyun_log_endpoint = json_data['aliyun_log_endpoint']
        aliyun_project = json_data['aliyun_project']
        aliyun_logstore = json_data['aliyun_logstore']
        try:
            waf_global.objects.filter(user_id=user_id).update(
                auto_update=auto_update, auto_update_period=auto_update_period, monitor=monitor,
                monitor_alert_period=monitor_alert_period, log_local=log_local, log_remote=log_remote, log_ip=log_ip,
                log_port=log_port, aliyun_access_id=aliyun_access_id, aliyun_access_secret=aliyun_access_secret,
                aliyun_log_endpoint=aliyun_log_endpoint,aliyun_project=aliyun_project,aliyun_logstore=aliyun_logstore,all_request_log=all_request_log)
            jxwaf_user.objects.filter(user_id=user_id).update(api_password=api_password)
            return_result['result'] = True
            return_result['message'] = 'edit success'
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 108
            return JsonResponse(return_result, safe=False)
    except:
        return_result['result'] = False
        return_result['message'] = 'error'
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def waf_get_global(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        try:
            waf_global_result = waf_global.objects.get(user_id=user_id)
        except:
            waf_global.objects.create(user_id=user_id)
            waf_global_result = waf_global.objects.get(user_id=user_id)
        user_result = jxwaf_user.objects.get(user_id=user_id)
        data['auto_update'] = waf_global_result.auto_update
        data['auto_update_period'] = waf_global_result.auto_update_period
        data['api_key'] = user_result.user_id
        data['api_password'] = user_result.api_password
        data['monitor'] = waf_global_result.monitor
        data['monitor_alert_period'] = waf_global_result.monitor_alert_period
        data['log_local'] = waf_global_result.log_local
        data['log_remote'] = waf_global_result.log_remote
        data['log_ip'] = waf_global_result.log_ip
        data['log_port'] = waf_global_result.log_port
        data['aliyun_access_id'] = waf_global_result.aliyun_access_id
        data['aliyun_access_secret'] = waf_global_result.aliyun_access_secret
        data['aliyun_log_endpoint'] = waf_global_result.aliyun_log_endpoint
        data['aliyun_project'] = waf_global_result.aliyun_project
        data['aliyun_logstore'] = waf_global_result.aliyun_logstore
        data['all_request_log'] = waf_global_result.all_request_log
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 108
        return JsonResponse(return_result, safe=False)


def waf_get_jxcheck_version(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        try:
            waf_jxcheck_result = waf_jxcheck.objects.get(user_id=user_id)
            return_result['result'] = True
            return_result['message'] = waf_jxcheck_result.version
            return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = "not load"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 108
        return JsonResponse(return_result, safe=False)

def waf_get_jxwaf_jxcheck_version(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        jxwaf_uri = "https://api.jxwaf.com/get_jxwaf_jxcheck_version"
        try:
            r = requests.get(jxwaf_uri)
            result = r.json()
            if result['result'] == True:
                return_result['result'] = True
                return_result['message'] = result['message']
                return JsonResponse(return_result, safe=False)
            else:
                return_result['result'] = False
                return_result['message'] = "jxwaf server error"
                return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = "network error"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 108
        return JsonResponse(return_result, safe=False)

def waf_download_jxwaf_jxcheck(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        jxwaf_uri = "https://api.jxwaf.com/download_jxwaf_jxcheck"
        try:
            r = requests.get(jxwaf_uri)
            result = r.json()
            if result['result'] == True:
                waf_jxcheck.objects.create(user_id=user_id,version=result['version'],jxcheck_code=result['message'])
                return_result['result'] = True
                return_result['message'] = "load success"
                return JsonResponse(return_result, safe=False)
            else:
                return_result['result'] = False
                return_result['message'] = "jxwaf server error"
                return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = "network error"
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 108
        return JsonResponse(return_result, safe=False)