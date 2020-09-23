# -*- coding:utf-8 –*-
from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q
from clickhouse_driver import Client
import uuid
from aliyun.log import LogClient
from aliyun.log.gethistogramsrequest import GetHistogramsRequest
from aliyun.log.getlogsrequest import GetLogsRequest
from time import time

GEO_SQL = "* and log_type: attack|select count(*) as count,ip_to_city_geo(client_ip) as geo,ip_to_city(client_ip) as city,count(DISTINCT client_ip) as ip_count   group by ip_to_city_geo(client_ip),ip_to_city(client_ip)"
ATT_TYPE_24H = "* and log_type: attack and protecion_type: jxcheck | select time_series(request_time,'1h', '%m-%d-%H', '0') as time,count(*) as count,protecion_info as protecion_info group by time,protecion_info order by time"
ATT_TYPE_7D = "* and log_type: attack and protecion_type: jxcheck | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count,protecion_info as protecion_info group by time,protecion_info order by time"
ATT_IP_COUNT_7D = "* and log_type: attack and protecion_type: jxcheck| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count( DISTINCT  client_ip) as ip_count group by time order by time"
ATT_IP_COUNT_24H = "* and log_type: attack and protecion_type: jxcheck| select time_series(request_time,'1h', '%m-%d-%H', '0') as time,count( DISTINCT  client_ip) as ip_count group by time order by time"
ATT_BLACK_IP_COUNT_7D = "* and log_type: attack and protecion_type: black_ip| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count( DISTINCT  client_ip) as ip_count group by time order by time"
ATT_BLACK_IP_COUNT_24H = "* and log_type: attack and protecion_type: black_ip| select time_series(request_time,'1h', '%m-%d-%H', '0') as time,count( DISTINCT  client_ip) as ip_count group by time order by time"
CC_TYPE_24H = "* and log_type: attack and protecion_type: cc | select time_series(request_time,'1h', '%m-%d-%H', '0') as time,count(*) as count,protecion_info as protecion_info group by time,protecion_info order by time"
CC_TYPE_7D = "* and log_type: attack and protecion_type: cc | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count,protecion_info as protecion_info group by time,protecion_info order by time"
CC_IP_COUNT_7D = "* and log_type: attack and protecion_type: cc| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count( DISTINCT  client_ip) as ip_count group by time order by time"
CC_IP_COUNT_24H = "* and log_type: attack and protecion_type: cc| select time_series(request_time,'1h', '%m-%d-%H', '0') as time,count( DISTINCT  client_ip) as ip_count group by time order by time"
CC_BLACK_IP_COUNT_7D = "* and log_type: cc and protecion_type: black_cc_ip| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count( DISTINCT  client_ip) as ip_count group by time order by time"
CC_BLACK_IP_COUNT_24H = "* and log_type: cc and protecion_type: black_cc_ip| select time_series(request_time,'1h', '%m-%d-%H', '0') as time,count( DISTINCT  client_ip) as ip_count group by time order by time"
ATT_IP_TOTLE_COUNT = "* and log_type: attack and protecion_type: jxcheck| select count( DISTINCT  client_ip) as ip_count"
CC_IP_TOTLE_COUNT = "* and log_type: attack and protecion_type: cc| select count( DISTINCT  client_ip) as ip_count"


def chart_get_attack_geoip(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        #domain = json_data['domain']
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        if time_zone == "7day":
            from_time = int(time() - 604800)
        elif time_zone == "24hour":
            from_time = int(time() - 86400)
        global_result = waf_global.objects.get(user_id=user_id)
        endpoint = global_result.aliyun_log_endpoint.replace('https://', '').replace('http://', '')
        accessKeyId = global_result.aliyun_access_id
        accessKey = global_result.aliyun_access_secret
        project = global_result.aliyun_project
        logstore = global_result.aliyun_logstore
        client = LogClient(endpoint, accessKeyId, accessKey)
        req = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=GEO_SQL)
        res = client.get_logs(req)
        for log_result in res.get_logs():
            geo_info = log_result.get_contents()['geo'].split(",")
            try:
                data.append({'name': log_result.get_contents()['city'],
                             'ip_count': log_result.get_contents()['ip_count'],
                             'geo': [geo_info[1], geo_info[0]],
                             'count': log_result.get_contents()['count']
                             }
                            )
            except:
                pass
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)


def chart_get_attack_type(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        #domain = json_data['domain']
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        if time_zone == "7day":
            from_time = int(time() - 604800)
            req_sql = ATT_TYPE_7D
        elif time_zone == "24hour":
            req_sql = ATT_TYPE_24H
            from_time = int(time() - 86400)
        global_result = waf_global.objects.get(user_id=user_id)
        endpoint = global_result.aliyun_log_endpoint.replace('https://', '').replace('http://', '')
        accessKeyId = global_result.aliyun_access_id
        accessKey = global_result.aliyun_access_secret
        project = global_result.aliyun_project
        logstore = global_result.aliyun_logstore
        client = LogClient(endpoint, accessKeyId, accessKey)
        req = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=req_sql)
        res = client.get_logs(req)
        x = []
        x_exist = {}
        y = []
        y_exist = {}
        for log_result in res.get_logs():
            print log_result.get_contents()
            if not x_exist.has_key(log_result.get_contents()['time']):
                x.append(log_result.get_contents()['time'])
                x_exist[log_result.get_contents()['time']] = len(x) - 1
            if not y_exist.has_key(log_result.get_contents()['protecion_info']):
                if log_result.get_contents()['protecion_info'] != 'null':
                    y.append(log_result.get_contents()['protecion_info'])
                    y_exist[log_result.get_contents()['protecion_info']] = True
        result = {}
        for tmp in y:
            ss = [0]
            result[tmp] = ss * len(x)
        for log_result in res.get_logs():
            for tmp in y:
                if log_result.get_contents()['protecion_info'] == tmp:
                    tt = result[tmp]
                    tt[x_exist[log_result.get_contents()['time']]] = log_result.get_contents()['count']
                    result[tmp] = tt
        return_result['result'] = True
        return_result['message'] = result
        return_result['x'] = x
        return_result['y'] = y
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)


def chart_get_attack_ip_count(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        #domain = json_data['domain']
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        if time_zone == "7day":
            from_time = int(time() - 604800)
            req_sql = ATT_IP_COUNT_7D
        elif time_zone == "24hour":
            from_time = int(time() - 86400)
            req_sql = ATT_IP_COUNT_24H
        global_result = waf_global.objects.get(user_id=user_id)
        endpoint = global_result.aliyun_log_endpoint.replace('https://', '').replace('http://', '')
        accessKeyId = global_result.aliyun_access_id
        accessKey = global_result.aliyun_access_secret
        project = global_result.aliyun_project
        logstore = global_result.aliyun_logstore
        client = LogClient(endpoint, accessKeyId, accessKey)
        req = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=req_sql)
        res = client.get_logs(req)
        for log_result in res.get_logs():
            try:
                data.append({'time': log_result.get_contents()['time'],
                             'ip_count': log_result.get_contents()['ip_count'],
                             }
                            )
            except:
                pass
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def chart_get_attack_black_ip_count(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        #domain = json_data['domain']
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        if time_zone == "7day":
            from_time = int(time() - 604800)
            req_sql = ATT_BLACK_IP_COUNT_7D
        elif time_zone == "24hour":
            from_time = int(time() - 86400)
            req_sql = ATT_BLACK_IP_COUNT_24H
        global_result = waf_global.objects.get(user_id=user_id)
        endpoint = global_result.aliyun_log_endpoint.replace('https://', '').replace('http://', '')
        accessKeyId = global_result.aliyun_access_id
        accessKey = global_result.aliyun_access_secret
        project = global_result.aliyun_project
        logstore = global_result.aliyun_logstore
        client = LogClient(endpoint, accessKeyId, accessKey)
        req = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=req_sql)
        res = client.get_logs(req)
        for log_result in res.get_logs():
            try:
                data.append({'time': log_result.get_contents()['time'],
                             'ip_count': log_result.get_contents()['ip_count'],
                             }
                            )
            except:
                pass
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def chart_get_cc_type(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        #domain = json_data['domain']
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        if time_zone == "7day":
            from_time = int(time() - 604800)
            req_sql = CC_TYPE_7D
        elif time_zone == "24hour":
            req_sql = CC_TYPE_24H
            from_time = int(time() - 86400)
        global_result = waf_global.objects.get(user_id=user_id)
        endpoint = global_result.aliyun_log_endpoint.replace('https://', '').replace('http://', '')
        accessKeyId = global_result.aliyun_access_id
        accessKey = global_result.aliyun_access_secret
        project = global_result.aliyun_project
        logstore = global_result.aliyun_logstore
        client = LogClient(endpoint, accessKeyId, accessKey)
        req = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=req_sql)
        res = client.get_logs(req)
        x = []
        x_exist = {}
        y = []
        y_exist = {}
        for log_result in res.get_logs():
            print log_result.get_contents()
            if not x_exist.has_key(log_result.get_contents()['time']):
                x.append(log_result.get_contents()['time'])
                x_exist[log_result.get_contents()['time']] = len(x) - 1
            if not y_exist.has_key(log_result.get_contents()['protecion_info']):
                if log_result.get_contents()['protecion_info'] != 'null':
                    y.append(log_result.get_contents()['protecion_info'])
                    y_exist[log_result.get_contents()['protecion_info']] = True
        result = {}
        for tmp in y:
            ss = [0]
            result[tmp] = ss * len(x)
        for log_result in res.get_logs():
            for tmp in y:
                if log_result.get_contents()['protecion_info'] == tmp:
                    tt = result[tmp]
                    tt[x_exist[log_result.get_contents()['time']]] = log_result.get_contents()['count']
                    result[tmp] = tt
        return_result['result'] = True
        return_result['message'] = result
        return_result['x'] = x
        return_result['y'] = y
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def chart_get_cc_ip_count(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        #domain = json_data['domain']
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        if time_zone == "7day":
            from_time = int(time() - 604800)
            req_sql = CC_IP_COUNT_7D
        elif time_zone == "24hour":
            from_time = int(time() - 86400)
            req_sql = CC_IP_COUNT_24H
        global_result = waf_global.objects.get(user_id=user_id)
        endpoint = global_result.aliyun_log_endpoint.replace('https://', '').replace('http://', '')
        accessKeyId = global_result.aliyun_access_id
        accessKey = global_result.aliyun_access_secret
        project = global_result.aliyun_project
        logstore = global_result.aliyun_logstore
        client = LogClient(endpoint, accessKeyId, accessKey)
        req = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=req_sql)
        res = client.get_logs(req)
        for log_result in res.get_logs():
            try:
                data.append({'time': log_result.get_contents()['time'],
                             'ip_count': log_result.get_contents()['ip_count'],
                             }
                            )
            except:
                pass
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def chart_get_cc_black_ip_count(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        #domain = json_data['domain']
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        if time_zone == "7day":
            from_time = int(time() - 604800)
            req_sql = CC_BLACK_IP_COUNT_7D
        elif time_zone == "24hour":
            from_time = int(time() - 86400)
            req_sql = CC_BLACK_IP_COUNT_24H
        global_result = waf_global.objects.get(user_id=user_id)
        endpoint = global_result.aliyun_log_endpoint.replace('https://', '').replace('http://', '')
        accessKeyId = global_result.aliyun_access_id
        accessKey = global_result.aliyun_access_secret
        project = global_result.aliyun_project
        logstore = global_result.aliyun_logstore
        client = LogClient(endpoint, accessKeyId, accessKey)
        req = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=req_sql)
        res = client.get_logs(req)
        for log_result in res.get_logs():
            try:
                data.append({'time': log_result.get_contents()['time'],
                             'ip_count': log_result.get_contents()['ip_count'],
                             }
                            )
            except:
                pass
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def chart_get_attack_totle_black_ip_count(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        #domain = json_data['domain']
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        if time_zone == "7day":
            from_time = int(time() - 604800)
        elif time_zone == "24hour":
            from_time = int(time() - 86400)
        global_result = waf_global.objects.get(user_id=user_id)
        endpoint = global_result.aliyun_log_endpoint.replace('https://', '').replace('http://', '')
        accessKeyId = global_result.aliyun_access_id
        accessKey = global_result.aliyun_access_secret
        project = global_result.aliyun_project
        logstore = global_result.aliyun_logstore
        client = LogClient(endpoint, accessKeyId, accessKey)
        req = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=ATT_IP_TOTLE_COUNT)
        res = client.get_logs(req)
        ip_count = ""
        for log_result in res.get_logs():
            try:
                ip_count = log_result.get_contents()['ip_count']
            except:
                pass
        return_result['result'] = True
        return_result['message'] = ip_count
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def chart_get_cc_totle_black_ip_count(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        #domain = json_data['domain']
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        if time_zone == "7day":
            from_time = int(time() - 604800)
        elif time_zone == "24hour":
            from_time = int(time() - 86400)
        global_result = waf_global.objects.get(user_id=user_id)
        endpoint = global_result.aliyun_log_endpoint.replace('https://', '').replace('http://', '')
        accessKeyId = global_result.aliyun_access_id
        accessKey = global_result.aliyun_access_secret
        project = global_result.aliyun_project
        logstore = global_result.aliyun_logstore
        client = LogClient(endpoint, accessKeyId, accessKey)
        req = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=CC_IP_TOTLE_COUNT)
        res = client.get_logs(req)
        ip_count = ""
        for log_result in res.get_logs():
            try:
                ip_count = log_result.get_contents()['ip_count']
            except:
                pass
        return_result['result'] = True
        return_result['message'] = ip_count
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)