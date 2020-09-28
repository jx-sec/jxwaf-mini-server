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

ATT_TYPE_7D = "* and log_type: owasp_attack | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count,protection_type as protection_type group by time,protection_type order by time"
ATT_TYPE_24H = "* and log_type: owasp_attack | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count,protection_type as protection_type group by time,protection_type order by time"
ATT_TYPE_1H = "* and log_type: owasp_attack  | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count,protection_type as protection_type group by time,protection_type order by time"
DOMAIN_ATT_TYPE_7D = "* and log_type: owasp_attack and host: \"%s\"| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count,protection_type as protection_type group by time,protection_type order by time"
DOMAIN_ATT_TYPE_24H = "* and log_type: owasp_attack and host: \"%s\"| select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count,protection_type as protection_type group by time,protection_type order by time"
DOMAIN_ATT_TYPE_1H = "* and log_type: owasp_attack and host: \"%s\" | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count,protection_type as protection_type group by time,protection_type order by time"
ATT_IP_7D = "* and log_type: owasp_attack | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
ATT_IP_24H = "* and log_type: owasp_attack | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
ATT_IP_1H = "* and log_type: owasp_attack  | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
DOMAIN_ATT_IP_7D = "* and log_type: owasp_attack and host: \"%s\"| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
DOMAIN_ATT_IP_24H = "* and log_type: owasp_attack and host: \"%s\"| select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
DOMAIN_ATT_IP_1H = "* and log_type: owasp_attack and host: \"%s\" | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
ATT_BLACK_IP_7D = "* and log_type: owasp_attack  and protection_type: black_ip| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
ATT_BLACK_IP_24H = "* and log_type: owasp_attack and protection_type: black_ip| select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
ATT_BLACK_IP_1H = "* and log_type: owasp_attack  and protection_type: black_ip | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
DOMAIN_ATT_BLACK_IP_7D = "* and log_type: owasp_attack and host: \"%s\" and protection_type: black_ip | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
DOMAIN_ATT_BLACK_IP_24H = "* and log_type: owasp_attack and host: \"%s\" and protection_type: black_ip | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
DOMAIN_ATT_BLACK_IP_1H = "* and log_type: owasp_attack and host: \"%s\" and protection_type: black_ip | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
ATT_REQ_COUNT_AND_IP_COUNT = '* and log_type: owasp_attack  | select count(*) as req_count,count(DISTINCT client_ip) as ip_count'
DOMAIN_ATT_REQ_COUNT_AND_IP_COUNT = '* and log_type: owasp_attack  and host: \"%s\"| select count(*) as req_count,count(DISTINCT client_ip) as ip_count'
ATT_BLACK_IP_COUNT = '* and log_type: owasp_attack and protection_type: black_ip  | select count(DISTINCT client_ip) as black_ip_count'
DOMAIN_ATT_BLACK_IP_COUNT = '* and log_type: owasp_attack and protection_type: black_ip and host: \"%s\" | select count(DISTINCT client_ip) as black_ip_count'
ATT_TYPE_TOP10 = '* and log_type: owasp_attack  | select protection_type as protection_type,count(*) as count group by protection_type order by count desc limit 10'
DOMAIN_ATT_TYPE_TOP10 = '* and log_type: owasp_attack and host: \"%s\" | select protection_type as protection_type,count(*) as count group by protection_type order by count desc limit 10'
ATT_URI_TOP10 = '* and log_type: owasp_attack  | select uri as uri,count(*) as count group by uri order by count desc limit 10'
DOMAIN_ATT_URI_TOP10 = '* and log_type: owasp_attack  | select uri as uri,count(*) as count group by uri order by count desc limit 10'

def attack_chart_get_type_trend(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = DOMAIN_ATT_TYPE_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_ATT_TYPE_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_ATT_TYPE_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = ATT_TYPE_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = ATT_TYPE_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = ATT_TYPE_1H
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
                             'count': log_result.get_contents()['count'],
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



def attack_chart_get_ip_trend(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = DOMAIN_ATT_IP_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_ATT_IP_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_ATT_IP_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = ATT_IP_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = ATT_IP_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = ATT_IP_1H
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
                             'count': log_result.get_contents()['count'],
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


def attack_chart_get_black_ip_trend(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = DOMAIN_ATT_BLACK_IP_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_ATT_BLACK_IP_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_ATT_BLACK_IP_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = ATT_BLACK_IP_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = ATT_BLACK_IP_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = ATT_BLACK_IP_1H
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
                             'count': log_result.get_contents()['count'],
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

def attack_chart_get_req_count_and_ip_count(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        try:
            domain = json_data['domain']
            req_sql = DOMAIN_ATT_REQ_COUNT_AND_IP_COUNT%(domain)
            if time_zone == "7day":
                from_time = int(time() - 604800)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
        except:
            req_sql = ATT_REQ_COUNT_AND_IP_COUNT
            if time_zone == "7day":
                from_time = int(time() - 604800)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
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
        req_count = ''
        ip_count = ''
        for log_result in res.get_logs():
            try:
                req_count = log_result.get_contents()['req_count']
                ip_count = log_result.get_contents()['ip_count']
            except:
                pass
        return_result['result'] = True
        return_result['req_count'] = req_count
        return_result['ip_count'] = ip_count
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def attack_chart_get_black_ip_count(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        try:
            domain = json_data['domain']
            req_sql = DOMAIN_ATT_BLACK_IP_COUNT%(domain)
            if time_zone == "7day":
                from_time = int(time() - 604800)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
        except:
            req_sql = ATT_BLACK_IP_COUNT
            if time_zone == "7day":
                from_time = int(time() - 604800)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
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
        black_ip_count = ''
        for log_result in res.get_logs():
            try:
                black_ip_count = log_result.get_contents()['black_ip_count']

            except:
                pass
        return_result['result'] = True
        return_result['black_ip_count'] = black_ip_count
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 103
        return JsonResponse(return_result, safe=False)

def attack_chart_get_type_top10(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        try:
            domain = json_data['domain']
            req_sql = DOMAIN_ATT_TYPE_TOP10%(domain)
            if time_zone == "7day":
                from_time = int(time() - 604800)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
        except:
            req_sql = ATT_TYPE_TOP10
            if time_zone == "7day":
                from_time = int(time() - 604800)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
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
                data.append({'protection_type': log_result.get_contents()['protection_type'],
                             'count': log_result.get_contents()['count'],
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

def attack_chart_get_uri_top10(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
        try:
            domain = json_data['domain']
            req_sql = DOMAIN_ATT_URI_TOP10%(domain)
            if time_zone == "7day":
                from_time = int(time() - 604800)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
        except:
            req_sql = ATT_URI_TOP10
            if time_zone == "7day":
                from_time = int(time() - 604800)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
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
                data.append({'uri': log_result.get_contents()['uri'],
                             'count': log_result.get_contents()['count'],
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