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

#totle count
REQUEST_TOTLE_COUNT = "* |select count(*) as count"
UPSTREAM_TOTLE_COUNT = "* and (not upstream_addr: -)|select count(*) as count"
DOMAIN_REQUEST_TOTLE_COUNT = '* and host: "%s" and (not upstream_addr: -)|select count(*) as count |select count(*) as count'
DOMAIN_UPSTREAM_TOTLE_COUNT = '* and host: "%s" and (not upstream_addr: -)|select count(*) as count'
# req count
REQUEST_COUNT_TREND_7D = "*   | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
REQUEST_COUNT_TREND_24H = "*  | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
REQUEST_COUNT_TREND_1H = "*   | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"
UPSTREAM_COUNT_TREND_7D = "*  and (not upstream_addr: -) | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
UPSTREAM_COUNT_TREND_24H = "*  and (not upstream_addr: -) | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
UPSTREAM_COUNT_TREND_1H = "*  and (not upstream_addr: -) | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"
DOMAIN_REQUEST_COUNT_TREND_7D = "* and host: \"%s\"  | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_REQUEST_COUNT_TREND_24H = "* and host: \"%s\" | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_REQUEST_COUNT_TREND_1H = "* and host: \"%s\" | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"
DOMAIN_UPSTREAM_COUNT_TREND_7D = "* and (not upstream_addr: -)  and host: \"%s\"| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_UPSTREAM_COUNT_TREND_24H = "* and (not upstream_addr: -) and host: \"%s\" | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_UPSTREAM_COUNT_TREND_1H = "* and (not upstream_addr: -)  and host: \"%s\"| select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"
# req input byte
INPUT_TREND_7D = "*   | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,sum(bytes_received) as count group by time order by time"
INPUT_TREND_24H = "*  | select time_series(request_time,'1h','%m-%d-%H', '0') as time,sum(bytes_received) as count group by time order by time"
INPUT_TREND_1H = "*   | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,sum(bytes_received) as count group by time order by time"
UPSTREAM_INPUT_TREND_7D = "*  and (not upstream_addr: -) | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,sum(cast(upstream_bytes_sent AS double)) as count group by time order by time"
UPSTREAM_INPUT_TREND_24H = "*  and (not upstream_addr: -) | select time_series(request_time,'1h','%m-%d-%H', '0') as time,sum(cast(upstream_bytes_sent AS double)) as count group by time order by time"
UPSTREAM_INPUT_TREND_1H = "*  and (not upstream_addr: -) | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,sum(cast(upstream_bytes_sent AS double)) as count group by time order by time"
DOMAIN_INPUT_TREND_7D = "* and host: \"%s\"  | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,sum(bytes_received) as count group by time order by time"
DOMAIN_INPUT_TREND_24H = "* and host: \"%s\" | select time_series(request_time,'1h','%m-%d-%H', '0') as time,sum(bytes_received) as count group by time order by time"
DOMAIN_INPUT_TREND_1H = "* and host: \"%s\" | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,sum(bytes_received) as count group by time order by time"
DOMAIN_UPSTREAM_INPUT_TREND_7D = "* and (not upstream_addr: -)  and host: \"%s\"| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,sum(cast(upstream_bytes_sent AS double)) as count group by time order by time"
DOMAIN_UPSTREAM_INPUT_TREND_24H = "* and (not upstream_addr: -) and host: \"%s\" | select time_series(request_time,'1h','%m-%d-%H', '0') as time,sum(cast(upstream_bytes_sent AS double)) as count group by time order by time"
DOMAIN_UPSTREAM_INPUT_TREND_1H = "* and (not upstream_addr: -)  and host: \"%s\"| select time_series(request_time,'5m', '%H:%i:%s', '0') as time,sum(cast(upstream_bytes_sent AS double)) as count group by time order by time"
# req output byte
OUTPUT_TREND_7D = "*   | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,sum(bytes_sent) as count group by time order by time"
OUTPUT_TREND_24H = "*  | select time_series(request_time,'1h','%m-%d-%H', '0') as time,sum(bytes_sent) as count group by time order by time"
OUTPUT_TREND_1H = "*   | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,sum(bytes_sent) as count group by time order by time"
UPSTREAM_OUTPUT_TREND_7D = "*  and (not upstream_addr: -) | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,sum(cast(upstream_bytes_received AS double)) as count group by time order by time"
UPSTREAM_OUTPUT_TREND_24H = "*  and (not upstream_addr: -) | select time_series(request_time,'1h','%m-%d-%H', '0') as time,sum(cast(upstream_bytes_received AS double)) as count group by time order by time"
UPSTREAM_OUTPUT_TREND_1H = "*  and (not upstream_addr: -) | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,sum(cast(upstream_bytes_received AS double)) as count group by time order by time"
DOMAIN_OUTPUT_TREND_7D = "* and host: \"%s\"  | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,sum(bytes_sent) as count group by time order by time"
DOMAIN_OUTPUT_TREND_24H = "* and host: \"%s\" | select time_series(request_time,'1h','%m-%d-%H', '0') as time,sum(bytes_sent) as count group by time order by time"
DOMAIN_OUTPUT_TREND_1H = "* and host: \"%s\" | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,sum(bytes_sent) as count group by time order by time"
DOMAIN_UPSTREAM_OUTPUT_TREND_7D = "* and (not upstream_addr: -)  and host: \"%s\"| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,sum(cast(upstream_bytes_received AS double)) as count group by time order by time"
DOMAIN_UPSTREAM_OUTPUT_TREND_24H = "* and (not upstream_addr: -) and host: \"%s\" | select time_series(request_time,'1h','%m-%d-%H', '0') as time,sum(cast(upstream_bytes_received AS double)) as count group by time order by time"
DOMAIN_UPSTREAM_OUTPUT_TREND_1H = "* and (not upstream_addr: -)  and host: \"%s\"| select time_series(request_time,'5m', '%H:%i:%s', '0') as time,sum(cast(upstream_bytes_received AS double)) as count group by time order by time"
# prossess time
PROCESS_TREND_7D = "*   | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,avg(request_process_time) as count group by time order by time"
PROCESS_TREND_24H = "*  | select time_series(request_time,'1h','%m-%d-%H', '0') as time,avg(request_process_time) as count group by time order by time"
PROCESS_TREND_1H = "*   | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,avg(request_process_time) as count group by time order by time"
UPSTREAM_PROCESS_TREND_7D = "*  and (not upstream_addr: -) | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,avg(cast(upstream_response_time AS double)) as count group by time order by time"
UPSTREAM_PROCESS_TREND_24H = "*  and (not upstream_addr: -) | select time_series(request_time,'1h','%m-%d-%H', '0') as time,avg(cast(upstream_response_time AS double)) as count group by time order by time"
UPSTREAM_PROCESS_TREND_1H = "*  and (not upstream_addr: -) | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,avg(cast(upstream_response_time AS double)) as count group by time order by time"
DOMAIN_PROCESS_TREND_7D = "* and host: \"%s\"  | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,avg(request_process_time) as count group by time order by time"
DOMAIN_PROCESS_TREND_24H = "* and host: \"%s\" | select time_series(request_time,'1h','%m-%d-%H', '0') as time,avg(request_process_time) as count group by time order by time"
DOMAIN_PROCESS_TREND_1H = "* and host: \"%s\" | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,avg(request_process_time) as count group by time order by time"
DOMAIN_UPSTREAM_PROCESS_TREND_7D = "* and (not upstream_addr: -)  and host: \"%s\"| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,avg(cast(upstream_response_time AS double)) as count group by time order by time"
DOMAIN_UPSTREAM_PROCESS_TREND_24H = "* and (not upstream_addr: -) and host: \"%s\" | select time_series(request_time,'1h','%m-%d-%H', '0') as time,avg(cast(upstream_response_time AS double)) as count group by time order by time"
DOMAIN_UPSTREAM_PROCESS_TREND_1H = "* and (not upstream_addr: -)  and host: \"%s\"| select time_series(request_time,'5m', '%H:%i:%s', '0') as time,avg(cast(upstream_response_time AS double)) as count group by time order by time"
# bad request count
BAD_REQUEST_COUNT_TREND_7D = "*  and status >= 400 | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
BAD_REQUEST_COUNT_TREND_24H = "* and status >= 400 | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
BAD_REQUEST_COUNT_TREND_1H = "*  and status >= 400 | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"
UPSTREAM_BAD_COUNT_TREND_7D = "*  and (not upstream_addr: -) and status >= 400| select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
UPSTREAM_BAD_COUNT_TREND_24H = "*  and (not upstream_addr: -) and status >= 400| select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
UPSTREAM_BAD_COUNT_TREND_1H = "*  and (not upstream_addr: -) and status >= 400| select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"
DOMAIN_BAD_REQUEST_COUNT_TREND_7D = "* and host: \"%s\" and status >= 400 | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_BAD_REQUEST_COUNT_TREND_24H = "* and host: \"%s\" and status >= 400 | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_BAD_REQUEST_COUNT_TREND_1H = "* and host: \"%s\" and status >= 400 | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"
DOMAIN_BAD_UPSTREAM_COUNT_TREND_7D = "* and (not upstream_addr: -)  and host: \"%s\" and status >= 400 | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_BAD_UPSTREAM_COUNT_TREND_24H = "* and (not upstream_addr: -) and host: \"%s\" and status >= 400 | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_BAD_UPSTREAM_COUNT_TREND_1H = "* and (not upstream_addr: -)  and host: \"%s\" and status >= 400 | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"
# IP trend
IP_TREND_7D = "*   | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
IP_TREND_24H = "*  | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
IP_TREND_1H = "*   | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
DOMAIN_IP_TREND_7D = "* and host: \"%s\"  | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
DOMAIN_IP_TREND_24H = "* and host: \"%s\" | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(DISTINCT client_ip) as count group by time order by time"
DOMAIN_IP_TREND_1H = "* and host: \"%s\" | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(DISTINCT client_ip) as count group by time order by time"


def flow_chart_get_totle_count(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        try:
            domain = json_data['domain']
            req_sql = DOMAIN_REQUEST_TOTLE_COUNT%(domain)
            req_sql2 = DOMAIN_UPSTREAM_TOTLE_COUNT%(domain)
        except:
            req_sql = REQUEST_TOTLE_COUNT
            req_sql2 = UPSTREAM_TOTLE_COUNT
        time_zone = json_data['time_zone']
        from_time = int(time() - 86400)
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
        request_count = ""
        for log_result in res.get_logs():
            try:
                request_count = log_result.get_contents()['count']
            except:
                pass
        client2 = LogClient(endpoint, accessKeyId, accessKey)
        req2 = GetLogsRequest(project=project, logstore=logstore, fromTime=from_time, toTime=int(time()), topic='',
                             query=req_sql2)
        res2= client2.get_logs(req2)
        upstream_count = ""
        for log_result2 in res2.get_logs():
            try:
                upstream_count = log_result2.get_contents()['count']
            except:
                pass
        return_result['result'] = True
        return_result['request_count'] = request_count
        return_result['upstream_count'] = upstream_count
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def flow_chart_get_req_count_trend(request):
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
                req_sql = DOMAIN_REQUEST_COUNT_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_REQUEST_COUNT_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_REQUEST_COUNT_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = REQUEST_COUNT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = REQUEST_COUNT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = REQUEST_COUNT_TREND_1H
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)



def flow_chart_get_upstream_count_trend(request):
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
                req_sql = DOMAIN_UPSTREAM_COUNT_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_UPSTREAM_COUNT_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_UPSTREAM_COUNT_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = UPSTREAM_COUNT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = UPSTREAM_COUNT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = UPSTREAM_COUNT_TREND_1H
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def flow_chart_get_input_byte_trend(request):
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
                req_sql = DOMAIN_INPUT_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_INPUT_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_INPUT_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = INPUT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = INPUT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = INPUT_TREND_1H
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
                             'count': round((float(log_result.get_contents()['count'])/1024)/1024,2),
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)



def flow_chart_get_upstream_input_byte_trend(request):
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
                req_sql = DOMAIN_UPSTREAM_INPUT_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_UPSTREAM_INPUT_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_UPSTREAM_INPUT_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = UPSTREAM_INPUT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = UPSTREAM_INPUT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = UPSTREAM_INPUT_TREND_1H
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
                             'count': round((float(log_result.get_contents()['count'])/1024)/1024,2),
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)

def flow_chart_get_output_byte_trend(request):
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
                req_sql = DOMAIN_OUTPUT_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_OUTPUT_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_OUTPUT_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = OUTPUT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = OUTPUT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = OUTPUT_TREND_1H
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
                             'count': round((float(log_result.get_contents()['count'])/1024)/1024,2),
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)



def flow_chart_get_upstream_output_byte_trend(request):
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
                req_sql = DOMAIN_UPSTREAM_OUTPUT_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_UPSTREAM_OUTPUT_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_UPSTREAM_OUTPUT_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = UPSTREAM_OUTPUT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = UPSTREAM_OUTPUT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = UPSTREAM_OUTPUT_TREND_1H
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
                             'count': round((float(log_result.get_contents()['count'])/1024)/1024,2),
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def flow_chart_get_process_time_trend(request):
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
                req_sql = DOMAIN_PROCESS_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_PROCESS_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_PROCESS_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = PROCESS_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = PROCESS_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = PROCESS_TREND_1H
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
                             'count': round(float(log_result.get_contents()['count']),4),
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)



def flow_chart_get_upstream_process_time_trend(request):
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
                req_sql = DOMAIN_UPSTREAM_PROCESS_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_UPSTREAM_PROCESS_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_UPSTREAM_PROCESS_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = UPSTREAM_PROCESS_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = UPSTREAM_PROCESS_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = UPSTREAM_PROCESS_TREND_1H
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
                             'count': round(float(log_result.get_contents()['count']),4),
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)

def flow_chart_get_bad_req_count_trend(request):
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
                req_sql = DOMAIN_BAD_REQUEST_COUNT_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_BAD_REQUEST_COUNT_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_BAD_REQUEST_COUNT_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = BAD_REQUEST_COUNT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = BAD_REQUEST_COUNT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = BAD_REQUEST_COUNT_TREND_1H
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)



def flow_chart_get_bad_upstream_count_trend(request):
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
                req_sql = DOMAIN_BAD_UPSTREAM_COUNT_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql =DOMAIN_BAD_UPSTREAM_COUNT_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_BAD_UPSTREAM_COUNT_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = UPSTREAM_BAD_COUNT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = UPSTREAM_BAD_COUNT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = UPSTREAM_BAD_COUNT_TREND_1H
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def flow_chart_get_ip_trend(request):
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
                req_sql = DOMAIN_IP_TREND_7D%(domain)
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = DOMAIN_IP_TREND_24H%(domain)
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = DOMAIN_IP_TREND_1H%(domain)
        except:
            if time_zone == "7day":
                from_time = int(time() - 604800)
                req_sql = IP_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time() - 86400)
                req_sql = IP_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time() - 3600)
                req_sql = IP_TREND_1H
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
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)