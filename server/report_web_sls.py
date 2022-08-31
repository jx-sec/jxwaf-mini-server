# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from aliyun.log import LogClient
from aliyun.log.getlogsrequest import GetLogsRequest
from server.models import *

WEB_REQUEST_COUNT_TREND_7D = "*  and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
WEB_REQUEST_COUNT_TREND_24H = "*  and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
WEB_REQUEST_COUNT_TREND_1H = "*  and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"
DOMAIN_WEB_REQUEST_COUNT_TREND_7D = "* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_WEB_REQUEST_COUNT_TREND_24H = "* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(*) as count group by time order by time"
DOMAIN_WEB_REQUEST_COUNT_TREND_1H = "* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(*) as count group by time order by time"

WEB_IP_COUNT_TREND_7D = "*  and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(DISTINCT src_ip) as count group by time order by time"
WEB_IP_COUNT_TREND_24H = "*  and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(DISTINCT src_ip) as count group by time order by time"
WEB_IP_COUNT_TREND_1H = "*  and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(DISTINCT src_ip) as count group by time order by time"
DOMAIN_WEB_IP_COUNT_TREND_7D = "* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'1d', '%m-%d-%H', '0') as time,count(DISTINCT src_ip) as count group by time order by time"
DOMAIN_WEB_IP_COUNT_TREND_24H = "* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'1h','%m-%d-%H', '0') as time,count(DISTINCT src_ip) as count group by time order by time"
DOMAIN_WEB_IP_COUNT_TREND_1H = "* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select time_series(request_time,'5m', '%H:%i:%s', '0') as time,count(DISTINCT src_ip) as count group by time order by time"

WEB_REQUEST_COUNT_TOTLE = "*  and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select count(*) as count"
DOMAIN_WEB_REQUEST_COUNT_TOTLE = "* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select count(*) as count"

WEB_REQUEST_IP_TOTLE = "*  and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select count(DISTINCT src_ip) as count"
DOMAIN_WEB_REQUEST_IP_TOTLE = "* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection) | select count(DISTINCT src_ip) as count"

WEB_ATT_TYPE_TOP10 = '* and (waf_module: web_rule_protection or waf_module: web_engine_protection)  | select waf_policy as waf_policy,count(*) as count group by waf_policy order by count desc limit 10'
DOMAIN_WEB_ATT_TYPE_TOP10 = '* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection)  | select waf_policy as waf_policy,count(*) as count group by waf_policy order by count desc limit 10'

WEB_ATT_IP_TOP10 = '* and (waf_module: web_rule_protection or waf_module: web_engine_protection)  | select src_ip as src_ip,count(*) as count group by src_ip order by count desc limit 10'
DOMAIN_WEB_ATT_IP_TOP10 = '* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection)  | select src_ip as src_ip,count(*) as count group by src_ip order by count desc limit 10'

WEB_ATT_URI_TOP10 = '* and (waf_module: web_rule_protection or waf_module: web_engine_protection)  | select uri as uri,count(*) as count group by uri order by count desc limit 10'
DOMAIN_WEB_ATT_URI_TOP10 = '* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection)  | select uri as uri,count(*) as count group by uri order by count desc limit 10'

WEB_ATT_IP_COUNTRY_TOP10 = '* and (waf_module: web_rule_protection or waf_module: web_engine_protection)  | select ip_to_country(src_ip) as country,count(*) as count group by country order by count desc limit 10'
DOMAIN_WEB_ATT_IP_COUNTRY_TOP10 = '* and host: \"{}\" and (waf_module: web_rule_protection or waf_module: web_engine_protection)  | select ip_to_country(src_ip) as country,count(*) as count group by country order by count desc limit 10'


def sls_report_web_request_count_trend(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TREND_7D.format(domain)
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TREND_24H.format(domain)
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TREND_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = WEB_REQUEST_COUNT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = WEB_REQUEST_COUNT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = WEB_REQUEST_COUNT_TREND_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        to_time = int(time.time())
        sls_AccessKey_ID = sys_report_conf_result.sls_AccessKey_ID
        sls_AccessKey_Secret = sys_report_conf_result.sls_AccessKey_Secret
        sls_endpoint = sys_report_conf_result.sls_endpoint.replace('https://', '').replace('http://', '')
        sls_project = sys_report_conf_result.sls_project
        sls_logstore = sys_report_conf_result.sls_logstore
        client = LogClient(sls_endpoint, sls_AccessKey_ID, sls_AccessKey_Secret)
        req = GetLogsRequest(project=sls_project, logstore=sls_logstore, fromTime=from_time, toTime=to_time, topic='',
                             query=req_sql)
        res = client.get_logs(req)
        return_result['result'] = True
        return_result['message'] = res.get_body()
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def sls_report_web_ip_count_trend(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = DOMAIN_WEB_IP_COUNT_TREND_7D.format(domain)
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = DOMAIN_WEB_IP_COUNT_TREND_24H.format(domain)
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = DOMAIN_WEB_IP_COUNT_TREND_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = WEB_IP_COUNT_TREND_7D
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = WEB_IP_COUNT_TREND_24H
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = WEB_IP_COUNT_TREND_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        to_time = int(time.time())
        sls_AccessKey_ID = sys_report_conf_result.sls_AccessKey_ID
        sls_AccessKey_Secret = sys_report_conf_result.sls_AccessKey_Secret
        sls_endpoint = sys_report_conf_result.sls_endpoint.replace('https://', '').replace('http://', '')
        sls_project = sys_report_conf_result.sls_project
        sls_logstore = sys_report_conf_result.sls_logstore
        client = LogClient(sls_endpoint, sls_AccessKey_ID, sls_AccessKey_Secret)
        req = GetLogsRequest(project=sls_project, logstore=sls_logstore, fromTime=from_time, toTime=to_time, topic='',
                             query=req_sql)
        res = client.get_logs(req)
        return_result['result'] = True
        return_result['message'] = res.get_body()
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def sls_report_web_request_count_totle(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TOTLE.format(domain)
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TOTLE.format(domain)
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TOTLE.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = WEB_REQUEST_COUNT_TOTLE
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = WEB_REQUEST_COUNT_TOTLE
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = WEB_REQUEST_COUNT_TOTLE
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        to_time = int(time.time())
        sls_AccessKey_ID = sys_report_conf_result.sls_AccessKey_ID
        sls_AccessKey_Secret = sys_report_conf_result.sls_AccessKey_Secret
        sls_endpoint = sys_report_conf_result.sls_endpoint.replace('https://', '').replace('http://', '')
        sls_project = sys_report_conf_result.sls_project
        sls_logstore = sys_report_conf_result.sls_logstore
        client = LogClient(sls_endpoint, sls_AccessKey_ID, sls_AccessKey_Secret)
        req = GetLogsRequest(project=sls_project, logstore=sls_logstore, fromTime=from_time, toTime=to_time, topic='',
                             query=req_sql)
        res = client.get_logs(req)
        return_result['result'] = True
        return_result['message'] = res.get_body()
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def sls_report_web_request_ip_totle(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = DOMAIN_WEB_REQUEST_IP_TOTLE.format(domain)
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = DOMAIN_WEB_REQUEST_IP_TOTLE.format(domain)
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = DOMAIN_WEB_REQUEST_IP_TOTLE.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = WEB_REQUEST_IP_TOTLE
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = WEB_REQUEST_IP_TOTLE
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = WEB_REQUEST_IP_TOTLE
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        to_time = int(time.time())
        sls_AccessKey_ID = sys_report_conf_result.sls_AccessKey_ID
        sls_AccessKey_Secret = sys_report_conf_result.sls_AccessKey_Secret
        sls_endpoint = sys_report_conf_result.sls_endpoint.replace('https://', '').replace('http://', '')
        sls_project = sys_report_conf_result.sls_project
        sls_logstore = sys_report_conf_result.sls_logstore
        client = LogClient(sls_endpoint, sls_AccessKey_ID, sls_AccessKey_Secret)
        req = GetLogsRequest(project=sls_project, logstore=sls_logstore, fromTime=from_time, toTime=to_time, topic='',
                             query=req_sql)
        res = client.get_logs(req)
        return_result['result'] = True
        return_result['message'] = res.get_body()
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def sls_report_web_att_type_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = DOMAIN_WEB_ATT_TYPE_TOP10.format(domain)
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = DOMAIN_WEB_ATT_TYPE_TOP10.format(domain)
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = DOMAIN_WEB_ATT_TYPE_TOP10.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = WEB_ATT_TYPE_TOP10
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = WEB_ATT_TYPE_TOP10
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = WEB_ATT_TYPE_TOP10
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        to_time = int(time.time())
        sls_AccessKey_ID = sys_report_conf_result.sls_AccessKey_ID
        sls_AccessKey_Secret = sys_report_conf_result.sls_AccessKey_Secret
        sls_endpoint = sys_report_conf_result.sls_endpoint.replace('https://', '').replace('http://', '')
        sls_project = sys_report_conf_result.sls_project
        sls_logstore = sys_report_conf_result.sls_logstore
        client = LogClient(sls_endpoint, sls_AccessKey_ID, sls_AccessKey_Secret)
        req = GetLogsRequest(project=sls_project, logstore=sls_logstore, fromTime=from_time, toTime=to_time, topic='',
                             query=req_sql)
        res = client.get_logs(req)
        return_result['result'] = True
        return_result['message'] = res.get_body()
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def sls_report_web_att_ip_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = DOMAIN_WEB_ATT_IP_TOP10.format(domain)
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = DOMAIN_WEB_ATT_IP_TOP10.format(domain)
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = DOMAIN_WEB_ATT_IP_TOP10.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = WEB_ATT_IP_TOP10
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = WEB_ATT_IP_TOP10
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = WEB_ATT_IP_TOP10
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        to_time = int(time.time())
        sls_AccessKey_ID = sys_report_conf_result.sls_AccessKey_ID
        sls_AccessKey_Secret = sys_report_conf_result.sls_AccessKey_Secret
        sls_endpoint = sys_report_conf_result.sls_endpoint.replace('https://', '').replace('http://', '')
        sls_project = sys_report_conf_result.sls_project
        sls_logstore = sys_report_conf_result.sls_logstore
        client = LogClient(sls_endpoint, sls_AccessKey_ID, sls_AccessKey_Secret)
        req = GetLogsRequest(project=sls_project, logstore=sls_logstore, fromTime=from_time, toTime=to_time, topic='',
                             query=req_sql)
        res = client.get_logs(req)
        return_result['result'] = True
        return_result['message'] = res.get_body()
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def sls_report_web_att_uri_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = DOMAIN_WEB_ATT_URI_TOP10.format(domain)
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = DOMAIN_WEB_ATT_URI_TOP10.format(domain)
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = DOMAIN_WEB_ATT_URI_TOP10.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = WEB_ATT_URI_TOP10
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = WEB_ATT_URI_TOP10
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = WEB_ATT_URI_TOP10
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        to_time = int(time.time())
        sls_AccessKey_ID = sys_report_conf_result.sls_AccessKey_ID
        sls_AccessKey_Secret = sys_report_conf_result.sls_AccessKey_Secret
        sls_endpoint = sys_report_conf_result.sls_endpoint.replace('https://', '').replace('http://', '')
        sls_project = sys_report_conf_result.sls_project
        sls_logstore = sys_report_conf_result.sls_logstore
        client = LogClient(sls_endpoint, sls_AccessKey_ID, sls_AccessKey_Secret)
        req = GetLogsRequest(project=sls_project, logstore=sls_logstore, fromTime=from_time, toTime=to_time, topic='',
                             query=req_sql)
        res = client.get_logs(req)
        return_result['result'] = True
        return_result['message'] = res.get_body()
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def sls_report_web_att_ip_country_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = DOMAIN_WEB_ATT_IP_COUNTRY_TOP10.format(domain)
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = DOMAIN_WEB_ATT_IP_COUNTRY_TOP10.format(domain)
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = DOMAIN_WEB_ATT_IP_COUNTRY_TOP10.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = WEB_ATT_IP_COUNTRY_TOP10
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = WEB_ATT_IP_COUNTRY_TOP10
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = WEB_ATT_IP_COUNTRY_TOP10
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        to_time = int(time.time())
        sls_AccessKey_ID = sys_report_conf_result.sls_AccessKey_ID
        sls_AccessKey_Secret = sys_report_conf_result.sls_AccessKey_Secret
        sls_endpoint = sys_report_conf_result.sls_endpoint.replace('https://', '').replace('http://', '')
        sls_project = sys_report_conf_result.sls_project
        sls_logstore = sys_report_conf_result.sls_logstore
        client = LogClient(sls_endpoint, sls_AccessKey_ID, sls_AccessKey_Secret)
        req = GetLogsRequest(project=sls_project, logstore=sls_logstore, fromTime=from_time, toTime=to_time, topic='',
                             query=req_sql)
        res = client.get_logs(req)
        return_result['result'] = True
        return_result['message'] = res.get_body()
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)