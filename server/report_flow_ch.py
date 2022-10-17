# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *

WEB_REQUEST_COUNT_TREND_7D = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 1  DAY) as chunk_time,count(*) as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(day,7,now())  group by chunk_time order by  chunk_time"

WEB_REQUEST_COUNT_TREND_24H = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 1  Hour) as chunk_time,count(*) as count from jxlog where (WafModule = 'flow_engine_protection' or  WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now())  group by chunk_time order by  chunk_time"

WEB_REQUEST_COUNT_TREND_1H = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 5  Minute) as chunk_time,count(*) as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now())  group by chunk_time order by  chunk_time"

DOMAIN_WEB_REQUEST_COUNT_TREND_7D = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 1  DAY) as chunk_time,count(*) as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(day,7,now())  group by chunk_time order by  chunk_time"

DOMAIN_WEB_REQUEST_COUNT_TREND_24H = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 1  Hour) as chunk_time,count(*) as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now())  group by chunk_time order by  chunk_time"

DOMAIN_WEB_REQUEST_COUNT_TREND_1H = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 5  Minute) as chunk_time,count(*) as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now())  group by chunk_time order by  chunk_time"

WEB_IP_COUNT_TREND_7D = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 1  DAY) as chunk_time,count(DISTINCT  SrcIP) as count from jxlog  where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(day,7,now())  group by chunk_time        order by  chunk_time"

WEB_IP_COUNT_TREND_24H = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 1  Hour) as chunk_time,count(DISTINCT  SrcIP) as count from jxlog  where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now())  group by chunk_time        order by  chunk_time"

WEB_IP_COUNT_TREND_1H = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 5  Minute) as chunk_time,count(DISTINCT  SrcIP) as count from jxlog  where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now())  group by chunk_time        order by  chunk_time  "

DOMAIN_WEB_IP_COUNT_TREND_7D = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 1  DAY) as chunk_time,count(DISTINCT  SrcIP) as count from jxlog  where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(day,7,now())  group by chunk_time        order by  chunk_time"

DOMAIN_WEB_IP_COUNT_TREND_24H = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 1  Hour) as chunk_time,count(DISTINCT  SrcIP) as count from jxlog  where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now())  group by chunk_time        order by  chunk_time"

DOMAIN_WEB_IP_COUNT_TREND_1H = "select toStartOfInterval(toDateTime(RequestTime), INTERVAL 5  Minute) as chunk_time,count(DISTINCT  SrcIP) as count from jxlog  where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now())  group by chunk_time        order by  chunk_time  "

WEB_REQUEST_COUNT_TOTLE_7D = "select count()  as count from jxlog where  (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) "

WEB_REQUEST_COUNT_TOTLE_24H = "select count()  as count from jxlog where  (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now()) "

WEB_REQUEST_COUNT_TOTLE_1H = "select count()  as count from jxlog where  (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and  toDateTime(RequestTime) >= timestamp_sub(Hour,1,now())"

DOMAIN_WEB_REQUEST_COUNT_TOTLE_7D = "select count()  as count from jxlog where  Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) "
DOMAIN_WEB_REQUEST_COUNT_TOTLE_24H = "select count()  as count from jxlog where  Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now()) "
DOMAIN_WEB_REQUEST_COUNT_TOTLE_1H = "select count()  as count from jxlog where  Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and  toDateTime(RequestTime) >= timestamp_sub(Hour,1,now())"

WEB_REQUEST_IP_TOTLE_7D = "select count(DISTINCT  SrcIP)  as count from jxlog where  (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) "

WEB_REQUEST_IP_TOTLE_24H = "select count(DISTINCT  SrcIP)  as count from jxlog where  (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now()) "

WEB_REQUEST_IP_TOTLE_1H = "select count(DISTINCT  SrcIP)  as count from jxlog where  (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now())"

DOMAIN_WEB_REQUEST_IP_TOTLE_7D = "select count(DISTINCT  SrcIP)  as count from jxlog where  Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) "
DOMAIN_WEB_REQUEST_IP_TOTLE_24H = "select count(DISTINCT  SrcIP)  as count from jxlog where  Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now()) "
DOMAIN_WEB_REQUEST_IP_TOTLE_1H = "select count(DISTINCT  SrcIP)  as count from jxlog where  Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now())"

WEB_ATT_TYPE_TOP10_7D = "select WafPolicy,count() as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) group by WafPolicy order by count desc limit 10"
WEB_ATT_TYPE_TOP10_24H = "select WafPolicy,count() as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now())  group by WafPolicy order by count desc limit 10"
WEB_ATT_TYPE_TOP10_1H = "select WafPolicy,count() as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection') and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now()) group by WafPolicy order by count desc limit 10"

DOMAIN_WEB_ATT_TYPE_TOP10_7D = "select WafPolicy,count() as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) group by WafPolicy order by count desc limit 10"
DOMAIN_WEB_ATT_TYPE_TOP10_24H = "select WafPolicy,count() as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now()) group by WafPolicy order by count desc limit 10"
DOMAIN_WEB_ATT_TYPE_TOP10_1H = "select WafPolicy,count() as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')   and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now()) group by WafPolicy order by count desc limit 10"

WEB_ATT_IP_TOP10_7D = "select SrcIP,count() as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) group by SrcIP order by count desc limit 10"
WEB_ATT_IP_TOP10_24H = "select SrcIP,count() as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now())  group by SrcIP order by count desc limit 10"
WEB_ATT_IP_TOP10_1H = "select SrcIP,count() as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now()) group by SrcIP order by count desc limit 10"

DOMAIN_WEB_ATT_IP_TOP10_7D = "select SrcIP,count() as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) group by SrcIP order by count desc limit 10"
DOMAIN_WEB_ATT_IP_TOP10_24H = "select SrcIP,count() as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now()) group by SrcIP order by count desc limit 10"
DOMAIN_WEB_ATT_IP_TOP10_1H = "select SrcIP,count() as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')   and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now()) group by SrcIP order by count desc limit 10"

WEB_ATT_URI_TOP10_7D = "select URI,count() as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) group by URI order by count desc limit 10"
WEB_ATT_URI_TOP10_24H = "select URI,count() as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now())  group by URI order by count desc limit 10"
WEB_ATT_URI_TOP10_1H = "select URI,count() as count from jxlog where (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now()) group by URI order by count desc limit 10"

DOMAIN_WEB_ATT_URI_TOP10_7D = "select URI,count() as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(day,7,now()) group by URI order by count desc limit 10"
DOMAIN_WEB_ATT_URI_TOP10_24H = "select URI,count() as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')  and toDateTime(RequestTime) >= timestamp_sub(Hour,24,now()) group by URI order by count desc limit 10"
DOMAIN_WEB_ATT_URI_TOP10_1H = "select URI,count() as count from jxlog where Host = '{}' and (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection')   and toDateTime(RequestTime) >= timestamp_sub(Hour,1,now()) group by URI order by count desc limit 10"


# WEB_ATT_IP_COUNTRY_TOP10 = '* and (waf_module: flow_rule_protection or waf_module: flow_engine_protection)  | select ip_to_country(src_ip) as country,count(*) as count group by country order by count desc limit 10'
# DOMAIN_WEB_ATT_IP_COUNTRY_TOP10 = '* and host: \"{}\" and (waf_module: flow_rule_protection or waf_module: flow_engine_protection)  | select ip_to_country(src_ip) as country,count(*) as count group by country order by count desc limit 10'


def ch_report_flow_request_count_trend(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TREND_7D.format(domain)
            elif time_zone == "24hour":
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TREND_24H.format(domain)
            elif time_zone == "1hour":
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TREND_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                req_sql = WEB_REQUEST_COUNT_TREND_7D
            elif time_zone == "24hour":
                req_sql = WEB_REQUEST_COUNT_TREND_24H
            elif time_zone == "1hour":
                req_sql = WEB_REQUEST_COUNT_TREND_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        result = client.execute(req_sql)

        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def ch_report_flow_ip_count_trend(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                req_sql = DOMAIN_WEB_IP_COUNT_TREND_7D.format(domain)
            elif time_zone == "24hour":
                req_sql = DOMAIN_WEB_IP_COUNT_TREND_24H.format(domain)
            elif time_zone == "1hour":
                req_sql = DOMAIN_WEB_IP_COUNT_TREND_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                req_sql = WEB_IP_COUNT_TREND_7D
            elif time_zone == "24hour":
                req_sql = WEB_IP_COUNT_TREND_24H
            elif time_zone == "1hour":
                req_sql = WEB_IP_COUNT_TREND_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        result = client.execute(req_sql)

        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def ch_report_flow_request_count_totle(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TOTLE_7D.format(domain)
            elif time_zone == "24hour":
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TOTLE_24H.format(domain)
            elif time_zone == "1hour":
                req_sql = DOMAIN_WEB_REQUEST_COUNT_TOTLE_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                req_sql = WEB_REQUEST_COUNT_TOTLE_7D
            elif time_zone == "24hour":
                req_sql = WEB_REQUEST_COUNT_TOTLE_24H
            elif time_zone == "1hour":
                req_sql = WEB_REQUEST_COUNT_TOTLE_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def ch_report_flow_request_ip_totle(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                req_sql = DOMAIN_WEB_REQUEST_IP_TOTLE_7D.format(domain)
            elif time_zone == "24hour":
                req_sql = DOMAIN_WEB_REQUEST_IP_TOTLE_24H.format(domain)
            elif time_zone == "1hour":
                req_sql = DOMAIN_WEB_REQUEST_IP_TOTLE_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                req_sql = WEB_REQUEST_IP_TOTLE_7D
            elif time_zone == "24hour":
                req_sql = WEB_REQUEST_IP_TOTLE_24H
            elif time_zone == "1hour":
                req_sql = WEB_REQUEST_IP_TOTLE_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def ch_report_flow_att_type_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                req_sql = DOMAIN_WEB_ATT_TYPE_TOP10_7D.format(domain)
            elif time_zone == "24hour":
                req_sql = DOMAIN_WEB_ATT_TYPE_TOP10_24H.format(domain)
            elif time_zone == "1hour":
                req_sql = DOMAIN_WEB_ATT_TYPE_TOP10_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                req_sql = WEB_ATT_TYPE_TOP10_7D
            elif time_zone == "24hour":
                req_sql = WEB_ATT_TYPE_TOP10_24H
            elif time_zone == "1hour":
                req_sql = WEB_ATT_TYPE_TOP10_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def ch_report_flow_att_ip_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = DOMAIN_WEB_ATT_IP_TOP10_7D.format(domain)
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = DOMAIN_WEB_ATT_IP_TOP10_24H.format(domain)
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = DOMAIN_WEB_ATT_IP_TOP10_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                from_time = int(time.time() - 604800)
                req_sql = WEB_ATT_IP_TOP10_7D
            elif time_zone == "24hour":
                from_time = int(time.time() - 86400)
                req_sql = WEB_ATT_IP_TOP10_24H
            elif time_zone == "1hour":
                from_time = int(time.time() - 3600)
                req_sql = WEB_ATT_IP_TOP10_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def ch_report_flow_att_uri_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                req_sql = DOMAIN_WEB_ATT_URI_TOP10_7D.format(domain)
            elif time_zone == "24hour":
                req_sql = DOMAIN_WEB_ATT_URI_TOP10_24H.format(domain)
            elif time_zone == "1hour":
                req_sql = DOMAIN_WEB_ATT_URI_TOP10_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                req_sql = WEB_ATT_URI_TOP10_7D
            elif time_zone == "24hour":
                req_sql = WEB_ATT_URI_TOP10_24H
            elif time_zone == "1hour":
                req_sql = WEB_ATT_URI_TOP10_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)



def ch_report_flow_att_ip_country_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        try:
            domain = json_data['domain']
            if time_zone == "7day":
                req_sql = DOMAIN_WEB_ATT_URI_TOP10_7D.format(domain)
            elif time_zone == "24hour":
                req_sql = DOMAIN_WEB_ATT_URI_TOP10_24H.format(domain)
            elif time_zone == "1hour":
                req_sql = DOMAIN_WEB_ATT_URI_TOP10_1H.format(domain)
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        except:
            if time_zone == "7day":
                req_sql = WEB_ATT_URI_TOP10_7D
            elif time_zone == "24hour":
                req_sql = WEB_ATT_URI_TOP10_24H
            elif time_zone == "1hour":
                req_sql = WEB_ATT_URI_TOP10_1H
            else:
                return_result['result'] = False
                return_result['message'] = "time_zone error"
                return JsonResponse(return_result, safe=False)
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
