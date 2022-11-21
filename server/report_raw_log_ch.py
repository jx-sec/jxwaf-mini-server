# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *


def ch_report_get_raw_log(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        sql_query_rule = json_data['sql_query_rule']
        start_time = json_data['start_time']
        end_time = json_data['end_time']
        limit_start = json_data['limit_start']
        limit_end = json_data['limit_end']
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        start_sql_query = 'select RequestTime,SrcIP,Method,Host,URI,UserAgent,Status,WafModule,WafPolicy,WafAction,RequestID from jxwaf.jxlog'
        end_sql_query = "RequestTime > '{}' and RequestTime < '{}' limit {},{} ".format(start_time, end_time,
                                                                                        limit_start, limit_end)
        rules = json.loads(sql_query_rule)
        rule_sql_query = ' where '
        for rule in rules:
            type = rule['type']
            action = rule['action']
            value = rule['value']
            if action == 'like':
                rule_sql_query = rule_sql_query + type + " " + action + " '%" + value + "%' and "
            else:
                rule_sql_query = rule_sql_query + type + " " + action + " '" + value + "' and "
        sql_query = start_sql_query + rule_sql_query + end_sql_query
        try:
            result = client.execute(sql_query)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = "sql exec error:" + sql_query
            return_result['exception'] = str(e)
            return_result['errCode'] = 400
            return JsonResponse(return_result, safe=False)
        return_result['result'] = True
        return_result['message'] = result
        return_result['sql_query'] = sql_query
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def ch_report_get_raw_full_log(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        sql_query_rule = json_data['sql_query_rule']
        start_time = json_data['start_time']
        end_time = json_data['end_time']
        limit_start = json_data['limit_start']
        limit_end = json_data['limit_end']
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        start_sql_query = 'select BytesReceived,BytesSent,ConnectionsActive,ConnectionsWaiting,ContentLength,ContentType,Cookie,Host,Method,ProcessTime,QueryString,RawBody,RawHeaders,UserAgent,Accept,AcceptEncoding,Origin,Referer,UpgradeInsecureRequests,AcceptLanguage,RawRespHeadersconnection,RawRespHeaderscontentEncoding,RawRespHeaderscontentType,RawRespHeaderstransferEncoding,RequestID,RequestTime,Scheme,SrcIP,SslCiphers,SslProtocol,Status,UpstreamAddr,UpstreamBytesReceived,UpstreamBytesSent,UpstreamResponseTime,UpstreamStatus,URI,Version,WafAction,WafExtra,WafModule,WafNodeUUID,WafPolicy,XForwardedFor from jxwaf.jxlog'
        end_sql_query = "RequestTime > '{}' and RequestTime < '{}' limit {},{} ".format(start_time, end_time,
                                                                                        limit_start, limit_end)
        rules = json.loads(sql_query_rule)
        rule_sql_query = ' where '
        for rule in rules:
            type = rule['type']
            action = rule['action']
            value = rule['value']
            if action == 'like':
                rule_sql_query = rule_sql_query + type + " " + action + " '%" + value + "%' and "
            else:
                rule_sql_query = rule_sql_query + type + " " + action + " '" + value + "' and "
        sql_query = start_sql_query + rule_sql_query + end_sql_query
        try:
            result = client.execute(sql_query)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = "sql exec error:" + sql_query
            return_result['exception'] = str(e)
            return_result['errCode'] = 400
            return JsonResponse(return_result, safe=False)
        return_result['result'] = True
        return_result['message'] = result
        return_result['sql_query'] = sql_query
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def ch_report_custom_get_raw_log(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        custom_sql_query = json_data['custom_sql_query']
        start_time = json_data['start_time']
        end_time = json_data['end_time']
        limit_start = json_data['limit_start']
        limit_end = json_data['limit_end']
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        start_sql_query = 'select RequestTime,SrcIP,Method,Host,URI,UserAgent,Status,WafModule,WafPolicy,WafAction,RequestID from jxwaf.jxlog where '
        end_sql_query = "and RequestTime > '{}' and RequestTime < '{}' limit {},{} ".format(start_time, end_time,
                                                                                        limit_start, limit_end)
        sql_query = start_sql_query + custom_sql_query + end_sql_query
        try:
            result = client.execute(sql_query)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = "sql exec error:" + sql_query
            return_result['exception'] = str(e)
            return_result['errCode'] = 400
            return JsonResponse(return_result, safe=False)
        return_result['result'] = True
        return_result['message'] = result
        return_result['sql_query'] = sql_query
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def ch_report_custom_get_raw_full_log(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        custom_sql_query = json_data['custom_sql_query']
        start_time = json_data['start_time']
        end_time = json_data['end_time']
        limit_start = json_data['limit_start']
        limit_end = json_data['limit_end']
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        start_sql_query = 'select BytesReceived,BytesSent,ConnectionsActive,ConnectionsWaiting,ContentLength,ContentType,Cookie,Host,Method,ProcessTime,QueryString,RawBody,RawHeaders,UserAgent,Accept,AcceptEncoding,Origin,Referer,UpgradeInsecureRequests,AcceptLanguage,RawRespHeadersconnection,RawRespHeaderscontentEncoding,RawRespHeaderscontentType,RawRespHeaderstransferEncoding,RequestID,RequestTime,Scheme,SrcIP,SslCiphers,SslProtocol,Status,UpstreamAddr,UpstreamBytesReceived,UpstreamBytesSent,UpstreamResponseTime,UpstreamStatus,URI,Version,WafAction,WafExtra,WafModule,WafNodeUUID,WafPolicy,XForwardedFor from jxwaf.jxlog where '
        end_sql_query = "and RequestTime > '{}' and RequestTime < '{}' limit {},{} ".format(start_time, end_time,
                                                                                        limit_start, limit_end)
        sql_query = start_sql_query + custom_sql_query + end_sql_query
        try:
            result = client.execute(sql_query)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = "sql exec error:" + sql_query
            return_result['exception'] = str(e)
            return_result['errCode'] = 400
            return JsonResponse(return_result, safe=False)
        return_result['result'] = True
        return_result['message'] = result
        return_result['sql_query'] = sql_query
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
