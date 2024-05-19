# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *
from django.db.models import Q
import traceback


def waf_log_query_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_range = json_data['time_range']
        page = json_data['page']
        offset = (page - 1) * 20
        count_sql = "SELECT COUNT(*) FROM jxlog WHERE  toDateTime(RequestTime) >= now() - INTERVAL {} DAY"
        raw_sql = "SELECT RequestTime,SrcIP,Host,URI,WafPolicy,Status,RequestUuid  FROM jxlog WHERE  toDateTime(RequestTime) >= now() - INTERVAL {} DAY ORDER BY RequestTime ASC LIMIT 20 OFFSET {};"
        if time_range == "1day":
            req_sql = raw_sql.format('1', offset)
            count_sql = count_sql.format('1')
        elif time_range == "7day":
            req_sql = raw_sql.format('7', offset)
            count_sql = count_sql.format('7')
        elif time_range == "30day":
            req_sql = raw_sql.format('30', offset)
            count_sql = count_sql.format('30')
        else:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        client = Client(host=sys_conf_result.report_conf_ch_host, port=int(sys_conf_result.report_conf_ch_port),
                        user=sys_conf_result.report_conf_ch_user,
                        password=sys_conf_result.report_conf_ch_password,
                        database=sys_conf_result.report_conf_ch_database,
                        send_receive_timeout=30)
        results = client.execute(req_sql)
        message = []
        for row in results:
            request_time = row[0]
            src_ip = row[1]
            host = row[2]
            uri = row[3]
            waf_policy = row[4]
            status = row[5]
            request_uuid = row[6]
            message.append({
                'request_time': request_time,
                'src_ip': src_ip,
                'host': host,
                'uri': uri,
                'waf_policy': waf_policy,
                'status': status,
                'request_uuid': request_uuid
            })
        count_sql_result = client.execute(count_sql)
        total_records = count_sql_result[0][0]
        total_pages = (total_records + 20 - 1) // 20
        return_result['result'] = True
        return_result['message'] = message
        return_result['total_records'] = total_records
        return_result['total_pages'] = total_pages
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_log_query_search_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_range = json_data['time_range']
        search_type = json_data['search_type']
        search_value = json_data['search_value']
        if search_type == 'src_ip':
            raw_sql = "SELECT RequestTime,SrcIP,Host,URI,WafPolicy,Status,RequestUuid  FROM jxlog WHERE  toDateTime(RequestTime) >= now() - INTERVAL {} DAY and SrcIP = '{}' ORDER BY RequestTime ASC LIMIT 20 OFFSET {};"
        elif search_type == 'host':
            raw_sql = "SELECT RequestTime,SrcIP,Host,URI,WafPolicy,Status,RequestUuid  FROM jxlog WHERE  toDateTime(RequestTime) >= now() - INTERVAL {} DAY and Host = '{}' ORDER BY RequestTime ASC LIMIT 20 OFFSET {};"
        elif search_type == 'uri':
            raw_sql = "SELECT RequestTime,SrcIP,Host,URI,WafPolicy,Status,RequestUuid  FROM jxlog WHERE  toDateTime(RequestTime) >= now() - INTERVAL {} DAY and URI = '{}' ORDER BY RequestTime ASC LIMIT 20 OFFSET {};"
        elif search_type == 'request_uuid':
            raw_sql = "SELECT RequestTime,SrcIP,Host,URI,WafPolicy,Status,RequestUuid  FROM jxlog WHERE  toDateTime(RequestTime) >= now() - INTERVAL {} DAY and RequestUuid = '{}' ORDER BY RequestTime ASC LIMIT 20 OFFSET {};"
        else:
            return_result['result'] = False
            return_result['message'] = "search_type error"
            return JsonResponse(return_result, safe=False)
        if time_range == "1day":
            req_sql = raw_sql.format('1', search_value)
        elif time_range == "7day":
            req_sql = raw_sql.format('7', search_value)
        elif time_range == "30day":
            req_sql = raw_sql.format('30', search_value)
        else:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        client = Client(host=sys_conf_result.report_conf_ch_host, port=int(sys_conf_result.report_conf_ch_port),
                        user=sys_conf_result.report_conf_ch_user,
                        password=sys_conf_result.report_conf_ch_password,
                        database=sys_conf_result.report_conf_ch_database,
                        send_receive_timeout=30)
        results = client.execute(req_sql)
        message = []
        for row in results:
            request_time = row[0]
            src_ip = row[1]
            host = row[2]
            uri = row[3]
            waf_policy = row[4]
            status = row[5]
            request_uuid = row[6]
            message.append({
                'request_time': request_time,
                'src_ip': src_ip,
                'host': host,
                'uri': uri,
                'waf_policy': waf_policy,
                'status': status,
                'request_uuid': request_uuid
            })
        return_result['result'] = True
        return_result['message'] = message
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_log_query_get_detail(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        request_uuid = json_data['request_uuid']
        req_sql = "SELECT *  FROM jxlog WHERE  RequestUuid = '{}' ;"
        req_sql = req_sql.format(request_uuid)
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        client = Client(host=sys_conf_result.report_conf_ch_host, port=int(sys_conf_result.report_conf_ch_port),
                        user=sys_conf_result.report_conf_ch_user,
                        password=sys_conf_result.report_conf_ch_password,
                        database=sys_conf_result.report_conf_ch_database,
                        send_receive_timeout=30)
        results = client.execute(req_sql)
        message = results[0]
        return_result['result'] = True
        return_result['message'] = message
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
