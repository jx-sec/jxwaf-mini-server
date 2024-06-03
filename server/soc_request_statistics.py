# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *
import traceback


def soc_query_request_statistics(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)
        if sys_conf_result.log_conf_remote == 'false':
            return_result['result'] = False
            return_result['message'] = "remote log is not configured"
            return JsonResponse(return_result, safe=False)
        if sys_conf_result.log_all == 'false':
            return_result['result'] = False
            return_result['message'] = "log_all is not configured"
            return JsonResponse(return_result, safe=False)
        json_data = json.loads(request.body)
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        client = Client(host=sys_conf_result.report_conf_ch_host,
                        port=int(sys_conf_result.report_conf_ch_port),
                        user=sys_conf_result.report_conf_ch_user,
                        password=sys_conf_result.report_conf_ch_password,
                        database=sys_conf_result.report_conf_ch_database,
                        send_receive_timeout=30)
        query_params = {'from_time': from_time, 'to_time': to_time}
        req_sql = """
        SELECT
    COUNT(*) AS total_requests,
    COUNT(DISTINCT SrcIP) AS unique_ips,
    countIf(Status LIKE '2%%' OR Status LIKE '3%%') AS successful_requests,
    countIf(Status LIKE '4%%') AS error_4xx_requests,
    countIf(Status LIKE '5%%') AS error_5xx_requests,
    round(AVG(toFloat64(NULLIF(ProcessTime, ''))), 3) AS avg_request_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(ProcessTime, ''))), 3) AS median_request_time_ms,
    countIf(WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') and WafAction NOT IN ('all_bypass','web_bypass','flow_bypass')) AS attack_attempts,
    COUNT(DISTINCT IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') AND WafAction NOT IN ('all_bypass', 'web_bypass', 'flow_bypass'), SrcIP, NULL)) AS unique_ips_attack,
    countIf(WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') and WafAction NOT IN ('all_bypass','web_bypass','flow_bypass','watch')) AS intercepted_attempts,
    COUNT(DISTINCT IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') AND WafAction NOT IN ('all_bypass', 'web_bypass', 'flow_bypass','watch'), SrcIP, NULL)) AS unique_ips_intercepted,
    countIf(UpstreamAddr != '') AS total_upstream_requests,
    COUNT(DISTINCT IF(UpstreamAddr != '', SrcIP, NULL)) AS upstream_unique_ips,
    countIf(UpstreamStatus LIKE '2%%' OR UpstreamStatus LIKE '3%%') AS successful_upstream_requests,
    countIf(UpstreamStatus LIKE '4%%') AS error_4xx_upstream_requests,
    countIf(UpstreamStatus LIKE '5%%') AS error_5xx_upstream_requests,
    round(AVG(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS avg_upstream_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS median_upstream_time_ms
        FROM jxlog
        WHERE toDateTime64(RequestTime, 0) BETWEEN toDateTime64(%(from_time)s,0) AND toDateTime64(%(to_time)s, 0)     
        """

        stats_results = client.execute(req_sql, query_params)
        stats = stats_results[0] if stats_results else None

        if stats:
            return_result.update({
                'total_requests': stats[0],
                'unique_ips': stats[1],
                'successful_requests': stats[2],
                'error_4xx_requests': stats[3],
                'error_5xx_requests': stats[4],
                'avg_request_time_ms': stats[5],
                'median_request_time_ms': stats[6],
                'attack_attempts': stats[7],
                'unique_ips_attack': stats[8],
                'intercepted_attempts': stats[9],
                'unique_ips_intercepted': stats[10],
                'total_upstream_requests': stats[11],
                'upstream_unique_ips': stats[12],
                'successful_upstream_requests': stats[13],
                'error_4xx_upstream_requests': stats[14],
                'error_5xx_upstream_requests': stats[15],
                'avg_upstream_time_ms': stats[16],
                'median_upstream_time_ms': stats[17]
            })

        else:
            return_result['message'] = "No data found for the given time range"
            return_result['result'] = False
            return JsonResponse(return_result, safe=False)
        result = {}
        result['result'] = True
        result['message'] = return_result
        return JsonResponse(result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)


def soc_query_domain_request_statistics(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)
        if sys_conf_result.log_conf_remote == 'false':
            return_result['result'] = False
            return_result['message'] = "remote log is not configured"
            return JsonResponse(return_result, safe=False)
        if sys_conf_result.log_all == 'false':
            return_result['result'] = False
            return_result['message'] = "log_all is not configured"
            return JsonResponse(return_result, safe=False)
        json_data = json.loads(request.body)
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        domain = json_data['domain']
        client = Client(host=sys_conf_result.report_conf_ch_host,
                        port=int(sys_conf_result.report_conf_ch_port),
                        user=sys_conf_result.report_conf_ch_user,
                        password=sys_conf_result.report_conf_ch_password,
                        database=sys_conf_result.report_conf_ch_database,
                        send_receive_timeout=30)
        query_params = {'from_time': from_time, 'to_time': to_time, 'domain': domain}
        req_sql = """
        SELECT
    COUNT(*) AS total_requests,
    COUNT(DISTINCT SrcIP) AS unique_ips,
    countIf(Status LIKE '2%%' OR Status LIKE '3%%') AS successful_requests,
    countIf(Status LIKE '4%%') AS error_4xx_requests,
    countIf(Status LIKE '5%%') AS error_5xx_requests,
    round(AVG(toFloat64(NULLIF(ProcessTime, ''))), 3) AS avg_request_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(ProcessTime, ''))), 3) AS median_request_time_ms,
    countIf(WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') and WafAction NOT IN ('all_bypass','web_bypass','flow_bypass')) AS attack_attempts,
    COUNT(DISTINCT IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') AND WafAction NOT IN ('all_bypass', 'web_bypass', 'flow_bypass'), SrcIP, NULL)) AS unique_ips_attack,
    countIf(WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') and WafAction NOT IN ('all_bypass','web_bypass','flow_bypass','watch')) AS intercepted_attempts,
    COUNT(DISTINCT IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') AND WafAction NOT IN ('all_bypass', 'web_bypass', 'flow_bypass','watch'), SrcIP, NULL)) AS unique_ips_intercepted,
    countIf(UpstreamAddr != '') AS total_upstream_requests,
    COUNT(DISTINCT IF(UpstreamAddr != '', SrcIP, NULL)) AS upstream_unique_ips,
    countIf(UpstreamStatus LIKE '2%%' OR UpstreamStatus LIKE '3%%') AS successful_upstream_requests,
    countIf(UpstreamStatus LIKE '4%%') AS error_4xx_upstream_requests,
    countIf(UpstreamStatus LIKE '5%%') AS error_5xx_upstream_requests,
    round(AVG(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS avg_upstream_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS median_upstream_time_ms
        FROM jxlog
        WHERE toDateTime64(RequestTime, 0) BETWEEN toDateTime64(%(from_time)s,0) AND toDateTime64(%(to_time)s, 0)  AND Host = %(domain)s   
        """

        stats_results = client.execute(req_sql, query_params)
        stats = stats_results[0] if stats_results else None

        if stats:
            return_result.update({
                'total_requests': stats[0],
                'unique_ips': stats[1],
                'successful_requests': stats[2],
                'error_4xx_requests': stats[3],
                'error_5xx_requests': stats[4],
                'avg_request_time_ms': stats[5],
                'median_request_time_ms': stats[6],
                'attack_attempts': stats[7],
                'unique_ips_attack': stats[8],
                'intercepted_attempts': stats[9],
                'unique_ips_intercepted': stats[10],
                'total_upstream_requests': stats[11],
                'upstream_unique_ips': stats[12],
                'successful_upstream_requests': stats[13],
                'error_4xx_upstream_requests': stats[14],
                'error_5xx_upstream_requests': stats[15],
                'avg_upstream_time_ms': stats[16],
                'median_upstream_time_ms': stats[17]
            })

        else:
            return_result['message'] = "No data found for the given time range"
            return_result['result'] = False
            return JsonResponse(return_result, safe=False)
        result = {}
        result['result'] = True
        result['message'] = return_result
        return JsonResponse(result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)


def soc_query_request_statistics_detail(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)
        if sys_conf_result.log_conf_remote == 'false':
            return_result['result'] = False
            return_result['message'] = "remote log is not configured"
            return JsonResponse(return_result, safe=False)
        if sys_conf_result.log_all == 'false':
            return_result['result'] = False
            return_result['message'] = "log_all is not configured"
            return JsonResponse(return_result, safe=False)
        json_data = json.loads(request.body)
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        client = Client(host=sys_conf_result.report_conf_ch_host,
                        port=int(sys_conf_result.report_conf_ch_port),
                        user=sys_conf_result.report_conf_ch_user,
                        password=sys_conf_result.report_conf_ch_password,
                        database=sys_conf_result.report_conf_ch_database,
                        send_receive_timeout=30)
        query_params = {'from_time': from_time, 'to_time': to_time}
        req_sql = """
      SELECT
          Host,
    UpstreamAddr,
    countIf(UpstreamAddr != '') AS total_upstream_requests,
    COUNT(DISTINCT IF(UpstreamAddr != '', SrcIP, NULL)) AS upstream_unique_ips,
    countIf(UpstreamStatus LIKE '2%%' OR UpstreamStatus LIKE '3%%') AS successful_upstream_requests,
    countIf(UpstreamStatus LIKE '4%%') AS error_4xx_upstream_requests,
    countIf(UpstreamStatus LIKE '5%%') AS error_5xx_upstream_requests,
    round(AVG(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS avg_upstream_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS median_upstream_time_ms,
    ROUND(MAX(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS max_upstream_time_ms,
    ROUND(MIN(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS min_upstream_time_ms
        FROM jxlog  
        WHERE toDateTime64(RequestTime, 0) BETWEEN toDateTime64(%(from_time)s,0) AND toDateTime64(%(to_time)s, 0)   
        GROUP BY Host, UpstreamAddr
        ORDER BY Host, UpstreamAddr
        """
        stats_results = client.execute(req_sql, query_params)
        response_list = [{
            'Host': result[0],
            'UpstreamAddr': result[1],
            'TotalRequests': result[2],
            'UniqueSrcIPs': result[3],
            'SuccessfulRequests': result[4],
            'Error4xxRequests': result[5],
            'Error5xxRequests': result[6],
            'AvgUpstreamTimeMs': result[7],
            'MedianUpstreamTimeMs': result[8],
            'MaxUpstreamTimeMs': result[9],
            'MinUpstreamTimeMs': result[10]
        } for result in stats_results]
        return_result.update({
            'result': True,
            'message': response_list
        })
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)


def soc_query_domain_request_statistics_detail(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)
        if sys_conf_result.log_conf_remote == 'false':
            return_result['result'] = False
            return_result['message'] = "remote log is not configured"
            return JsonResponse(return_result, safe=False)
        if sys_conf_result.log_all == 'false':
            return_result['result'] = False
            return_result['message'] = "log_all is not configured"
            return JsonResponse(return_result, safe=False)
        json_data = json.loads(request.body)
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        domain = json_data['domain']
        client = Client(host=sys_conf_result.report_conf_ch_host,
                        port=int(sys_conf_result.report_conf_ch_port),
                        user=sys_conf_result.report_conf_ch_user,
                        password=sys_conf_result.report_conf_ch_password,
                        database=sys_conf_result.report_conf_ch_database,
                        send_receive_timeout=30)
        query_params = {'from_time': from_time, 'to_time': to_time, 'domain': domain}
        req_sql = """
      SELECT
          Host,
    UpstreamAddr,
    countIf(UpstreamAddr != '') AS total_upstream_requests,
    COUNT(DISTINCT IF(UpstreamAddr != '', SrcIP, NULL)) AS upstream_unique_ips,
    countIf(UpstreamStatus LIKE '2%%' OR UpstreamStatus LIKE '3%%') AS successful_upstream_requests,
    countIf(UpstreamStatus LIKE '4%%') AS error_4xx_upstream_requests,
    countIf(UpstreamStatus LIKE '5%%') AS error_5xx_upstream_requests,
    round(AVG(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS avg_upstream_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS median_upstream_time_ms,
    ROUND(MAX(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS max_upstream_time_ms,
    ROUND(MIN(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS min_upstream_time_ms
        FROM jxlog  
        WHERE toDateTime64(RequestTime, 0) BETWEEN toDateTime64(%(from_time)s,0) AND toDateTime64(%(to_time)s, 0) AND Host = %(domain)s   
        GROUP BY Host, UpstreamAddr
        ORDER BY Host, UpstreamAddr
        """
        stats_results = client.execute(req_sql, query_params)
        response_list = [{
            'Host': result[0],
            'UpstreamAddr': result[1],
            'TotalRequests': result[2],
            'UniqueSrcIPs': result[3],
            'SuccessfulRequests': result[4],
            'Error4xxRequests': result[5],
            'Error5xxRequests': result[6],
            'AvgUpstreamTimeMs': result[7],
            'MedianUpstreamTimeMs': result[8],
            'MaxUpstreamTimeMs': result[9],
            'MinUpstreamTimeMs': result[10]
        } for result in stats_results]
        return_result.update({
            'result': True,
            'message': response_list
        })
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)
