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
    countIf(Status LIKE '2%%' OR Status LIKE '3%%') AS successful_requests,
    countIf(Status LIKE '5%%' OR Status LIKE '4%%') AS failed_requests,
    round(AVG(toFloat64(NULLIF(ProcessTime, ''))), 3) AS avg_request_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(ProcessTime, ''))), 3) AS median_request_time_ms,
    countIf(UpstreamStatus != '') AS total_upstream_requests,
    countIf(UpstreamStatus LIKE '2%%' OR UpstreamStatus LIKE '3%%' OR UpstreamStatus LIKE '4%%') AS successful_upstream_requests,
    countIf(UpstreamStatus LIKE '5%%') AS failed_upstream_requests,
    round(AVG(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS avg_upstream_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS median_upstream_time_ms
        FROM jxlog
        WHERE toDateTime64(RequestTime, 0) BETWEEN toDateTime64(%(from_time)s,0) AND toDateTime64(%(to_time)s, 0)  and UpstreamAddr <> ''     
        """

        stats_results = client.execute(req_sql, query_params)
        stats = stats_results[0] if stats_results else None

        if stats:
            return_result.update({
                'total_requests': stats[0],
                'successful_requests': stats[1],
                'failed_requests': stats[2],
                'avg_request_time_ms': stats[3],
                'median_request_time_ms': stats[4],
                'total_upstream_requests': stats[5],
                'successful_upstream_requests': stats[6],
                'failed_upstream_requests': stats[7],
                'avg_upstream_time_ms': stats[8],
                'median_upstream_time_ms': stats[9]
            })
        else:
            return_result['message'] = "No data found for the given time range"
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
    COUNT(*) AS total_requests,
    countIf(Status LIKE '2%%' OR Status LIKE '3%%' ) AS successful_requests,
    countIf(Status LIKE '4%%' OR Status LIKE '5%%') AS failed_requests,
    round(AVG(toFloat64(NULLIF(ProcessTime, ''))), 3) AS avg_request_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(ProcessTime, ''))), 3) AS median_request_time_ms,
    countIf(UpstreamStatus != '') AS total_upstream_requests,
    countIf(UpstreamStatus LIKE '2%%' OR UpstreamStatus LIKE '3%%' OR UpstreamStatus LIKE '4%%') AS successful_upstream_requests,
    countIf(UpstreamStatus LIKE '5%%') AS failed_upstream_requests,
    round(AVG(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS avg_upstream_time_ms,
    round(quantileExact(0.5)(toFloat64(NULLIF(UpstreamResponseTime, ''))), 3) AS median_upstream_time_ms
        FROM jxlog  
        WHERE toDateTime64(RequestTime, 0) BETWEEN toDateTime64(%(from_time)s,0) AND toDateTime64(%(to_time)s, 0)  and UpstreamAddr <> ''     
        GROUP BY Host, UpstreamAddr
        ORDER BY Host, UpstreamAddr
        """
        stats_results = client.execute(req_sql, query_params)
        response_list = [{
            'Host': result[0],
            'UpstreamAddr': result[1],
            'TotalRequests': result[2],
            'SuccessfulRequests': result[3],
            'FailedRequests': result[4],
            'AvgRequestTimeMs': result[5],
            'MedianRequestTimeMs': result[6],
            'TotalUpstreamRequests': result[7],
            'SuccessfulUpstreamRequests': result[8],
            'FailedUpstreamRequests': result[9],
            'AvgUpstreamTimeMs': result[10],
            'MedianUpstreamTimeMs': result[11]
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
