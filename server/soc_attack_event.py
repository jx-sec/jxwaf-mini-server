# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *
import traceback
from datetime import datetime, timedelta


def soc_attack_event_get_list(request):
    return_result = {}
    try:
        user_id = request.session.get('user_id')
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        page_number = int(json_data.get('page_number', 1))
        page_size = int(json_data.get('page_size', 20))  # 允许请求指定每页大小
        offset = (page_number - 1) * page_size

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        total_count_query = """
            SELECT
                COUNT(DISTINCT SrcIP)
            FROM
                jxlog
            WHERE
                toDateTime(RequestTime) BETWEEN toDateTime(%(from_time)s) AND toDateTime(%(to_time)s)
                AND WafModule NOT IN ('web_white_rule', 'flow_white_rule', '')
        """
        total_count_result = client.execute(total_count_query, {'from_time': from_time, 'to_time': to_time})
        total_count = total_count_result[0][0]
        total_pages = (total_count + page_size - 1) // page_size

        req_sql = """
            SELECT
                SrcIP AS AttackIP,
                COUNT(*) AS AttackCount,  
                COUNT(CASE WHEN WafAction IN ('block', 'reject_response', 'bot_check') THEN 1 END) AS BlockCount,
                COUNT(DISTINCT CONCAT(Host,URI)) AS UniqueAttackInterfaces,  
                COUNT(DISTINCT CASE WHEN WafAction IN ('block', 'reject_response', 'bot_check') THEN URI END) AS UniqueBlockedInterfaces,
                MIN(RequestTime) AS StartTime,  
                MAX(RequestTime) AS LatestTime,
                groupArray(distinct WafPolicy) AS AttackTypes
            FROM
                jxlog
            WHERE
                toDateTime(RequestTime) BETWEEN toDateTime(%(from_time)s) AND toDateTime(%(to_time)s)
                AND WafModule NOT IN ('web_white_rule', 'flow_white_rule', '')
            GROUP BY
                SrcIP
            ORDER BY
                LatestTime DESC
            LIMIT %(page_size)s OFFSET %(offset)s
        """

        query_params = {
            'from_time': from_time,
            'to_time': to_time,
            'page_size': page_size,
            'offset': offset
        }

        result = client.execute(req_sql, query_params)

        return_result['result'] = True
        return_result['data'] = [dict(
            zip(['AttackIP', 'AttackCount', 'BlockCount', 'UniqueAttackInterfaces',
                 'UniqueBlockedInterfaces', 'StartTime', 'LatestTime', 'AttackTypes'],
                row[:-1] + ([atype for atype in row[-1] if atype != ''],)
                ))
            for row in result
        ]
        return_result['total_count'] = total_count
        return_result['total_pages'] = total_pages
        return_result['now_page'] = page_number

        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)


def soc_attack_event_get_behave_track(request):
    return_result = {}
    try:
        user_id = request.session.get('user_id')
        sys_conf_result = sys_conf.objects.get(user_id=user_id)

        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        attack_ip = json_data['attack_ip']
        from_time = json_data['from_time']
        to_time = json_data['to_time']

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        req_sql = """
        SELECT
            MIN(CASE WHEN WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') THEN toDateTime(RequestTime) END) AS StartAttackTime,
            MAX(CASE WHEN WafModule NOT IN ('web_white_rule', 'flow_white_rule', '') THEN toDateTime(RequestTime) END) AS LatestAttackTime,
            CONCAT(Host, URI) AS URL,
            groupArray(distinct IF(WafPolicy != '', WafPolicy, NULL)) AS AttackTypes, 
            COUNT(*) AS AttackCount,
            COUNT(CASE WHEN WafAction IN ('block', 'reject_response', 'bot_check') THEN 1 END) AS BlockCount,
            Host AS Host,
            URI AS URI
        FROM
            jxlog
        WHERE
            SrcIP = %(attack_ip)s AND
            toDateTime(RequestTime) >= toDateTime(%(from_time)s) AND
            toDateTime(RequestTime) <= toDateTime(%(to_time)s)       
            AND WafModule NOT IN ('web_white_rule', 'flow_white_rule', '')
        GROUP BY
            Host,URI
        ORDER BY
            StartAttackTime 
        """

        query_params = {
            'attack_ip': attack_ip,
            'from_time': from_time,
            'to_time': to_time
        }

        rows = client.execute(req_sql, query_params)
        data = [{
            'StartAttackTime': row[0].strftime('%Y-%m-%d %H:%M:%S') if row[1] else None,
            'LatestAttackTime': row[1].strftime('%Y-%m-%d %H:%M:%S') if row[2] else None,
            'URL': row[2],
            'AttackTypes': row[3],
            'AttackCount': row[4],
            'BlockCount': row[5],
            'Host': row[6],
            'URI': row[7]
        } for row in rows]

        return_result['result'] = True
        return_result['data'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)


def soc_attack_event_get_all_log_list(request):
    return_result = {}
    try:
        user_id = request.session.get('user_id')
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        page_number = int(json_data.get('page_number', 1))
        page_size = int(json_data.get('page_size', 20))  # 允许请求指定每页大小
        offset = (page_number - 1) * page_size

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        total_count_query = """
            SELECT
                COUNT(DISTINCT SrcIP)
            FROM
                jxlog
            WHERE
                toDateTime(RequestTime) BETWEEN toDateTime(%(from_time)s) AND toDateTime(%(to_time)s)
                AND WafModule NOT IN ('web_white_rule', 'flow_white_rule', '')
        """
        total_count_result = client.execute(total_count_query, {'from_time': from_time, 'to_time': to_time})
        total_count = total_count_result[0][0]
        total_pages = (total_count + page_size - 1) // page_size

        req_sql = """
            SELECT
                jxlog.SrcIP AS AttackIP,
                COUNT(*) AS TotalRequests,
                SUM(IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', ''), 1, 0)) AS AttackCount,  
                SUM(IF(WafAction IN ('block', 'reject_response', 'bot_check'), 1, 0)) AS BlockCount,  
                COUNT(DISTINCT IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', ''), URI, NULL)) AS UniqueAttackInterfaces,
                COUNT(DISTINCT IF(WafAction IN ('block', 'reject_response', 'bot_check'), URI, NULL)) AS UniqueBlockedInterfaces,
                MIN(RequestTime) AS FirstRequestTime, 
                MIN(IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', ''), RequestTime, NULL)) AS FirstAttackTime,
                MAX(IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', ''), RequestTime, NULL)) AS LatestAttackTime,
                groupArray(distinct WafPolicy) AS AttackTypes
            FROM
                jxlog
            WHERE
                SrcIP IN (
                    SELECT DISTINCT SrcIP
                    FROM jxlog
                    WHERE toDateTime(RequestTime) BETWEEN toDateTime(%(from_time)s) AND toDateTime(%(to_time)s)
                      AND WafModule NOT IN ('web_white_rule', 'flow_white_rule', '')
                )
                AND toDateTime(RequestTime) BETWEEN toDateTime(%(from_time)s) AND toDateTime(%(to_time)s)
            GROUP BY
                jxlog.SrcIP
            ORDER BY
                LatestAttackTime DESC
            LIMIT %(page_size)s OFFSET %(offset)s
        """
        query_params = {
            'from_time': from_time,
            'to_time': to_time,
            'page_size': page_size,
            'offset': offset
        }

        result = client.execute(req_sql, query_params)

        return_result['result'] = True
        return_result['data'] = [dict(
            zip(['AttackIP', 'TotalRequests', 'AttackCount', 'BlockCount', 'UniqueAttackInterfaces',
                 'UniqueBlockedInterfaces',
                 'FirstRequestTime', 'FirstAttackTime', 'LatestAttackTime', 'AttackTypes'],
                row[:9] + ([atype for atype in row[9] if atype != ''],)
                ))
            for row in result]
        return_result['total_count'] = total_count
        return_result['total_pages'] = total_pages
        return_result['now_page'] = page_number

        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)


def soc_attack_event_get_all_log_behave_track(request):
    return_result = {}
    try:
        user_id = request.session.get('user_id')
        sys_conf_result = sys_conf.objects.get(user_id=user_id)

        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        attack_ip = json_data['attack_ip']
        from_time = json_data['from_time']
        to_time = json_data['to_time']

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        req_sql = """
        SELECT
            MIN(toDateTime(RequestTime)) AS FirstRequestTime,
            MIN(IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', ''), toDateTime(RequestTime), NULL)) AS StartAttackTime,
            MAX(IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', ''), toDateTime(RequestTime), NULL)) AS LatestAttackTime,
            CONCAT(Host, URI) AS URL,
            groupArray(distinct IF(WafPolicy != '', WafPolicy, NULL)) AS AttackTypes, 
            SUM(IF(WafModule NOT IN ('web_white_rule', 'flow_white_rule', ''), 1, 0)) AS AttackCount,
            SUM(IF(WafAction IN ('block', 'reject_response', 'bot_check'), 1, 0)) AS BlockCount,
            COUNT(*) AS TotalRequestCount,
            Host AS Host,
            URI AS URI
        FROM
            jxlog
        WHERE
            SrcIP = %(attack_ip)s AND
            toDateTime(RequestTime) >= toDateTime(%(from_time)s) AND
            toDateTime(RequestTime) <= toDateTime(%(to_time)s)
        GROUP BY
            Host, URI
        HAVING
            AttackCount > 0  -- 只显示有攻击的接口
        ORDER BY
            FirstRequestTime 
        """

        query_params = {
            'attack_ip': attack_ip,
            'from_time': from_time,
            'to_time': to_time
        }

        rows = client.execute(req_sql, query_params)
        data = [{
            'FirstRequestTime': row[0].strftime('%Y-%m-%d %H:%M:%S'),
            'StartAttackTime': row[1].strftime('%Y-%m-%d %H:%M:%S') if row[1] is not None else None,
            'LatestAttackTime': row[2].strftime('%Y-%m-%d %H:%M:%S') if row[2] is not None else None,
            'URL': row[3],
            'AttackTypes': row[4],
            'AttackCount': row[5],
            'BlockCount': row[6],
            'TotalRequestCount': row[7],
            'Host': row[8],
            'URI': row[9]
        } for row in rows]

        return_result['result'] = True
        return_result['data'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)
