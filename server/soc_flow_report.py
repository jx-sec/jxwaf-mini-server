# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *
import traceback
from datetime import datetime, timedelta


def soc_flow_report_attack_count_total(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT COUNT(*)
            FROM jxlog  
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter}
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        result = client.execute(req_sql)
        web_attack_count = result[0][0] if result else 0

        return_result['result'] = True
        return_result['attack_count'] = web_attack_count
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_api_count_total(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT COUNT(DISTINCT concat(Host, URI))
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter}
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        result = client.execute(req_sql)
        web_attack_count = result[0][0] if result else 0

        return_result['result'] = True
        return_result['attack_count'] = web_attack_count
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_ip_count_total(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT COUNT(DISTINCT SrcIP)
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter}
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        result = client.execute(req_sql)
        web_attack_count = result[0][0] if result else 0

        return_result['result'] = True
        return_result['attack_count'] = web_attack_count
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_isocode_count_total(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT COUNT(DISTINCT IsoCode)
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter}
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        result = client.execute(req_sql)
        web_attack_count = result[0][0] if result else 0

        return_result['result'] = True
        return_result['attack_count'] = web_attack_count
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_city_count_total(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT COUNT(DISTINCT City)
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter}
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        result = client.execute(req_sql)
        web_attack_count = result[0][0] if result else 0

        return_result['result'] = True
        return_result['attack_count'] = web_attack_count
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_geoip(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT    
            IsoCode,
            COUNT(*) AS attack_count
            FROM jxlog
            WHERE  IsoCode !='' AND (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter} GROUP BY  IsoCode ORDER BY attack_count DESC
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        result = client.execute(req_sql)
        attack_locations = []
        for iso_code, attack_count in result:
            attack_locations.append({
                'iso_code': iso_code,
                'attack_count': attack_count

            })
        return_result['result'] = True
        return_result['message'] = attack_locations
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_city_geoip(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT    
            City,
            COUNT(*) AS attack_count
            FROM jxlog
            WHERE  City !='' AND (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter} GROUP BY  City ORDER BY attack_count DESC
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        result = client.execute(req_sql)
        attack_locations = []
        for City, attack_count in result:
            attack_locations.append({
                'City': City,
                'attack_count': attack_count

            })
        return_result['result'] = True
        return_result['message'] = attack_locations
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_count_trend(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)

        group_by_time_func = {
            '30day': 'toStartOfDay',
            '7day': 'toStartOfDay',
            '24hour': 'toStartOfHour',
            '1hour': 'toStartOfMinute',  # 注意: 如果数据量很大，慎用toStartOfMinute
        }
        group_by_func = group_by_time_func.get(time_zone, 'toStartOfDay')

        req_sql = """
            SELECT
                {group_by_func}(toDateTime(RequestTime)) AS TimeSlot,
                COUNT(*) AS AttackCount
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
                {domain_filter}
                {time_filter}
            GROUP BY TimeSlot
            ORDER BY TimeSlot
        """.format(
            group_by_func=group_by_func,
            domain_filter=domain_filter,
            time_filter=time_filter
        )

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )

        result = client.execute(req_sql)

        trend_data = [{'time_slot': str(row[0]), 'attack_count': row[1]} for row in result]
        return_result['result'] = True
        return_result['attack_trend'] = trend_data
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_api_top(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT 
            concat(Host, URI) AS api,
            COUNT(*) AS AttackCount
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter} GROUP BY api  ORDER BY AttackCount DESC LIMIT 5
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )
        result = client.execute(req_sql)
        top_apis = [{"api": row[0], "attack_count": row[1]} for row in result]

        return_result['result'] = True
        return_result['result'] = top_apis
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_type_top(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT 
            WafPolicy,
            COUNT(*) AS attack_count
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter} GROUP BY WafPolicy  ORDER BY attack_count DESC LIMIT 5
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )
        result = client.execute(req_sql)
        top_apis = [{"WafPolicy": row[0], "attack_count": row[1]} for row in result]

        return_result['result'] = True
        return_result['result'] = top_apis
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_ip_top(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT 
            SrcIP,
            COUNT(*) AS attack_count
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter} GROUP BY SrcIP  ORDER BY attack_count DESC LIMIT 5
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )
        result = client.execute(req_sql)
        top_apis = [{"SrcIP": row[0], "attack_count": row[1]} for row in result]

        return_result['result'] = True
        return_result['result'] = top_apis
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_isocode_top(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT 
            IsoCode,
            COUNT(*) AS attack_count
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter} GROUP BY IsoCode  ORDER BY attack_count DESC LIMIT 5
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )
        result = client.execute(req_sql)
        top_apis = [{"IsoCode": row[0], "attack_count": row[1]} for row in result]

        return_result['result'] = True
        return_result['result'] = top_apis
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def soc_flow_report_attack_city_top(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        current_time = datetime.now()

        time_ranges = {
            '30day': current_time - timedelta(days=30),
            '7day': current_time - timedelta(days=7),
            '24hour': current_time - timedelta(hours=24),
            '1hour': current_time - timedelta(hours=1),
        }

        if time_zone not in time_ranges:
            return_result['result'] = False
            return_result['message'] = "time_zone error"
            return JsonResponse(return_result, safe=False)

        start_time = time_ranges[time_zone].strftime('%Y-%m-%d %H:%M:%S')
        domain_filter = ""
        try:
            domain = json_data['domain']
            domain_filter = "AND Host = '{}'".format(domain)
        except KeyError:
            pass
        time_filter = "AND toDateTime(RequestTime) >= toDateTime('{}')".format(start_time)
        req_sql = """
            SELECT 
            City,
            COUNT(*) AS attack_count
            FROM jxlog
            WHERE (WafModule = 'flow_engine_protection' or WafModule = 'flow_rule_protection' or WafModule = 'flow_ip_region_block')
            {domain_filter}
            {time_filter} GROUP BY City  ORDER BY attack_count DESC LIMIT 5
        """.format(domain_filter=domain_filter, time_filter=time_filter)

        client = Client(
            host=sys_conf_result.report_conf_ch_host,
            port=int(sys_conf_result.report_conf_ch_port),
            user=sys_conf_result.report_conf_ch_user,
            password=sys_conf_result.report_conf_ch_password,
            database=sys_conf_result.report_conf_ch_database,
            send_receive_timeout=30
        )
        result = client.execute(req_sql)
        top_apis = [{"City": row[0], "attack_count": row[1]} for row in result]

        return_result['result'] = True
        return_result['result'] = top_apis
        return JsonResponse(return_result, safe=False)

    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
