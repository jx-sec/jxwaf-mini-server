# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *
from django.db.models import Q
import traceback


def waf_attack_event_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_range = json_data['time_range']
        page = json_data['page']
        offset = (page - 1) * 20
        count_sql = "SELECT COUNT(DISTINCT SrcIP) FROM jxlog WHERE WafModule <> '' and WafModule <> 'white_name_list' and WafModule <> 'flow_white_rule' and WafModule <> 'web_white_rule' and toDateTime(RequestTime) >= now() - INTERVAL {} DAY"
        raw_sql = "SELECT SrcIP, min(toDateTime(RequestTime)) AS EarliestTime,max(toDateTime(RequestTime)) AS LatestTime, count(*) AS AttackCount,count(distinct concat(Host,URI)) as AttackHostUriCount,arraySort(groupArray(WafPolicy)) as WafPolicyList,COUNT(If(WafAction = 'block')) AS BlockCount,COUNT(DISTINCT If(WafAction = 'block',URI,NULL)) AS BlockUriCount,COUNT(If(WafAction = 'reject_response')) AS RejectResponseCount,COUNT(DISTINCT If(WafAction = 'reject_response',URI,NULL)) AS RejectResponseUriCount,COUNT(If(WafAction = 'bot_check')) AS BotCheckCount,COUNT(DISTINCT If(WafAction = 'bot_check',URI,NULL)) AS BotCHeckUriCount  FROM jxlog WHERE WafModule <> '' and WafModule <> 'white_name_list' and WafModule <> 'flow_white_rule' and WafModule <> 'web_white_rule' and toDateTime(RequestTime) >= now() - INTERVAL {} DAY GROUP BY SrcIP ORDER BY EarliestTime ASC LIMIT 20 OFFSET {};"
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
            src_ip = row[0]
            earliest_time = row[1]
            latest_time = row[2]
            attack_host_uri_count = row[3]
            waf_policy_list = row[4]
            block_count = row[5]
            block_uri_count = row[6]
            reject_response_count = row[7]
            reject_response_uri_count = row[8]
            bot_check_count = row[9]
            bot_check_uri_count = row[10]
            message.append({
                'src_ip': src_ip,
                'earliest_time': earliest_time,
                'latest_time': latest_time,
                'attack_host_uri_count': attack_host_uri_count,
                'waf_policy_list': waf_policy_list,
                'block_count': block_count,
                'block_uri_count': block_uri_count,
                'reject_response_count': reject_response_count,
                'reject_response_uri_count': reject_response_uri_count,
                'bot_check_count': bot_check_count,
                'bot_check_uri_count': bot_check_uri_count
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


def waf_attack_search_event_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_range = json_data['time_range']
        src_ip = json_data['src_ip']
        raw_sql = "SELECT SrcIP, min(toDateTime(RequestTime)) AS EarliestTime,max(toDateTime(RequestTime)) AS LatestTime, count(*) AS AttackCount,count(distinct concat(Host,URI)) as AttackHostUriCount,arraySort(groupArray(WafPolicy)) as WafPolicyList,COUNT(If(WafAction = 'block')) AS BlockCount,COUNT(DISTINCT If(WafAction = 'block',URI,NULL)) AS BlockUriCount,COUNT(If(WafAction = 'reject_response')) AS RejectResponseCount,COUNT(DISTINCT If(WafAction = 'reject_response',URI,NULL)) AS RejectResponseUriCount,COUNT(If(WafAction = 'bot_check')) AS BotCheckCount,COUNT(DISTINCT If(WafAction = 'bot_check',URI,NULL)) AS BotCHeckUriCount  FROM jxlog WHERE WafModule <> '' and WafModule <> 'white_name_list' and WafModule <> 'flow_white_rule' and WafModule <> 'web_white_rule' and toDateTime(RequestTime) >= now() - INTERVAL {} DAY and src_ip = '{}' GROUP BY SrcIP ORDER BY EarliestTime ASC ;"
        if time_range == "1day":
            req_sql = raw_sql.format('1', src_ip)
        elif time_range == "7day":
            req_sql = raw_sql.format('7', src_ip)
        elif time_range == "30day":
            req_sql = raw_sql.format('30', src_ip)
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
            src_ip = row[0]
            earliest_time = row[1]
            latest_time = row[2]
            attack_host_uri_count = row[3]
            waf_policy_list = row[4]
            block_count = row[5]
            block_uri_count = row[6]
            reject_response_count = row[7]
            reject_response_uri_count = row[8]
            bot_check_count = row[9]
            bot_check_uri_count = row[10]
            message.append({
                'src_ip': src_ip,
                'earliest_time': earliest_time,
                'latest_time': latest_time,
                'attack_host_uri_count': attack_host_uri_count,
                'waf_policy_list': waf_policy_list,
                'block_count': block_count,
                'block_uri_count': block_uri_count,
                'reject_response_count': reject_response_count,
                'reject_response_uri_count': reject_response_uri_count,
                'bot_check_count': bot_check_count,
                'bot_check_uri_count': bot_check_uri_count
            })
        return_result['result'] = True
        return_result['message'] = message
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_attack_event_add_black_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        name_list_item = json_data['name_list_item']
        domain = json_data['domain']
        waf_black_name_list_result = waf_black_name_list.objects.get(
            Q(user_id=user_id) & Q(domain=domain) & Q(name_list_name=name_list_name))
        if waf_black_name_list_result.name_list_expire == "false":
            name_list_expire_time = ""
        else:
            name_list_expire_time = int(time.time()) + waf_black_name_list_result.name_list_expire_time
        name_list_item_count = waf_black_name_list_item.objects.filter(user_id=user_id).filter(
            name_list_name=name_list_name).filter(domain=domain).filter(
            name_list_item=name_list_item).count()
        if name_list_item_count == 0:
            waf_black_name_list_item.objects.create(user_id=user_id, domain=domain, name_list_name=name_list_name,
                                                    name_list_item=name_list_item,
                                                    name_list_expire=waf_black_name_list_result.name_list_expire,
                                                    name_list_expire_time=name_list_expire_time)
        return_result['message'] = 'create_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_attack_event_add_white_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name_list_name = json_data['name_list_name']
        name_list_item = json_data['name_list_item']
        domain = json_data['domain']
        waf_white_name_list_result = waf_white_name_list.objects.get(
            Q(user_id=user_id) & Q(domain=domain) & Q(name_list_name=name_list_name))
        if waf_white_name_list_result.name_list_expire == "false":
            name_list_expire_time = ""
        else:
            name_list_expire_time = int(time.time()) + waf_white_name_list_result.name_list_expire_time
        name_list_item_count = waf_white_name_list_item.objects.filter(user_id=user_id).filter(
            name_list_name=name_list_name).filter(domain=domain).filter(
            name_list_item=name_list_item).count()
        if name_list_item_count == 0:
            waf_white_name_list_item.objects.create(user_id=user_id, domain=domain, name_list_name=name_list_name,
                                                    name_list_item=name_list_item,
                                                    name_list_expire_time=name_list_expire_time,
                                                    name_list_expire=waf_white_name_list_result.name_list_expire)
        return_result['message'] = 'create_success'
        return_result['result'] = True
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
