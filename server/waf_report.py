# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *




def waf_report_web_attack_count(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select count(*) as count from jxlog where (WafModule = 'web_rule_protection' or WafModule = 'web_engine_protection') and toDateTime(RequestTime) >= now() - INTERVAL {} DAY "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_web_attack_ip_count(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select count(distinct SrcIP) as count from jxlog where (WafModule = 'web_rule_protection' or WafModule = 'web_engine_protection') and toDateTime(RequestTime) >= now() - INTERVAL {} DAY "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_flow_attack_count(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select count(*) as count from jxlog where (WafModule = 'flow_rule_protection' or WafModule = 'flow_engine_protection' or WafModule = 'flow_ip_region_block') and toDateTime(RequestTime) >= now() - INTERVAL {} DAY "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_flow_attack_ip_count(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select count(distinct SrcIP) as count from jxlog where (WafModule = 'flow_rule_protection' or WafModule = 'flow_engine_protection' or WafModule = 'flow_ip_region_block') and toDateTime(RequestTime) >= now() - INTERVAL {} DAY "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_name_list_attack_count(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select count(*) as count from jxlog where (WafModule = 'black_name_list') and toDateTime(RequestTime) >= now() - INTERVAL {} DAY "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_name_list_attack_ip_count(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select count(distinct SrcIP) as count from jxlog where (WafModule = 'black_name_list') and toDateTime(RequestTime) >= now() - INTERVAL {} DAY "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_web_attack_ip_region(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select Longitude,Latitude,count(*) as count from jxlog where (WafModule = 'web_rule_protection' or WafModule = 'web_engine_protection') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by Longitude,Latitude order by count desc "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_flow_attack_ip_region(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select Longitude,Latitude,count(*) as count from jxlog where (WafModule = 'flow_rule_protection' or WafModule = 'flow_engine_protection' or WafModule = 'flow_ip_region_block') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by Longitude,Latitude order by count desc "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_name_list_attack_ip_region(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select Longitude,Latitude,count(*) as count from jxlog where (WafModule = 'black_name_list') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by Longitude,Latitude order by count desc "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_web_attack_host_uri_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select Host,URI,count(*) as count from jxlog where (WafModule = 'web_rule_protection' or WafModule = 'web_engine_protection') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by Host,URI order by count desc limit 10 "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_flow_attack_host_uri_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select Host,URI,count(*) as count from jxlog where (WafModule = 'flow_rule_protection' or WafModule = 'flow_engine_protection' or WafModule = 'flow_ip_region_block') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by Host,URI order by count desc limit 10 "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_name_list_attack_host_uri_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select Host,URI,count(*) as count from jxlog where (WafModule = 'black_name_list') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by Host,URI order by count desc limit 10 "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_web_attack_ip_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select SrcIP,count(*) as count from jxlog where (WafModule = 'web_rule_protection' or WafModule = 'web_engine_protection') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by SrcIP order by count desc limit 10 "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_flow_attack_ip_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select SrcIP,count(*) as count from jxlog where (WafModule = 'flow_rule_protection' or WafModule = 'flow_engine_protection' or WafModule = 'flow_ip_region_block') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by SrcIP order by count desc limit 10 "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_name_list_attack_ip_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select SrcIP,count(*) as count from jxlog where (WafModule = 'black_name_list') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by SrcIP order by count desc limit 10 "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_web_policy_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select WafPolicy,count(*) as count from jxlog where (WafModule = 'web_rule_protection' or WafModule = 'web_engine_protection') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by WafPolicy order by count desc limit 10 "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_flow_policy_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select WafPolicy,count(*) as count from jxlog where (WafModule = 'flow_rule_protection' or WafModule = 'flow_engine_protection' or WafModule = 'flow_ip_region_block') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by WafPolicy order by count desc limit 10 "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_report_name_list_policy_top10(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        time_zone = json_data['time_zone']
        raw_sql = "select WafPolicy,count(*) as count from jxlog where (WafModule = 'black_name_list') and  toDateTime(RequestTime) >= now() - INTERVAL {} DAY group by WafPolicy order by count desc limit 10 "
        if time_zone == "1day":
            req_sql = raw_sql.format('1')
        elif time_zone == "7day":
            req_sql = raw_sql.format('7')
        elif time_zone == "30day":
            req_sql = raw_sql.format('30')
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
        result = client.execute(req_sql)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
