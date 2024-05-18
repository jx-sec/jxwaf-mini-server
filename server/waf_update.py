# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
from django.db.models import Q
import uuid
import sys
import datetime
import traceback
import re
import hashlib
import dns.resolver
from django.conf import settings
import time
import ipaddress

reload(sys)
sys.setdefaultencoding('utf8')


def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False


def get_all_ips(ip_list):
    all_ips = []
    for item in ip_list:
        if '/' in item:
            network = ipaddress.ip_network(unicode(item))
            all_ips.extend(list(network.hosts()))
        else:
            all_ips.append(ipaddress.ip_address(unicode(item)))
    return all_ips


def list_to_dict(list):
    data = {}
    for key in list:
        data[key] = True
    return data


def waf_update(request):
    data_result = {}
    try:
        json_data = json.loads(request.body)
        waf_auth = json_data['waf_auth']
        try:
            conf_md5 = json_data['conf_md5']
        except:
            conf_md5 = ""
    except Exception as e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = "param error:" + str(e)
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(waf_auth=waf_auth))
        user_id = user_result.user_id
    except:
        data_result['result'] = False
        data_result['message'] = "waf_auth_error"
        return JsonResponse(data_result, safe=False)
    try:
        waf_domain_data = {}
        domain_results = waf_domain.objects.filter(user_id=user_id)
        for result in domain_results:
            source_ip = []
            for process_domain in str(result.source_ip).split(','):
                if isIP(process_domain.strip()):
                    source_ip.append(process_domain.strip())
                else:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        query = resolver.query(process_domain.strip(), 'A')
                        for i in query.response.answer:
                            for j in i.items:
                                if j.rdtype == 1:
                                    source_ip.append(j.address)
                    except:
                        data_result['error_domain'] = result.domain
                        source_ip.append(process_domain)
            white_ip_list = {}
            if result.advanced_conf == 'true' and result.pre_proxy == 'true':
                #white_ip_list = list_to_dict(get_all_ips(str(result.white_ip_list).split(',')))
                white_ip_list = str(result.white_ip_list).split(',')
            data = {
                'http': result.http,
                'https': result.https,
                'ssl_domain': result.ssl_domain,
                'source_ip': source_ip,
                'source_http_port': result.source_http_port,
                'proxy_pass_https': result.proxy_pass_https,
                'balance_type': result.balance_type,
                'advanced_conf': result.advanced_conf,
                'force_https': result.force_https,
                'pre_proxy': result.pre_proxy,
                'real_ip_conf': result.real_ip_conf,
                'white_ip_list': white_ip_list,
                'domain': result.domain
            }
            waf_domain_data[result.domain] = data
        data_result['waf_domain_data'] = waf_domain_data

        waf_protection_data = {}
        protection_results = waf_protection.objects.filter(user_id=user_id)
        for result in protection_results:
            data = {
                'web_engine_protection': result.web_engine_protection,
                'web_rule_protection': result.web_rule_protection,
                'web_white_rule': result.web_white_rule,
                'flow_engine_protection': result.flow_engine_protection,
                'flow_rule_protection': result.flow_rule_protection,
                'flow_white_rule': result.flow_white_rule,
                'flow_ip_region_block': result.flow_ip_region_block
            }
            waf_protection_data[result.domain] = data
        data_result['waf_protection_data'] = waf_protection_data

        waf_web_engine_protection_data = {}
        web_engine_protection_results = waf_web_engine_protection.objects.filter(user_id=user_id)
        for result in web_engine_protection_results:
            data = {
                'sql_check': result.sql_check,
                'xss_check': result.xss_check,
                'cmd_exec_check': result.cmd_exec_check,
                'code_exec_check': result.code_exec_check,
                'sensitive_file_check': result.sensitive_file_check,
                'path_traversal_check': result.path_traversal_check,
                'webshell_update_check': result.webshell_update_check,
                'high_nday_check': result.high_nday_check
            }
            waf_web_engine_protection_data[result.domain] = data
        data_result['waf_web_engine_protection_data'] = waf_web_engine_protection_data

        waf_web_rule_protection_data = {}
        web_rule_protection_results = waf_web_rule_protection.objects.filter(user_id=user_id).filter(
            status='true').order_by('rule_order_time')
        web_rule_protection_data = {}
        for result in web_rule_protection_results:
            if not web_rule_protection_data.has_key(result.domain):
                web_rule_protection_data[result.domain] = []
            web_rule_protection_data[result.domain].append(
                {
                    'rule_name': result.rule_name,
                    'rule_matchs': json.loads(result.rule_matchs),
                    'rule_action': result.rule_action,
                    'action_value': result.action_value
                }
            )
        for domain in web_rule_protection_data.keys():
            waf_web_rule_protection_data[domain] = web_rule_protection_data[domain]
        data_result['waf_web_rule_protection_data'] = waf_web_rule_protection_data

        waf_web_white_rule_data = {}
        web_white_rule_results = waf_web_white_rule.objects.filter(user_id=user_id).filter(
            status='true').order_by('rule_order_time')
        web_white_rule_data = {}
        for result in web_white_rule_results:
            if not web_white_rule_data.has_key(result.domain):
                web_white_rule_data[result.domain] = []
            web_white_rule_data[result.domain].append(
                {
                    'rule_name': result.rule_name,
                    'rule_matchs': json.loads(result.rule_matchs),
                    'rule_action': result.rule_action,
                    'action_value': result.action_value
                }
            )
        for domain in web_white_rule_data.keys():
            waf_web_white_rule_data[domain] = web_white_rule_data[domain]
        data_result['waf_web_white_rule_data'] = waf_web_white_rule_data

        waf_flow_engine_protection_data = {}
        flow_engine_protection_results = waf_flow_engine_protection.objects.filter(user_id=user_id)
        for result in flow_engine_protection_results:
            data = {
                'high_freq_cc_check': result.high_freq_cc_check,
                'req_count': result.req_count,
                'req_count_stat_time_period': result.req_count_stat_time_period,
                'req_count_block_mode': result.req_count_block_mode,
                'req_count_block_mode_extra_parameter': result.req_count_block_mode_extra_parameter,
                'req_rate': result.req_rate,
                'req_rate_block_mode': result.req_rate_block_mode,
                'req_rate_block_mode_extra_parameter': result.req_rate_block_mode_extra_parameter,
                'slow_cc_check': result.slow_cc_check,
                'domain_rate': result.domain_rate,
                'slow_cc_block_mode': result.slow_cc_block_mode,
                'slow_cc_block_mode_extra_parameter': result.slow_cc_block_mode_extra_parameter,
                'ip_count': result.ip_count,
                'ip_count_stat_time_period': result.ip_count_stat_time_period,
                'ip_count_block_mode': result.ip_count_block_mode,
                'ip_count_block_mode_extra_parameter': result.ip_count_block_mode_extra_parameter,
                'emergency_mode_check': result.emergency_mode_check,
                'emergency_mode_block_mode': result.emergency_mode_block_mode,
                'emergency_mode_block_mode_extra_parameter': result.emergency_mode_block_mode_extra_parameter,
            }
            waf_flow_engine_protection_data[result.domain] = data
        data_result['waf_flow_engine_protection_data'] = waf_flow_engine_protection_data

        waf_flow_rule_protection_data = {}
        flow_rule_protection_results = waf_flow_rule_protection.objects.filter(user_id=user_id).filter(
            status='true').order_by('rule_order_time')
        flow_rule_protection_data = {}
        for result in flow_rule_protection_results:
            if not flow_rule_protection_data.has_key(result.domain):
                flow_rule_protection_data[result.domain] = []
            flow_rule_protection_data[result.domain].append(
                {
                    'rule_name': result.rule_name,
                    'rule_matchs': json.loads(result.rule_matchs),
                    'rule_action': result.rule_action,
                    'action_value': result.action_value
                }
            )
        for domain in flow_rule_protection_data.keys():
            waf_flow_rule_protection_data[domain] = flow_rule_protection_data[domain]
        data_result['waf_flow_rule_protection_data'] = waf_flow_rule_protection_data

        waf_flow_white_rule_data = {}
        flow_white_rule_results = waf_flow_white_rule.objects.filter(user_id=user_id).filter(
            status='true').order_by('rule_order_time')
        flow_white_rule_data = {}
        for result in flow_white_rule_results:
            if not flow_white_rule_data.has_key(result.domain):
                flow_white_rule_data[result.domain] = []
            flow_white_rule_data[result.domain].append(
                {
                    'rule_name': result.rule_name,
                    'rule_matchs': json.loads(result.rule_matchs),
                    'rule_action': result.rule_action,
                    'action_value': result.action_value
                }
            )
        for domain in flow_white_rule_data.keys():
            waf_flow_white_rule_data[domain] = flow_white_rule_data[domain]
        data_result['waf_flow_white_rule_data'] = waf_flow_white_rule_data

        waf_flow_ip_region_block_data = {}
        flow_ip_region_block_results = waf_flow_ip_region_block.objects.filter(user_id=user_id)
        for result in flow_ip_region_block_results:
            try:
                region_white_list = list_to_dict(json.loads(result.region_white_list))
            except:
                region_white_list = {}
            data = {
                'ip_region_block': result.ip_region_block,
                'region_white_list': region_white_list,
                'block_action': result.block_action,
                'action_value': result.action_value
            }
            waf_flow_ip_region_block_data[result.domain] = data
        data_result['waf_flow_ip_region_block_data'] = waf_flow_ip_region_block_data

        waf_ssl_manage_data = {}
        waf_ssl_manage_results = waf_ssl_manage.objects.filter(user_id=user_id)
        for result in waf_ssl_manage_results:
            waf_ssl_manage_data[result.ssl_domain] = {
                'private_key': result.private_key,
                'public_key': result.public_key
            }
        data_result['waf_ssl_manage_data'] = waf_ssl_manage_data

        waf_name_list_data = []
        waf_name_list_results = waf_name_list.objects.filter(user_id=user_id).filter(
            status='true').order_by('order_time')
        for result in waf_name_list_results:
            waf_name_list_data.append(
                {
                    'name_list_name': result.name_list_name,
                    'name_list_rule': json.loads(result.name_list_rule),
                    'name_list_action': result.name_list_action,
                    'action_value': result.action_value
                }
            )
        data_result['waf_name_list_data'] = waf_name_list_data

        waf_base_component_data = []
        waf_base_component_results = waf_base_component.objects.filter(user_id=user_id).filter(
            status='true').order_by('order_time')
        for result in waf_base_component_results:
            waf_base_component_data.append(
                {
                    'name': result.name,
                    'conf': json.loads(result.conf),
                    'code': result.code
                }
            )
        data_result['waf_base_component_data'] = waf_base_component_data

        waf_analysis_component_data = []
        waf_analysis_component_results = waf_analysis_component.objects.filter(user_id=user_id).filter(
            status='true').order_by('order_time')
        for result in waf_analysis_component_results:
            waf_analysis_component_data.append(
                {
                    'name': result.name,
                    'conf': json.loads(result.conf),
                    'code': result.code
                }
            )
        data_result['waf_analysis_component_data'] = waf_analysis_component_data

        sys_conf_data = {}
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        sys_conf_data['log_conf_local_debug'] = sys_conf_result.log_conf_local_debug
        sys_conf_data['log_conf_remote'] = sys_conf_result.log_conf_remote
        sys_conf_data['log_ip'] = sys_conf_result.log_ip
        sys_conf_data['log_port'] = sys_conf_result.log_port
        sys_conf_data['log_response'] = sys_conf_result.log_response
        sys_conf_data['log_all'] = sys_conf_result.log_all
        sys_conf_data['custom_deny_page'] = sys_conf_result.custom_deny_page
        sys_conf_data['waf_deny_code'] = sys_conf_result.waf_deny_code
        sys_conf_data['waf_deny_html'] = sys_conf_result.waf_deny_html
        data_result['sys_conf_data'] = sys_conf_data

        result_md5 = hashlib.md5()
        result_md5.update(json.dumps(data_result))
        if conf_md5 == result_md5.hexdigest():
            same_result = {}
            same_result['result'] = True
            same_result['configure_without_change'] = True
            return JsonResponse(same_result, safe=False)
        data_result['conf_md5'] = result_md5.hexdigest()
        data_result['result'] = True
        data_result['message'] = "success_load_waf_configure"
        return JsonResponse(data_result, safe=False)
    except Exception as e:
        data_result['result'] = False
        data_result['errCode'] = 504
        data_result['message'] = str(e)
        data_result['detail'] = str(traceback.format_exc())
        return JsonResponse(data_result, safe=False)


def waf_monitor(request):
    data_result = {}
    try:
        json_data = json.loads(request.body)
        waf_auth = json_data['waf_auth']
        waf_node_uuid = json_data['waf_node_uuid']
        waf_node_hostname = json_data['waf_node_hostname']
        waf_node_ip = request.META['REMOTE_ADDR']
    except Exception as e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = str(e)
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(waf_auth=waf_auth))
    except:
        data_result['result'] = False
        data_result['errCode'] = 401
        data_result['message'] = "waf_auth error"
        return JsonResponse(data_result, safe=False)

    try:
        waf_node_monitor.objects.get(Q(user_id=user_result.user_id) & Q(node_uuid=waf_node_uuid))
        try:
            waf_node_monitor.objects.filter(user_id=user_result.user_id).filter(
                node_uuid=waf_node_uuid).update(node_hostname=waf_node_hostname,
                                                node_ip=waf_node_ip,
                                                node_status_update_time=int(time.time()))
            data_result['result'] = True
            return JsonResponse(data_result, safe=False)
        except:
            data_result['result'] = False
            data_result['message'] = str(traceback.format_exc())
            return JsonResponse(data_result, safe=False)
    except:
        try:
            waf_node_monitor.objects.create(user_id=user_result.user_id, node_uuid=waf_node_uuid,
                                            node_hostname=waf_node_hostname, node_ip=waf_node_ip,
                                            node_status_update_time=int(time.time()))
            data_result['result'] = True
            return JsonResponse(data_result, safe=False)
        except:
            data_result['result'] = False
            data_result['message'] = str(traceback.format_exc())
            return JsonResponse(data_result, safe=False)


def waf_name_list_item_update(request):
    data_result = {}
    waf_name_list_item_data = {}
    try:
        json_data = json.loads(request.body)
        waf_auth = json_data['waf_auth']
        try:
            conf_md5 = json_data['conf_md5']
        except:
            conf_md5 = ""
    except Exception as e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = str(e)
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(waf_auth=waf_auth))
        user_id = user_result.user_id
    except:
        data_result['result'] = False
        data_result['message'] = "waf_auth error"
        return JsonResponse(data_result, safe=False)
    try:
        now_time = int(time.time())
        waf_name_list_item.objects.filter(user_id=user_id).filter(name_list_item_expire_time__gt=0).filter(
            name_list_item_expire_time__lt=now_time).delete()
        waf_name_list_results = waf_name_list.objects.filter(user_id=user_id).filter(status='true')
        for result in waf_name_list_results:
            name_list_name = result.name_list_name
            waf_name_list_item_results = waf_name_list_item.objects.filter(user_id=user_id).filter(
                name_list_name=name_list_name)
            item_data = {}
            for waf_name_list_item_result in waf_name_list_item_results:
                item_data[waf_name_list_item_result.name_list_item] = True
            waf_name_list_item_data[name_list_name] = item_data
        data_result['waf_name_list_item_data'] = waf_name_list_item_data
        result_md5 = hashlib.md5()
        result_md5.update(json.dumps(data_result))
        if conf_md5 == result_md5.hexdigest():
            same_result = {}
            same_result['result'] = True
            same_result['configure_without_change'] = True
            return JsonResponse(same_result, safe=False)
        data_result['conf_md5'] = result_md5.hexdigest()
        data_result['result'] = True
        return JsonResponse(data_result, safe=False)
    except Exception as e:
        data_result['result'] = False
        data_result['errCode'] = 504
        data_result['message'] = str(e)
        data_result['detail'] = str(traceback.format_exc())
        return JsonResponse(data_result, safe=False)


def waf_sys_conf_log_and_report_init(request):
    data_result = {}
    try:
        json_data = json.loads(request.body)
        waf_auth = json_data['waf_auth']
        log_ip = json_data['log_ip']
        log_port = json_data['log_port']
        report_conf_ch_host = json_data['report_conf_ch_host']
        report_conf_ch_port = json_data['report_conf_ch_port']
        report_conf_ch_user = json_data['report_conf_ch_user']
        report_conf_ch_password = json_data['report_conf_ch_password']
        report_conf_ch_database = json_data['report_conf_ch_database']
    except Exception as e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = str(e)
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(waf_auth=waf_auth))
        user_id = user_result.user_id
    except:
        data_result['result'] = False
        data_result['message'] = "waf_auth error"
        return JsonResponse(data_result, safe=False)
    try:
        sys_conf.objects.filter(user_id=user_id).update(log_conf_remote='true', log_ip=log_ip, log_port=log_port,
                                                        report_conf='true', report_conf_ch_host=report_conf_ch_host,
                                                        report_conf_ch_port=report_conf_ch_port,
                                                        report_conf_ch_user=report_conf_ch_user,
                                                        report_conf_ch_password=report_conf_ch_password,
                                                        report_conf_ch_database=report_conf_ch_database)
        data_result['result'] = True
        data_result['message'] = "update_success"
        return JsonResponse(data_result, safe=False)
    except Exception as e:
        data_result['result'] = False
        data_result['errCode'] = 504
        data_result['message'] = str(e)
        data_result['detail'] = str(traceback.format_exc())
        return JsonResponse(data_result, safe=False)
