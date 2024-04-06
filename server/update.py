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

reload(sys)
sys.setdefaultencoding('utf8')


def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False


def waf_update(request):
    data_result = {}
    try:
        json_data = json.loads(request.body)
        api_key = json_data['api_key']
        api_password = json_data['api_password']
        try:
            conf_md5 = json_data['conf_md5']
            node_uuid = json_data['waf_node_uuid']
        except:
            conf_md5 = ""
            node_uuid = ""
    except Exception, e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = "param error:" + str(e)
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(api_key=api_key) & Q(api_password=api_password))
    except:
        data_result['result'] = False
        data_result['message'] = "api_key or api_password error"
        return JsonResponse(data_result, safe=False)
    try:
        try:
            node_monitor_result = node_monitor.objects.get(Q(user_id=user_result.api_key) & Q(node_uuid=node_uuid))
            if node_monitor_result.node_waf_conf_update == "false":
                same_result = {}
                same_result['result'] = True
                same_result['configure_without_change'] = True
                return JsonResponse(same_result, safe=False)
        except:
            pass
        waf_domain_data = {}
        domain_results = waf_domain.objects.filter(user_id=user_result.api_key)
        for result in domain_results:
            source_ip = []
            for process_domain in str(result.source_ip).split(','):
                if isIP(process_domain.strip()):
                    source_ip.append(process_domain.strip())
                else:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        query = resolver.query(process_domain.strip(),'A')
                        for i in query.response.answer:
                            for j in i.items:
                                if j.rdtype == 1:
                                    source_ip.append(j.address)
                    except:
                        data_result['error_domain'] = result.domain
                        source_ip.append(process_domain)
            data = {
                'http': result.http,
                'https': result.https,
                'redirect_https': result.redirect_https,
                'ssl_source': result.ssl_source,
                'ssl_domain': result.ssl_domain,
                'private_key': result.private_key,
                'public_key': result.public_key,
                'source_ip': source_ip,
                'source_http_port': result.source_http_port,
                'proxy_pass_https': result.proxy_pass_https,
                'balance_type': result.balance_type,
                'domain': result.domain
            }
            waf_domain_data[result.domain] = {}
            waf_domain_data[result.domain]['domain_data'] = data

        protection_results = waf_protection.objects.filter(user_id=user_result.api_key)
        for result in protection_results:
            data = {
                'web_engine_protection': result.web_engine_protection,
                'web_rule_protection': result.web_rule_protection,
                'web_white_rule': result.web_white_rule,
                'web_deny_page': result.web_deny_page,
                'flow_engine_protection': result.flow_engine_protection,
                'flow_rule_protection': result.flow_rule_protection,
                'flow_white_rule': result.flow_white_rule,
                'flow_deny_page': result.flow_deny_page,
                'name_list': result.name_list,
                'component_protection': result.component_protection,
                'analysis_component': result.analysis_component
            }
            waf_domain_data[result.domain]['protection_data'] = data

        web_engine_protection_results = waf_web_engine_protection.objects.filter(user_id=user_result.api_key)
        for result in web_engine_protection_results:
            data = {
                'sql_check': result.sql_check,
                'xss_check': result.xss_check,
                'command_inject_check': result.command_inject_check,
                'webshell_update_check': result.webshell_update_check,
                'sensitive_file_check': result.sensitive_file_check,
                'path_traversal_check': result.path_traversal_check,
                'high_nday_check': result.high_nday_check
            }
            waf_domain_data[result.domain][
                'web_engine_protection_data'] = data

        web_rule_protection_results = waf_web_rule_protection.objects.filter(user_id=user_result.api_key).filter(
            rule_status='true').order_by('rule_order_time')
        web_rule_protection_data = {}
        for result in web_rule_protection_results:
            if not web_rule_protection_data.has_key(result.domain):
                web_rule_protection_data[result.domain] = []
            if result.rule_type == "group_rule":
                group_id_results = sys_web_rule_protection.objects.filter(
                    rule_type='group_rule').filter(
                    rule_group_uuid=result.uuid).order_by('rule_order_time')
                for group_id_result in group_id_results:
                    web_rule_protection_data[result.domain].append(group_id_result.rule_uuid)
            elif result.rule_type == "single_rule":
                web_rule_protection_data[result.domain].append(result.uuid)

        for domain in web_rule_protection_data.keys():
            waf_domain_data[domain]['web_rule_protection_data'] = web_rule_protection_data[
                domain]

        web_white_rule_results = waf_web_white_rule.objects.filter(user_id=user_result.api_key).filter(
            rule_status='true').order_by('rule_order_time')
        web_white_rule_data = {}
        for result in web_white_rule_results:
            if not web_white_rule_data.has_key(result.domain):
                web_white_rule_data[result.domain] = []
            if result.rule_type == "group_rule":
                group_id_results = sys_web_white_rule.objects.filter(
                    rule_type='group_rule').filter(
                    rule_group_uuid=result.uuid).order_by('rule_order_time')
                for group_id_result in group_id_results:
                    web_white_rule_data[result.domain].append(group_id_result.rule_uuid)

            elif result.rule_type == "single_rule":
                web_white_rule_data[result.domain].append(result.uuid)
        for domain in web_white_rule_data.keys():
            waf_domain_data[domain]['web_white_rule_data'] = web_white_rule_data[
                domain]

        flow_engine_protection_results = waf_flow_engine_protection.objects.filter(user_id=user_result.api_key)
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
            waf_domain_data[result.domain][
                'flow_engine_protection_data'] = data

        flow_rule_protection_results = waf_flow_rule_protection.objects.filter(user_id=user_result.api_key).filter(
            rule_status='true').order_by('rule_order_time')
        flow_rule_protection_data = {}
        for result in flow_rule_protection_results:
            if not flow_rule_protection_data.has_key(result.domain):
                flow_rule_protection_data[result.domain] = []
            if result.rule_type == "group_rule":
                group_id_results = sys_flow_rule_protection.objects.filter(
                    rule_type='group_rule').filter(
                    rule_group_uuid=result.uuid).order_by('rule_order_time')
                for group_id_result in group_id_results:
                    flow_rule_protection_data[result.domain].append(group_id_result.rule_uuid)
            elif result.rule_type == "single_rule":
                flow_rule_protection_data[result.domain].append(result.uuid)

        for domain in flow_rule_protection_data.keys():
            waf_domain_data[domain]['flow_rule_protection_data'] = flow_rule_protection_data[
                domain]

        flow_white_rule_results = waf_flow_white_rule.objects.filter(user_id=user_result.api_key).filter(
            rule_status='true').order_by('rule_order_time')
        flow_white_rule_data = {}
        for result in flow_white_rule_results:
            if not flow_white_rule_data.has_key(result.domain):
                flow_white_rule_data[result.domain] = []
            if result.rule_type == "group_rule":
                group_id_results = sys_flow_white_rule.objects.filter(
                    rule_type='group_rule').filter(
                    rule_group_uuid=result.uuid).order_by('rule_order_time')
                for group_id_result in group_id_results:
                    flow_white_rule_data[result.domain].append(group_id_result.rule_uuid)
            elif result.rule_type == "single_rule":
                flow_white_rule_data[result.domain].append(result.uuid)
        for domain in flow_white_rule_data.keys():
            waf_domain_data[domain]['flow_white_rule_data'] = flow_white_rule_data[
                domain]

        name_list_results = waf_name_list.objects.filter(user_id=user_result.api_key).filter(status='true').order_by(
            'order_time')
        name_list_data = {}
        for result in name_list_results:
            if not name_list_data.has_key(result.domain):
                name_list_data[result.domain] = []
            name_list_data[result.domain].append(result.name_list_uuid)
        for domain in name_list_data.keys():
            waf_domain_data[domain]['name_list_data'] = name_list_data[domain]

        component_protection_results = waf_component_protection.objects.filter(user_id=user_result.api_key).filter(
            status='true').order_by(
            'order_time')
        component_protection_data = {}
        for result in component_protection_results:
            if not component_protection_data.has_key(result.domain):
                component_protection_data[result.domain] = []
            sys_component_protection_result = sys_component_protection.objects.get(
                Q(user_id=user_result.api_key) & Q(uuid=result.uuid))
            component_protection_data[result.domain].append(
                {"uuid": result.uuid, "conf": json.loads(result.conf), "name": sys_component_protection_result.name})

        for domain in component_protection_data.keys():
            waf_domain_data[domain]['component_protection_data'] = component_protection_data[domain]
        data_result['waf_domain_data'] = waf_domain_data

        analysis_component_results = waf_analysis_component.objects.filter(user_id=user_result.api_key).filter(
            status='true').order_by(
            'order_time')
        analysis_component_data = {}
        for result in analysis_component_results:
            if not analysis_component_data.has_key(result.domain):
                analysis_component_data[result.domain] = []
            sys_component_protection_result = sys_component_protection.objects.get(
                Q(user_id=user_result.api_key) & Q(uuid=result.uuid))
            analysis_component_data[result.domain].append(
                {"uuid": result.uuid, "conf": json.loads(result.conf), "name": sys_component_protection_result.name})

        for domain in analysis_component_data.keys():
            waf_domain_data[domain]['analysis_component_data'] = analysis_component_data[domain]
        data_result['waf_domain_data'] = waf_domain_data

        global_component_protection_results = waf_global_component_protection.objects.filter(
            user_id=user_result.api_key).filter(
            status='true').order_by('order_time')
        waf_global_component_protection_data = []
        for result in global_component_protection_results:
            sys_component_protection_result = sys_component_protection.objects.get(
                Q(user_id=user_result.api_key) & Q(uuid=result.uuid))
            waf_global_component_protection_data.append(
                {
                    "uuid": result.uuid,
                    "conf": json.loads(result.conf),
                    "name": sys_component_protection_result.name
                }
            )
        data_result['waf_global_component_protection_data'] = waf_global_component_protection_data
        waf_group_domain_data = {}
        group_domain_results = waf_group_domain.objects.filter(user_id=user_result.api_key)
        for result in group_domain_results:
            source_ip = []
            for process_domain in str(result.source_ip).split(','):
                if isIP(process_domain.strip()):
                    source_ip.append(process_domain.strip())
                else:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        query = resolver.query(process_domain.strip(),'A')
                        for i in query.response.answer:
                            for j in i.items:
                                if j.rdtype == 1:
                                    source_ip.append(j.address)
                    except:
                        data_result['error_domain'] = result.domain
                        source_ip.append(process_domain)
            data = {
                'http': result.http,
                'https': result.https,
                'redirect_https': result.redirect_https,
                'ssl_source': result.ssl_source,
                'ssl_domain': result.ssl_domain,
                'private_key': result.private_key,
                'public_key': result.public_key,
                'source_ip': source_ip,
                'source_http_port': result.source_http_port,
                'proxy_pass_https': result.proxy_pass_https,
                'group_id': result.group_id,
                'balance_type': result.balance_type,
                'domain': result.domain
            }
            waf_group_domain_data[result.domain] = data
        data_result['waf_group_domain_data'] = waf_group_domain_data
        waf_group_id_data = {}
        group_protection_results = waf_group_protection.objects.filter(user_id=user_result.api_key)
        for result in group_protection_results:
            data = {
                'web_engine_protection': result.web_engine_protection,
                'web_rule_protection': result.web_rule_protection,
                'web_white_rule': result.web_white_rule,
                'web_deny_page': result.web_deny_page,
                'flow_engine_protection': result.flow_engine_protection,
                'flow_rule_protection': result.flow_rule_protection,
                'flow_white_rule': result.flow_white_rule,
                'flow_deny_page': result.flow_deny_page,
                'name_list': result.name_list,
                'component_protection': result.component_protection
            }
            waf_group_id_data[result.group_id] = {}
            waf_group_id_data[result.group_id]['protection_data'] = data

        group_web_engine_protection_results = waf_group_web_engine_protection.objects.filter(
            user_id=user_result.api_key)
        for result in group_web_engine_protection_results:
            data = {
                'sql_check': result.sql_check,
                'xss_check': result.xss_check,
                'command_inject_check': result.command_inject_check,
                'webshell_update_check': result.webshell_update_check,
                'sensitive_file_check': result.sensitive_file_check,
                'path_traversal_check': result.path_traversal_check,
                'high_nday_check': result.high_nday_check
            }
            waf_group_id_data[result.group_id]['web_engine_protection_data'] = data

        group_web_rule_protection_results = waf_group_web_rule_protection.objects.filter(
            user_id=user_result.api_key).filter(
            rule_status='true').order_by('rule_order_time')
        group_web_rule_protection_data = {}
        for result in group_web_rule_protection_results:
            if not group_web_rule_protection_data.has_key(result.group_id):
                group_web_rule_protection_data[result.group_id] = []
            if result.rule_type == "group_rule":
                group_id_results = sys_web_rule_protection.objects.filter(
                    rule_type='group_rule').filter(
                    rule_group_uuid=result.uuid).order_by('rule_order_time')
                for group_id_result in group_id_results:
                    group_web_rule_protection_data[result.group_id].append(group_id_result.rule_uuid)
            elif result.rule_type == "single_rule":
                group_web_rule_protection_data[result.group_id].append(result.uuid)
        for group_id in group_web_rule_protection_data.keys():
            waf_group_id_data[group_id]['web_rule_protection_data'] = group_web_rule_protection_data[group_id]

        waf_group_web_white_rulee_results = waf_group_web_white_rule.objects.filter(user_id=user_result.api_key).filter(
            rule_status='true').order_by('rule_order_time')
        group_web_white_rule_data = {}
        for result in waf_group_web_white_rulee_results:
            if not group_web_white_rule_data.has_key(result.group_id):
                group_web_white_rule_data[result.group_id] = []
            if result.rule_type == "group_rule":
                group_id_results = sys_web_white_rule_group.objects.filter(
                    rule_type='group_rule').filter(
                    rule_group_uuid=result.uuid).order_by('rule_order_time')
                for group_id_result in group_id_results:
                    group_web_white_rule_data[result.group_id].append(group_id_result.rule_uuid)
            elif result.rule_type == "single_rule":
                group_web_white_rule_data[result.group_id].append(result.uuid)
        for group_id in group_web_white_rule_data.keys():
            waf_group_id_data[group_id]['web_white_rule_data'] = group_web_white_rule_data[group_id]

        group_flow_engine_protection_results = waf_group_flow_engine_protection.objects.filter(
            user_id=user_result.api_key)
        for result in group_flow_engine_protection_results:
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
            waf_group_id_data[result.group_id]['flow_engine_protection_data'] = data

        group_flow_rule_protection_results = waf_group_flow_rule_protection.objects.filter(
            user_id=user_result.api_key).filter(
            rule_status='true').order_by('rule_order_time')
        group_flow_rule_protection_data = {}
        for result in group_flow_rule_protection_results:
            if not group_flow_rule_protection_data.has_key(result.group_id):
                group_flow_rule_protection_data[result.group_id] = []
            if result.rule_type == "group_rule":
                group_id_results = sys_flow_rule_protection.objects.filter(
                    rule_type='group_rule').filter(
                    rule_group_uuid=result.uuid).order_by('rule_order_time')
                for group_id_result in group_id_results:
                    group_flow_rule_protection_data[result.group_id].append(group_id_result.rule_uuid)
            elif result.rule_type == "single_rule":
                group_flow_rule_protection_data[result.group_id].append(result.uuid)

        for group_id in group_flow_rule_protection_data.keys():
            waf_group_id_data[group_id]['flow_rule_protection_data'] = group_flow_rule_protection_data[group_id]

        group_flow_white_rule_results = waf_group_flow_white_rule.objects.filter(user_id=user_result.api_key).filter(
            rule_status='true').order_by('rule_order_time')
        group_flow_white_rule_data = {}
        for result in group_flow_white_rule_results:
            if not group_flow_white_rule_data.has_key(result.group_id):
                group_flow_white_rule_data[result.group_id] = []
            if result.rule_type == "group_rule":
                group_id_results = sys_flow_white_rule.objects.filter(
                    rule_type='group_rule').filter(
                    rule_group_uuid=result.uuid).order_by('rule_order_time')
                for group_id_result in group_id_results:
                    group_flow_white_rule_data[result.group_id].append(group_id_result.rule_uuid)
            elif result.rule_type == "single_rule":
                group_flow_white_rule_data[result.group_id] = group_flow_white_rule_data[result.group_id].append(
                    result.uuid)
        for group_id in group_flow_white_rule_data.keys():
            waf_group_id_data[group_id]['flow_white_rule_data'] = group_flow_white_rule_data[group_id]

        group_name_list_results = waf_group_name_list.objects.filter(user_id=user_result.api_key).filter(
            status='true').order_by('order_time')
        group_name_list_data = {}
        for result in group_name_list_results:
            if not group_name_list_data.has_key(result.group_id):
                group_name_list_data[result.group_id] = []
            group_name_list_data[result.group_id].append(result.name_list_uuid)
        for group_id in group_name_list_data.keys():
            waf_group_id_data[group_id]['name_list_data'] = group_name_list_data[group_id]

        group_component_protection_results = waf_group_component_protection.objects.filter(
            user_id=user_result.api_key).filter(status='true').order_by(
            'order_time')
        group_component_protection_data = {}
        for result in group_component_protection_results:
            if not group_component_protection_data.has_key(result.group_id):
                group_component_protection_data[result.group_id] = []
            sys_component_protection_result = sys_component_protection.objects.get(
                Q(user_id=user_result.api_key) & Q(uuid=result.uuid))
            group_component_protection_data[result.group_id].append(
                {"uuid": result.uuid, "conf": json.loads(result.conf), "name": sys_component_protection_result.name})

        for group_id in group_component_protection_data.keys():
            waf_group_id_data[group_id]['group_component_protection_data'] = group_component_protection_data[group_id]
        data_result['waf_group_id_data'] = waf_group_id_data

        group_analysis_component_results = waf_group_analysis_component.objects.filter(
            user_id=user_result.api_key).filter(status='true').order_by(
            'order_time')
        group_analysis_component_data = {}
        for result in group_analysis_component_results:
            if not group_analysis_component_data.has_key(result.group_id):
                group_analysis_component_data[result.group_id] = []
            sys_component_protection_result = sys_component_protection.objects.get(
                Q(user_id=user_result.api_key) & Q(uuid=result.uuid))
            group_analysis_component_data[result.group_id].append(
                {"uuid": result.uuid, "conf": json.loads(result.conf), "name": sys_component_protection_result.name})

        for group_id in group_analysis_component_data.keys():
            waf_group_id_data[group_id]['group_analysis_component_data'] = group_analysis_component_data[group_id]
        data_result['waf_group_id_data'] = waf_group_id_data

        sys_web_rule_protection_results = sys_web_rule_protection.objects.filter(user_id=user_result.api_key)
        sys_web_rule_protection_data = {}
        for result in sys_web_rule_protection_results:
            sys_web_rule_protection_data[result.rule_uuid] = {
                "rule_group_uuid": result.rule_group_uuid,
                "rule_group_name": result.rule_group_name,
                "rule_name": result.rule_name,
                "rule_matchs": json.loads(result.rule_matchs),
                "rule_action": result.rule_action,
                "action_value": result.action_value,
                "rule_log": result.rule_log
            }
        data_result['sys_web_rule_protection_data'] = sys_web_rule_protection_data

        sys_web_white_rule_results = sys_web_white_rule.objects.filter(user_id=user_result.api_key)
        sys_web_white_rule_data = {}
        for result in sys_web_white_rule_results:
            sys_web_white_rule_data[result.rule_uuid] = {
                "rule_group_uuid": result.rule_group_uuid,
                "rule_group_name": result.rule_group_name,
                "rule_name": result.rule_name,
                "rule_matchs": json.loads(result.rule_matchs),
                "rule_action": result.rule_action,
                "action_value": json.loads(result.action_value),
                "rule_log": result.rule_log
            }
        data_result['sys_web_white_rule_data'] = sys_web_white_rule_data

        sys_flow_rule_protection_results = sys_flow_rule_protection.objects.filter(user_id=user_result.api_key)
        sys_flow_rule_protection_data = {}
        for result in sys_flow_rule_protection_results:
            sys_flow_rule_protection_data[result.rule_uuid] = {
                "rule_group_uuid": result.rule_group_uuid,
                "rule_group_name": result.rule_group_name,
                "rule_name": result.rule_name,
                "rule_matchs": json.loads(result.rule_matchs),
                "rule_action": result.rule_action,
                "action_value": result.action_value,
                "rule_log": result.rule_log,
                "rule_pre_match": result.rule_pre_match
            }
        data_result['sys_flow_rule_protection_data'] = sys_flow_rule_protection_data

        sys_flow_white_rule_results = sys_flow_white_rule.objects.filter(user_id=user_result.api_key)
        sys_flow_white_rule_data = {}
        for result in sys_flow_white_rule_results:
            sys_flow_white_rule_data[result.rule_uuid] = {
                "rule_group_uuid": result.rule_group_uuid,
                "rule_group_name": result.rule_group_name,
                "rule_name": result.rule_name,
                "rule_matchs": json.loads(result.rule_matchs),
                "rule_action": result.rule_action,
                "action_value": json.loads(result.action_value),
                "rule_log": result.rule_log,
                "rule_pre_match": result.rule_pre_match
            }
        data_result['sys_flow_white_rule_data'] = sys_flow_white_rule_data

        sys_shared_dict_results = sys_shared_dict.objects.filter(user_id=user_result.api_key)
        sys_shared_dict_data = {}
        for result in sys_shared_dict_results:
            sys_shared_dict_data[result.shared_dict_uuid] = {
                "shared_dict_name": result.shared_dict_name,
                "shared_dict_key": json.loads(result.shared_dict_key),
                "shared_dict_type": result.shared_dict_type,
                "shared_dict_value": result.shared_dict_value,
                "shared_dict_expire_time": result.shared_dict_expire_time
            }
        data_result['sys_shared_dict_data'] = sys_shared_dict_data

        sys_name_list_results = sys_name_list.objects.filter(user_id=user_result.api_key)
        sys_name_list_data = {}
        for result in sys_name_list_results:
            sys_name_list_data[result.name_list_uuid] = {
                "name_list_name": result.name_list_name,
                "name_list_rule": json.loads(result.name_list_rule),
                "name_list_action": result.name_list_action,
                "action_value": result.action_value,
                "repeated_writing_suppression": result.repeated_writing_suppression
            }
        data_result['sys_name_list_data'] = sys_name_list_data

        sys_ssl_manage_results = sys_ssl_manage.objects.filter(user_id=user_result.api_key)
        sys_ssl_manage_data = {}
        for result in sys_ssl_manage_results:
            sys_ssl_manage_data[result.ssl_domain] = {
                "private_key": result.private_key,
                "public_key": result.public_key
            }
        data_result['sys_ssl_manage_data'] = sys_ssl_manage_data

        global_name_list_results = waf_global_name_list.objects.filter(user_id=user_result.api_key).filter(
            status='true').order_by('order_time')
        waf_global_name_list_data = []
        for result in global_name_list_results:
            waf_global_name_list_data.append(result.name_list_uuid)
        data_result['waf_global_name_list_data'] = waf_global_name_list_data

        global_component_protection_results = waf_global_component_protection.objects.filter(
            user_id=user_result.api_key).filter(
            status='true').order_by('order_time')
        waf_global_component_protection_data = []
        for result in global_component_protection_results:
            sys_component_protection_result = sys_component_protection.objects.get(
                Q(user_id=user_result.api_key) & Q(uuid=result.uuid))
            waf_global_component_protection_data.append(
                {
                    "uuid": result.uuid,
                    "conf": json.loads(result.conf),
                    'name': sys_component_protection_result.name
                }
            )
        data_result['waf_global_component_protection_data'] = waf_global_component_protection_data
        try:
            sys_abnormal_handle.objects.get(user_id=user_result.api_key)
        except:
            sys_abnormal_handle.objects.filter(user_id=user_result.api_key).delete()
            sys_abnormal_handle.objects.create(user_id=user_result.api_key)
        sys_abnormal_handle_result = sys_abnormal_handle.objects.get(user_id=user_result.api_key)
        data_result['sys_abnormal_handle_data'] = {
            "bypass_check": sys_abnormal_handle_result.bypass_check,
            "same_name_args_check": sys_abnormal_handle_result.same_name_args_check,
            "truncated_agrs_check": sys_abnormal_handle_result.truncated_agrs_check,
            "client_body_size_check": sys_abnormal_handle_result.client_body_size_check,
            "ssl_attack_check": sys_abnormal_handle_result.ssl_attack_check,
            "ssl_attack_count": sys_abnormal_handle_result.ssl_attack_count,
            "ssl_attack_count_stat_time_period": sys_abnormal_handle_result.ssl_attack_count_stat_time_period,
            "ssl_attack_block_name_list_uuid": sys_abnormal_handle_result.ssl_attack_block_name_list_uuid,
        }
        try:
            sys_global_default_page.objects.get(user_id=user_result.api_key)
        except:
            sys_global_default_page.objects.filter(user_id=user_result.api_key).delete()
            sys_global_default_page.objects.create(user_id=user_result.api_key)
        sys_global_default_page_result = sys_global_default_page.objects.get(user_id=user_result.api_key)
        data_result['sys_global_default_page_data'] = {
            "web_deny_code": sys_global_default_page_result.web_deny_code,
            "web_deny_html": sys_global_default_page_result.web_deny_html,
            "flow_deny_code": sys_global_default_page_result.flow_deny_code,
            "flow_deny_html": sys_global_default_page_result.flow_deny_html,
            "name_list_deny_code": sys_global_default_page_result.name_list_deny_code,
            "name_list_deny_html": sys_global_default_page_result.name_list_deny_html,
            "domain_404_code": sys_global_default_page_result.domain_404_code,
            "domain_404_html": sys_global_default_page_result.domain_404_html
        }
        try:
            sys_log_conf.objects.get(user_id=user_result.api_key)
        except:
            sys_log_conf.objects.filter(user_id=user_result.api_key).delete()
            sys_log_conf.objects.create(user_id=user_result.api_key)
        sys_log_conf_result = sys_log_conf.objects.get(user_id=user_result.api_key)
        kafka_bootstrap_servers_data = []
        kafka_bootstrap_servers = sys_log_conf_result.kafka_bootstrap_servers.split(',')
        for kafka_bootstrap_server in kafka_bootstrap_servers:
            try:
                kafka_bootstrap_servers_data.append(
                    {
                        'host': kafka_bootstrap_server.split(':')[0],
                        'port': kafka_bootstrap_server.split(':')[1]
                    }
                )
            except:
                pass
        data_result['sys_log_conf_data'] = {
            "log_local_debug": sys_log_conf_result.log_local_debug,
            "log_remote": sys_log_conf_result.log_remote,
            "log_ip": sys_log_conf_result.log_ip,
            "log_port": sys_log_conf_result.log_port,
            "log_all": sys_log_conf_result.log_all,
            "log_remote_type": sys_log_conf_result.log_remote_type,
            "kafka_bootstrap_servers": kafka_bootstrap_servers_data,
            "kafka_topic": sys_log_conf_result.kafka_topic
        }

        try:
            sys_mimetic_defense_conf.objects.get(user_id=user_result.api_key)
        except:
            sys_mimetic_defense_conf.objects.filter(user_id=user_result.api_key).delete()
            sys_mimetic_defense_conf.objects.create(user_id=user_result.api_key)
        sys_mimetic_defense_conf_result = sys_mimetic_defense_conf.objects.get(user_id=user_result.api_key)
        mimetic_defense_conf = {
            "mimetic_defense": sys_mimetic_defense_conf_result.mimetic_defense,
            "proxy_host": sys_mimetic_defense_conf_result.proxy_host,
            "proxy_port": sys_mimetic_defense_conf_result.proxy_port,
            "token": sys_mimetic_defense_conf_result.token,
        }
        data_result['sys_action_data'] = {}
        data_result['sys_action_data']['mimetic_defense_conf'] = mimetic_defense_conf

        custom_response_conf = {}
        sys_custom_response_results = sys_custom_response.objects.filter(user_id=user_result.api_key)
        for sys_custom_response_result in sys_custom_response_results:
            try:
                set_return_header_value = json.loads(sys_custom_response_result.set_return_header_value)
            except:
                set_return_header_value = {}
            custom_response_conf[sys_custom_response_result.name] = {
                'set_return_header_status': sys_custom_response_result.set_return_header_status,
                'set_return_header_value': set_return_header_value,
                'return_code': sys_custom_response_result.return_code,
                'return_html': sys_custom_response_result.return_html
            }
        data_result['sys_action_data']['custom_response_conf'] = custom_response_conf

        request_replace_conf = {}
        request_replace_results = sys_request_replace.objects.filter(user_id=user_result.api_key)
        for request_replace_result in request_replace_results:
            try:
                header_replace_data = json.loads(request_replace_result.header_replace_data)
            except:
                header_replace_data = {}
            request_replace_conf[request_replace_result.name] = {
                'get_status': request_replace_result.get_status,
                'header_replace_data': header_replace_data,
                'get_replace_match': request_replace_result.get_replace_match,
                'get_replace_data': request_replace_result.get_replace_data,
                'header_status': request_replace_result.header_status,
                'post_status': request_replace_result.post_status,
                'post_replace_match': request_replace_result.post_replace_match,
                'post_replace_data': request_replace_result.post_replace_data
            }
        data_result['sys_action_data']['request_replace_conf'] = request_replace_conf

        response_replace_conf = {}
        response_replace_results = sys_response_replace.objects.filter(user_id=user_result.api_key)
        for response_replace_result in response_replace_results:
            try:
                response_header_replace_data = json.loads(response_replace_result.response_header_replace_data)
            except:
                response_header_replace_data = {}
            response_replace_conf[response_replace_result.name] = {
                'response_header_status': response_replace_result.response_header_status,
                'response_header_replace_data': response_header_replace_data,
                'response_data_status': response_replace_result.response_data_status,
                'response_data_replace_match': response_replace_result.response_data_replace_match,
                'response_data_replace_data': response_replace_result.response_data_replace_data
            }
        data_result['sys_action_data']['response_replace_conf'] = response_replace_conf

        traffic_forward_conf = {}
        sys_traffic_forward_results = sys_traffic_forward.objects.filter(user_id=user_result.api_key)
        for sys_traffic_forward_result in sys_traffic_forward_results:
            try:
                set_request_header_value = json.loads(sys_traffic_forward_result.set_request_header_value)
            except:
                set_request_header_value = {}
            traffic_forward_conf[sys_traffic_forward_result.name] = {
                'set_request_header_status': sys_traffic_forward_result.set_request_header_status,
                'set_request_header_value': set_request_header_value,
                'traffic_forward_ip': sys_traffic_forward_result.traffic_forward_ip.split(','),
                'traffic_forward_port': sys_traffic_forward_result.traffic_forward_port
            }
        data_result['sys_action_data']['traffic_forward_conf'] = traffic_forward_conf

        sys_component_protection_data = {}
        sys_component_protection_results = sys_component_protection.objects.filter(user_id=user_result.api_key)
        for sys_component_protection_result in sys_component_protection_results:
            sys_component_protection_data[sys_component_protection_result.uuid] = sys_component_protection_result.code
        data_result['sys_component_protection_data'] = sys_component_protection_data
        sys_web_engine_protection_result = sys_web_engine_protection.objects.get(
            Q(user_id=user_result.api_key) & Q(default="true"))
        data_result['sys_web_engine_protection_data'] = sys_web_engine_protection_result.code
        sys_flow_engine_protection_result = sys_flow_engine_protection.objects.get(
            Q(user_id=user_result.api_key) & Q(default="true"))
        data_result['sys_flow_engine_protection_data'] = sys_flow_engine_protection_result.code
        result_md5 = hashlib.md5()
        result_md5.update(json.dumps(data_result))
        if conf_md5 == result_md5.hexdigest():
            same_result = {}
            same_result['result'] = True
            same_result['configure_without_change'] = True
            return JsonResponse(same_result, safe=False)
        node_monitor.objects.filter(user_id=user_result.api_key).filter(node_uuid=node_uuid).update(
            node_waf_conf_update_time=int(time.time()))
        data_result['conf_md5'] = result_md5.hexdigest()
        data_result['result'] = True
        data_result['message'] = "success load waf configure"
        return JsonResponse(data_result, safe=False)
    except Exception, e:
        data_result['result'] = False
        data_result['errCode'] = 504
        data_result['message'] = str(e)
        data_result['detail'] = str(traceback.format_exc())
        return JsonResponse(data_result, safe=False)


def waf_name_list_item_update(request):
    data_result = {}
    sys_name_list_item_data = {}
    try:
        json_data = json.loads(request.body)
        api_key = json_data['api_key']
        api_password = json_data['api_password']
        node_uuid = json_data['waf_node_uuid']
        conf_md5 = json_data['conf_md5']
    except Exception, e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = str(e)
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(api_key=api_key) & Q(api_password=api_password))
    except:
        data_result['result'] = False
        data_result['message'] = "api_key or api_password error"
        return JsonResponse(data_result, safe=False)
    try:
        try:
            node_monitor_result = node_monitor.objects.get(Q(user_id=user_result.api_key) & Q(node_uuid=node_uuid))
            if node_monitor_result.node_name_list_data_update == "false":
                same_result = {}
                same_result['result'] = True
                same_result['configure_without_change'] = True
                return JsonResponse(same_result, safe=False)
        except:
            pass
        now_time = int(time.time())
        sys_name_list_item.objects.filter(user_id=user_result.api_key).filter(
            name_list_item_expire_time__lt=now_time).delete()
        sys_name_list_results = sys_name_list.objects.filter(user_id=user_result.api_key)
        for sys_name_list_result in sys_name_list_results:
            name_list_uuid = sys_name_list_result.name_list_uuid
            sys_name_list_item_results = sys_name_list_item.objects.filter(user_id=user_result.api_key).filter(
                name_list_uuid=name_list_uuid)
            item_data = {}
            for sys_name_list_item_result in sys_name_list_item_results:
                item_data[sys_name_list_item_result.name_list_item] = True
            sys_name_list_item_data[name_list_uuid] = item_data
        data_result['sys_name_list_item_data'] = sys_name_list_item_data
        result_md5 = hashlib.md5()
        result_md5.update(json.dumps(data_result))
        if conf_md5 == result_md5.hexdigest():
            same_result = {}
            same_result['result'] = True
            same_result['configure_without_change'] = True
            return JsonResponse(same_result, safe=False)
        node_monitor.objects.filter(user_id=user_result.api_key).filter(node_uuid=node_uuid).update(
            node_name_list_data_update_time=int(time.time()))
        data_result['conf_md5'] = result_md5.hexdigest()
        data_result['result'] = True
        return JsonResponse(data_result, safe=False)
    except Exception, e:
        data_result['result'] = False
        data_result['errCode'] = 504
        data_result['message'] = str(e)
        data_result['detail'] = str(traceback.format_exc())
        return JsonResponse(data_result, safe=False)


def waf_monitor(request):
    data_result = {}
    data = {}
    try:
        json_data = json.loads(request.body)
        waf_api_key = json_data['api_key']
        waf_api_password = json_data['api_password']
        waf_node_uuid = json_data['waf_node_uuid']
        waf_node_hostname = json_data['waf_node_hostname']
        waf_node_ip = request.META['REMOTE_ADDR']
    except Exception, e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = str(e)
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(api_key=waf_api_key) & Q(api_password=waf_api_password))
    except:
        data_result['result'] = False
        data_result['errCode'] = 401
        data_result['message'] = "api_key or api_password error"
        return JsonResponse(data_result, safe=False)

    try:
        node_monitor.objects.get(Q(user_id=user_result.api_key) & Q(node_uuid=waf_node_uuid))
        try:
            node_monitor.objects.filter(user_id=user_result.api_key).filter(
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
            node_monitor.objects.create(user_id=user_result.api_key, node_uuid=waf_node_uuid,
                                        node_hostname=waf_node_hostname, node_ip=waf_node_ip,
                                        node_status_update_time=int(time.time()))
            data_result['result'] = True
            return JsonResponse(data_result, safe=False)
        except:
            data_result['result'] = False
            data_result['message'] = str(traceback.format_exc())
            return JsonResponse(data_result, safe=False)
