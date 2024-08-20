from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import hashlib
from django.http import HttpResponse
import traceback


def waf_edit_sys_log_conf(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        log_conf_local_debug = json_data['log_conf_local_debug']
        log_conf_remote = json_data['log_conf_remote']
        log_ip = json_data['log_ip']
        log_port = json_data['log_port']
        log_response = json_data['log_response']
        log_all = json_data['log_all']
        sys_conf.objects.filter(user_id=user_id).update(
            log_conf_local_debug=log_conf_local_debug, log_conf_remote=log_conf_remote,
            log_ip=log_ip, log_port=log_port,
            log_response=log_response,log_all=log_all)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_log_conf(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        try:
            result = sys_conf.objects.get(user_id=user_id)
        except:
            sys_conf.objects.filter(user_id=user_id).delete()
            sys_conf.objects.create(user_id=user_id)
            result = sys_conf.objects.get(user_id=user_id)
        data['log_conf_local_debug'] = result.log_conf_local_debug
        data['log_conf_remote'] = result.log_conf_remote
        data['log_ip'] = result.log_ip
        data['log_port'] = result.log_port
        data['log_response'] = result.log_response
        data['log_all'] = result.log_all
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_sys_report_conf_conf(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        report_conf = json_data['report_conf']
        report_conf_ch_host = json_data['report_conf_ch_host']
        report_conf_ch_port = json_data['report_conf_ch_port']
        report_conf_ch_user = json_data['report_conf_ch_user']
        report_conf_ch_password = json_data['report_conf_ch_password']
        report_conf_ch_database = json_data['report_conf_ch_database']
        sys_conf.objects.filter(user_id=user_id).update(
            report_conf=report_conf, report_conf_ch_host=report_conf_ch_host,
            report_conf_ch_port=report_conf_ch_port, report_conf_ch_user=report_conf_ch_user,
            report_conf_ch_password=report_conf_ch_password, report_conf_ch_database=report_conf_ch_database)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_report_conf_conf(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        try:
            result = sys_conf.objects.get(user_id=user_id)
        except:
            sys_conf.objects.filter(user_id=user_id).delete()
            sys_conf.objects.create(user_id=user_id)
            result = sys_conf.objects.get(user_id=user_id)
        data['report_conf'] = result.report_conf
        data['report_conf_ch_host'] = result.report_conf_ch_host
        data['report_conf_ch_port'] = result.report_conf_ch_port
        data['report_conf_ch_user'] = result.report_conf_ch_user
        data['report_conf_ch_password'] = result.report_conf_ch_password
        data['report_conf_ch_database'] = result.report_conf_ch_database
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_sys_custom_deny_page_conf(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        custom_deny_page = json_data['custom_deny_page']
        waf_deny_code = json_data['waf_deny_code']
        waf_deny_html = json_data['waf_deny_html']
        sys_conf.objects.filter(user_id=user_id).update(
            custom_deny_page=custom_deny_page, waf_deny_code=waf_deny_code,
            waf_deny_html=waf_deny_html)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_custom_deny_page_conf(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        try:
            result = sys_conf.objects.get(user_id=user_id)
        except:
            sys_conf.objects.filter(user_id=user_id).delete()
            sys_conf.objects.create(user_id=user_id)
            result = sys_conf.objects.get(user_id=user_id)
        data['custom_deny_page'] = result.custom_deny_page
        data['waf_deny_code'] = result.waf_deny_code
        data['waf_deny_html'] = result.waf_deny_html
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_waf_auth(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        jxwaf_user_result = jxwaf_user.objects.get(user_id=user_id)
        return_result['result'] = True
        return_result['waf_auth'] = jxwaf_user_result.waf_auth
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_waf_auth(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        waf_auth = json_data['waf_auth']
        jxwaf_user.objects.filter(user_id=user_id).update(waf_auth=waf_auth)
        return_result['result'] = True
        return_result['message'] = 'edit_success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_conf_backup(request):
    return_result = {}
    try:
        user_id = request.session['user_id']

        # Retrieve data and convert querysets to lists of dictionaries
        waf_domain_data = list(waf_domain.objects.filter(user_id=user_id).values())
        waf_protection_data = list(waf_protection.objects.filter(user_id=user_id).values())
        waf_web_engine_protection_data = list(waf_web_engine_protection.objects.filter(user_id=user_id).values())
        waf_web_rule_protection_data = list(waf_web_rule_protection.objects.filter(user_id=user_id).values())
        waf_web_white_rule_data = list(waf_web_white_rule.objects.filter(user_id=user_id).values())
        waf_flow_engine_protection_data = list(waf_flow_engine_protection.objects.filter(user_id=user_id).values())
        waf_flow_rule_protection_data = list(waf_flow_rule_protection.objects.filter(user_id=user_id).values())
        waf_flow_white_rule_data = list(waf_flow_white_rule.objects.filter(user_id=user_id).values())
        waf_flow_ip_region_block_data = list(waf_flow_ip_region_block.objects.filter(user_id=user_id).values())
        waf_name_list_data = list(waf_name_list.objects.filter(user_id=user_id).values())
        waf_name_list_item_data = list(waf_name_list_item.objects.filter(user_id=user_id).values())
        waf_base_component_data = list(waf_base_component.objects.filter(user_id=user_id).values())
        waf_analysis_component_data = list(waf_analysis_component.objects.filter(user_id=user_id).values())
        waf_ssl_manage_data = list(waf_ssl_manage.objects.filter(user_id=user_id).values())
        sys_conf_data = list(sys_conf.objects.filter(user_id=user_id).values())
        waf_scan_attack_protection_data = list(waf_scan_attack_protection.objects.filter(user_id=user_id).values())
        waf_web_page_tamper_proof_data = list(waf_web_page_tamper_proof.objects.filter(user_id=user_id).values())
        waf_flow_black_ip_data = list(waf_flow_black_ip.objects.filter(user_id=user_id).values())
        return_result['waf_domain_data'] = waf_domain_data
        return_result['waf_protection_data'] = waf_protection_data
        return_result['waf_web_engine_protection_data'] = waf_web_engine_protection_data
        return_result['waf_web_rule_protection_data'] = waf_web_rule_protection_data
        return_result['waf_web_white_rule_data'] = waf_web_white_rule_data
        return_result['waf_flow_engine_protection_data'] = waf_flow_engine_protection_data
        return_result['waf_flow_rule_protection_data'] = waf_flow_rule_protection_data
        return_result['waf_flow_white_rule_data'] = waf_flow_white_rule_data
        return_result['waf_flow_ip_region_block_data'] = waf_flow_ip_region_block_data
        return_result['waf_name_list_data'] = waf_name_list_data
        return_result['waf_name_list_item_data'] = waf_name_list_item_data
        return_result['waf_base_component_data'] = waf_base_component_data
        return_result['waf_analysis_component_data'] = waf_analysis_component_data
        return_result['waf_ssl_manage_data'] = waf_ssl_manage_data
        return_result['sys_conf_data'] = sys_conf_data
        return_result['waf_scan_attack_protection_data'] = waf_scan_attack_protection_data
        return_result['waf_web_page_tamper_proof_data'] = waf_web_page_tamper_proof_data
        return_result['waf_flow_black_ip_data'] = waf_flow_black_ip_data

        waf_conf_data = json.dumps(return_result)
        response = HttpResponse(waf_conf_data, content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename="backup_data.json"'
        return response
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_conf_load(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        waf_conf_data = json.loads(request.body)
        waf_domain_data = waf_conf_data['waf_domain_data']
        waf_protection_data = waf_conf_data['waf_protection_data']
        waf_web_engine_protection_data = waf_conf_data['waf_web_engine_protection_data']
        waf_web_rule_protection_data = waf_conf_data['waf_web_rule_protection_data']
        waf_web_white_rule_data = waf_conf_data['waf_web_white_rule_data']
        waf_flow_engine_protection_data = waf_conf_data['waf_flow_engine_protection_data']
        waf_flow_rule_protection_data = waf_conf_data['waf_flow_rule_protection_data']
        waf_flow_white_rule_data = waf_conf_data['waf_flow_white_rule_data']
        waf_flow_ip_region_block_data = waf_conf_data['waf_flow_ip_region_block_data']
        waf_name_list_data = waf_conf_data['waf_name_list_data']
        waf_name_list_item_data = waf_conf_data['waf_name_list_item_data']
        waf_base_component_data = waf_conf_data['waf_base_component_data']
        waf_analysis_component_data = waf_conf_data['waf_analysis_component_data']
        waf_ssl_manage_data = waf_conf_data['waf_ssl_manage_data']
        sys_conf_data = waf_conf_data['sys_conf_data']
        try:
            waf_scan_attack_protection_data = waf_conf_data['waf_scan_attack_protection_data']
            waf_scan_attack_protection.objects.filter(user_id=user_id).delete()
            for data in waf_scan_attack_protection_data:
                waf_scan_attack_protection.objects.create(
                    user_id=user_id,
                    rule_name=data['rule_name'],
                    rule_detail=data['rule_detail'],
                    rule_module=data['rule_module'],
                    statics_object=data['statics_object'],
                    statics_time=data['statics_time'],
                    statics_count=data['statics_count'],
                    rule_action=data['rule_action'],
                    action_value=data['action_value'],
                    block_time=data['block_time'],
                    status = data['status'],
                    rule_order_time = data['rule_order_time']
                )
            waf_web_page_tamper_proof_data = waf_conf_data['waf_web_page_tamper_proof_data']
            waf_web_page_tamper_proof.objects.filter(user_id=user_id).delete()
            for data in waf_web_page_tamper_proof_data:
                waf_web_page_tamper_proof.objects.create(
                    user_id=user_id,
                    rule_name=data['rule_name'],
                    rule_detail=data['rule_detail'],
                    rule_matchs=data['rule_matchs'],
                    cache_page_url=data['cache_page_url'],
                    cache_content_type=data['cache_content_type'],
                    cache_page_content=data['cache_page_content'],
                    status=data['status'],
                    rule_order_time=data['rule_order_time']
                )
            waf_flow_black_ip_data = waf_conf_data['waf_flow_black_ip_data']

            waf_flow_black_ip.objects.filter(user_id=user_id).delete()
            for data in waf_flow_black_ip_data:
                waf_flow_black_ip.objects.create(
                    user_id=user_id,
                    domain=data['domain'],
                    ip=data['ip'],
                    detail=data['detail'],
                    ip_expire=data['ip_expire'],
                    expire_time=data['expire_time'],
                    block_action=data['block_action'],
                    action_value=data['action_value']
                )
        except:
            pass
        waf_domain.objects.filter(user_id=user_id).delete()
        for data in waf_domain_data:
            waf_domain.objects.create(
                user_id=user_id,
                domain=data['domain'], http=data['http'], https=data['https'], ssl_domain=data['ssl_domain'],
                source_ip=data['source_ip'],
                source_http_port=data['source_http_port'],
                proxy_pass_https=data['proxy_pass_https'],
                advanced_conf=data['advanced_conf'],
                force_https=data['force_https'],
                pre_proxy=data['pre_proxy'],
                real_ip_conf=data['real_ip_conf'],
                white_ip_list=data['white_ip_list']
            )
        waf_protection.objects.filter(user_id=user_id).delete()
        for data in waf_protection_data:
            waf_protection.objects.create(
                user_id=user_id,
                domain=data['domain'],
                web_engine_protection=data['web_engine_protection'],
                web_rule_protection=data['web_rule_protection'],
                web_white_rule=data['web_white_rule'],
                flow_engine_protection=data['flow_engine_protection'],
                flow_rule_protection=data['flow_rule_protection'],
                flow_white_rule=data['flow_white_rule'],
                flow_ip_region_block=data['flow_ip_region_block'],
            )
        waf_web_engine_protection.objects.filter(user_id=user_id).delete()
        for data in waf_web_engine_protection_data:
            waf_web_engine_protection.objects.create(
                user_id=user_id,
                domain=data['domain'],
                sql_check=data['sql_check'],
                xss_check=data['xss_check'],
                cmd_exec_check=data['cmd_exec_check'],
                code_exec_check=data['code_exec_check'],
                webshell_update_check=data['webshell_update_check'],
                sensitive_file_check=data['sensitive_file_check'],
                path_traversal_check=data['path_traversal_check'],
                high_nday_check=data['high_nday_check']
            )
        waf_web_rule_protection.objects.filter(user_id=user_id).delete()
        for data in waf_web_rule_protection_data:
            waf_web_rule_protection.objects.create(
                user_id=user_id,
                domain=data['domain'],
                rule_name=data['rule_name'],
                rule_detail=data['rule_detail'],
                rule_matchs=data['rule_matchs'],
                rule_action=data['rule_action'],
                action_value=data['action_value'],
                status=data['status'],
                rule_order_time=data['rule_order_time']
            )
        waf_web_white_rule.objects.filter(user_id=user_id).delete()
        for data in waf_web_white_rule_data:
            waf_web_white_rule.objects.create(
                user_id=user_id,
                domain=data['domain'],
                rule_name=data['rule_name'],
                rule_detail=data['rule_detail'],
                rule_matchs=data['rule_matchs'],
                rule_action=data['rule_action'],
                action_value=data['action_value'],
                status=data['status'],
                rule_order_time=data['rule_order_time']
            )
        waf_flow_engine_protection.objects.filter(user_id=user_id).delete()
        for data in waf_flow_engine_protection_data:
            if 'req_count_block_time' in data:
                waf_flow_engine_protection.objects.create(
                    user_id=user_id,
                    domain=data['domain'],
                    high_freq_cc_check=data['high_freq_cc_check'],
                    req_count=data['req_count'],
                    req_count_stat_time_period=data['req_count_stat_time_period'],
                    req_count_block_mode=data['req_count_block_mode'],
                    req_count_block_mode_extra_parameter=data['req_count_block_mode_extra_parameter'],
                    req_count_block_time = data['req_count_block_time'],
                    req_rate=data['req_rate'],
                    req_rate_block_mode=data['req_rate_block_mode'],
                    req_rate_block_mode_extra_parameter=data['req_rate_block_mode_extra_parameter'],
                    req_rate_block_time=data['req_rate_block_time'],
                    slow_cc_check=data['slow_cc_check'],
                    domain_rate=data['domain_rate'],
                    slow_cc_block_mode=data['slow_cc_block_mode'],
                    slow_cc_block_mode_extra_parameter=data['slow_cc_block_mode_extra_parameter'],
                    ip_count=data['ip_count'],
                    ip_count_stat_time_period=data['ip_count_stat_time_period'],
                    ip_count_block_mode=data['ip_count_block_mode'],
                    ip_count_block_mode_extra_parameter=data['ip_count_block_mode_extra_parameter'],
                    emergency_mode_check=data['emergency_mode_check'],
                    emergency_mode_block_mode=data['emergency_mode_block_mode'],
                    emergency_mode_block_mode_extra_parameter=data['emergency_mode_block_mode_extra_parameter']
                )
        waf_flow_rule_protection.objects.filter(user_id=user_id).delete()
        for data in waf_flow_rule_protection_data:
            if 'filter' in data:
                waf_flow_rule_protection.objects.create(
                    user_id=user_id,
                    domain=data['domain'],
                    rule_name=data['rule_name'],
                    rule_detail=data['rule_detail'],
                    rule_matchs=data['rule_matchs'],
                    rule_action=data['rule_action'],
                    action_value=data['action_value'],
                    status=data['status'],
                    rule_order_time=data['rule_order_time']
                )
        waf_flow_white_rule.objects.filter(user_id=user_id).delete()
        for data in waf_flow_white_rule_data:
            waf_flow_white_rule.objects.create(
                user_id=user_id,
                domain=data['domain'],
                rule_name=data['rule_name'],
                rule_detail=data['rule_detail'],
                rule_matchs=data['rule_matchs'],
                rule_action=data['rule_action'],
                action_value=data['action_value'],
                status=data['status'],
                rule_order_time=data['rule_order_time']
            )
        waf_flow_ip_region_block.objects.filter(user_id=user_id).delete()
        for data in waf_flow_ip_region_block_data:
            waf_flow_ip_region_block.objects.create(
                user_id=user_id,
                domain=data['domain'],
                ip_region_block=data['ip_region_block'],
                region_white_list=data['region_white_list'],
                block_action=data['block_action'],
                action_value=data['action_value']
            )
        waf_name_list.objects.filter(user_id=user_id).delete()
        for data in waf_name_list_data:
            waf_name_list.objects.create(
                user_id=user_id,
                name_list_name=data['name_list_name'],
                name_list_detail=data['name_list_detail'],
                name_list_rule=data['name_list_rule'],
                name_list_action=data['name_list_action'],
                name_list_expire=data['name_list_expire'],
                name_list_expire_time=data['name_list_expire_time'],
                action_value=data['action_value'],
                order_time=data['order_time'],
                status=data['status']
            )
        waf_name_list_item.objects.filter(user_id=user_id).delete()
        for data in waf_name_list_item_data:
            waf_name_list_item.objects.create(
                user_id=user_id,
                name_list_name=data['name_list_name'],
                name_list_item=data['name_list_item'],
                name_list_expire=data['name_list_expire'],
                name_list_item_expire_time=data['name_list_item_expire_time']
            )
        waf_base_component.objects.filter(user_id=user_id).delete()
        for data in waf_base_component_data:
            waf_base_component.objects.create(
                user_id=user_id,
                name=data['name'],
                detail=data['detail'],
                code=data['code'],
                conf=data['conf'],
                order_time=data['order_time'],
                status=data['status']
            )
        waf_analysis_component.objects.filter(user_id=user_id).delete()
        for data in waf_analysis_component_data:
            waf_analysis_component.objects.create(
                user_id=user_id,
                name=data['name'],
                detail=data['detail'],
                code=data['code'],
                conf=data['conf'],
                order_time=data['order_time'],
                status=data['status']
            )
        waf_ssl_manage.objects.filter(user_id=user_id).delete()
        for data in waf_ssl_manage_data:
            waf_ssl_manage.objects.create(
                user_id=user_id,
                ssl_domain=data['ssl_domain'],
                detail=data['detail'],
                private_key=data['private_key'],
                public_key=data['public_key'],
                update_time=data['update_time']
            )
        sys_conf.objects.filter(user_id=user_id).delete()
        for data in sys_conf_data:
            sys_conf.objects.create(
                user_id=user_id,
                log_conf_local_debug=data['log_conf_local_debug'],
                log_conf_remote=data['log_conf_remote'],
                log_ip=data['log_ip'],
                log_port=data['log_port'],
                log_response=data['log_response'],
                log_all=data['log_all'],
                report_conf=data['report_conf'],
                report_conf_ch_host=data['report_conf_ch_host'],
                report_conf_ch_port=data['report_conf_ch_port'],
                report_conf_ch_user=data['report_conf_ch_user'],
                report_conf_ch_password=data['report_conf_ch_password'],
                report_conf_ch_database=data['report_conf_ch_database'],
                custom_deny_page=data['custom_deny_page'],
                waf_deny_code=data['waf_deny_code'],
                waf_deny_html=data['waf_deny_html'],
            )
        return_result['result'] = True
        return_result['message'] = 'load_success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['errCode'] = 504
        return_result['message'] = str(e)
        return_result['detail'] = str(traceback.format_exc())
        return JsonResponse(return_result, safe=False)
