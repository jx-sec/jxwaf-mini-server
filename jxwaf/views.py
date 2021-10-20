# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from jxwaf.models import *
from DjangoCaptcha import Captcha
import hashlib
from django.db.models import Q
from django.core.mail import send_mail
import uuid
import hashlib
import sys
import datetime
import re
import dns.resolver
from django.conf import settings

reload(sys)
sys.setdefaultencoding('utf8')


def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False


def index(request):
    try:
        request.session['user_id']
        return render(request, 'index.html')
    except:
        return render(request, 'login.html')


def login_html(request):
    return render(request, 'login.html')


def regist_html(request):
    return render(request, 'register.html')


def reset_password_html(request):
    return render(request, 'reset_password.html')


def login(request):
    data = {}
    try:
        json_data = json.loads(request.body)
        email = json_data['email']
        password = json_data['password']
        code = json_data['code']
    except Exception, e:
        data['result'] = False
        data['errCode'] = 400
        data['message'] = str(e)
        return JsonResponse(data, safe=False)

    ca = Captcha(request)
    if ca.check(code):
        try:
            result = jxwaf_user.objects.get(email=email)
        except Exception, e:
            data['result'] = False
            data['errCode'] = 403
            data['message'] = str(e)
            return JsonResponse(data, safe=False)
        md5 = hashlib.md5()
        md5.update(password)
        if result.password == md5.hexdigest():
            jxwaf_login_log.objects.create(user_id=result.user_id, email=result.email, status="true")
            request.session['user_id'] = str(result.user_id)
            data['result'] = True
            data['api_key'] = result.user_id
            data['api_password'] = result.api_password
            return JsonResponse(data, safe=False)
        else:
            jxwaf_login_log.objects.create(user_id=result.user_id, email=result.email, status="false")
            data['result'] = False
            data['errCode'] = 4011
            data['message'] = 'password is wrong'
            return JsonResponse(data, safe=False)
    else:
        data['result'] = False
        data['errCode'] = 4012
        data['message'] = 'code is wrong'
        return JsonResponse(data, safe=False)


def regist(request):
    data = {}
    try:
        json_data = json.loads(request.body)
        email = json_data['email']
        password = json_data['password']
    except Exception, e:
        data['result'] = False
        data['errCode'] = 400
        data['message'] = str(e)
        return JsonResponse(data, safe=False)
    # 开启/关闭注册
    if settings.OPEN_REGIST != True:
        data['result'] = False
        data['errCode'] = 403
        data['message'] = 'The registration function is closed, you may not have permission to register'
        return JsonResponse(data, safe=False)
    regist_count = jxwaf_user.objects.all().count()
    if regist_count >= settings.REGIST_COUNT:
        data['result'] = False
        data['errCode'] = 403
        data['message'] = 'Registration number exceeds the limit'
        return JsonResponse(data, safe=False)
    try:
        result = jxwaf_user.objects.get(email=email)
        data['result'] = False
        data['errCode'] = 409
        data['message'] = 'Account already exists'
        return JsonResponse(data, safe=False)
    except:
        md5 = hashlib.md5()
        md5.update(password)
        jxwaf_user.objects.create(email=email, password=md5.hexdigest())
        data['result'] = True
        jxwaf_user.objects.get(email=email)
        return JsonResponse(data, safe=False)


def captcha(request):
    ca = Captcha(request)
    ca.mode = 'four_number'
    ca.img_width = 100
    ca.img_height = 30
    return ca.display()


def logout(request):
    data = {}
    try:
        del request.session['user_id']
        data['result'] = True
        return render(request, 'login.html')
    except:
        data['result'] = False
        data['errCode'] = 504
        data['message'] = 'Operation failed'
        return render(request, 'login.html')


def waf_monitor(request):
    data_result = {}
    data = {}
    try:
        waf_api_key = request.POST['api_key']
        waf_api_password = request.POST['api_password']
        waf_node_uuid = request.POST['waf_node_uuid']
        server_info = request.POST['server_info']
        remote_ip = request.META['REMOTE_ADDR']
    except Exception, e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = str(e)
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(user_id=waf_api_key) & Q(api_password=waf_api_password))
    except:
        data_result['result'] = False
        data_result['errCode'] = 401
        data_result['message'] = "api_key or api_password error"
        return JsonResponse(data_result, safe=False)
    try:
        waf_global_result = waf_global.objects.get(user_id=user_result.user_id)
    except Exception, e:
        data_result['result'] = False
        data_result['errCode'] = 401
        data_result['message'] = str(e)
        return JsonResponse(data_result, safe=False)
    if waf_global_result.monitor == "true":
        try:
            waf_monitor_log.objects.get(Q(user_id=user_result.user_id) & Q(waf_monitor_node_uuid=waf_node_uuid))
            try:
                waf_monitor_log.objects.filter(user_id=user_result.user_id).filter(
                    waf_monitor_node_uuid=waf_node_uuid).update(waf_monitor_node_detail=server_info + '|' + remote_ip,
                                                                waf_monitor_node_time=datetime.datetime.now(),
                                                                waf_monitor_node_status="true")
                data_result['result'] = True
                data_result['waf_node_monitor'] = waf_global_result.monitor
                return JsonResponse(data_result, safe=False)
            except Exception, e:
                data_result['result'] = False
                data_result['errCode'] = 504
                data_result['message'] = str(e)
                return JsonResponse(data_result, safe=False)
        except:
            try:
                waf_monitor_log.objects.create(user_id=user_result.user_id, waf_monitor_node_uuid=waf_node_uuid,
                                               waf_monitor_node_detail=server_info + '|' + remote_ip)
                data_result['result'] = True
                data_result['waf_node_monitor'] = waf_global_result.monitor
                return JsonResponse(data_result, safe=False)
            except Exception, e:
                data_result['result'] = False
                data_result['errCode'] = 504
                data_result['message'] = str(e)
                return JsonResponse(data_result, safe=False)
    data_result['result'] = True
    data_result['waf_node_monitor'] = waf_global_result.monitor
    return JsonResponse(data_result, safe=False)


def waf_update(request):
    data_result = {}
    data = {}
    try:
        waf_api_key = request.POST['api_key']
        waf_api_password = request.POST['api_password']
        waf_md5 = request.POST['md5']
    except Exception, e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = "param error"
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(user_id=waf_api_key) & Q(api_password=waf_api_password))
    except:
        data_result['result'] = False
        data_result['errCode'] = 401
        data_result['message'] = "api_key or api_password error"
        return JsonResponse(data_result, safe=False)
    try:
        waf_domain_results = waf_domain.objects.filter(user_id=user_result.user_id)
        for waf_domain_result in waf_domain_results:
            global_data = {}
            domain_data = {}
            protection_data = {}
            cc_protection_data = {}
            cc_attack_ip_data = {}
            custom_rule_data = []
            owasp_check_data = {}
            page_custom_data = {}
            evil_ip_handle_data = {}
            ip_config_data = {}
            data_mask_data = {}
            data_mask_global_data = {}
            rule_engine_data = []
            check_key_data = {}
            domain_data['domain'] = waf_domain_result.domain
            domain_data['http'] = waf_domain_result.http
            domain_data['https'] = waf_domain_result.https
            if domain_data['https'] == "true":
                domain_data['redirect_https'] = waf_domain_result.redirect_https
                domain_data['private_key'] = waf_domain_result.private_key
                domain_data['public_key'] = waf_domain_result.public_key
            source_ip = []
            for process_domain in waf_domain_result.source_ip.split(","):
                if isIP(process_domain.strip()):
                    source_ip.append(process_domain.strip())
                else:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 2
                        resolver.lifetime = 2
                        query = resolver.query(process_domain.strip(),'A')
                        for i in query.response.answer:
                            for j in i.items:
                                if j.rdtype == 1:
                                    source_ip.append(j.address)
                    except:
                        data_result['error_domain'] = waf_domain_result.domain
                        source_ip.append(process_domain)
            domain_data['source_ip'] = source_ip
            domain_data['source_http_port'] = waf_domain_result.source_http_port
            domain_data['proxy'] = waf_domain_result.proxy
            domain_data['proxy_pass_https'] = waf_domain_result.proxy_pass_https
            if domain_data['proxy'] == "true":
                domain_data['proxy_ip'] = waf_domain_result.proxy_ip.split(",")
            global_data['domain_set'] = domain_data
            try:
                protection_result = waf_protection.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
            except Exception, e:
                data_result = {}
                data_result['result'] = False
                data_result['errDomain'] = waf_domain_result.domain
                data_result['message'] = str(e)
                return JsonResponse(data_result, safe=False)
            protection_data['owasp_protection'] = protection_result.owasp_protection
            protection_data['cc_protection'] = protection_result.cc_protection
            protection_data['cc_attack_ip_protection'] = protection_result.cc_attack_ip_protection
            protection_data['custom_protection'] = protection_result.custom_protection
            protection_data['page_custom'] = protection_result.page_custom
            protection_data['evil_ip_handle'] = protection_result.evil_ip_handle
            protection_data['ip_config'] = protection_result.ip_config
            protection_data['data_mask'] = protection_result.data_mask
            protection_data['rule_engine'] = protection_result.rule_engine
            global_data['protection_set'] = protection_data
            if protection_data['page_custom'] == "true":
                waf_page_custom_result = waf_page_custom.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                page_custom_data['owasp_code'] = waf_page_custom_result.owasp_code
                page_custom_data['owasp_html'] = waf_page_custom_result.owasp_html
                global_data['page_custom_set'] = page_custom_data
            if protection_data['cc_protection'] == "true":
                waf_cc_protection_result = waf_cc_protection.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                cc_protection_data['count_check'] = waf_cc_protection_result.count_check
                cc_protection_data['count'] = waf_cc_protection_result.count
                cc_protection_data['black_ip_time'] = waf_cc_protection_result.black_ip_time
                cc_protection_data['req_count_handle_mode'] = waf_cc_protection_result.req_count_handle_mode
                cc_protection_data['qps_check'] = waf_cc_protection_result.qps_check
                cc_protection_data['ip_qps'] = waf_cc_protection_result.ip_qps
                cc_protection_data['ip_expire_qps'] = waf_cc_protection_result.ip_expire_qps
                cc_protection_data['req_freq_handle_mode'] = waf_cc_protection_result.req_freq_handle_mode
                cc_protection_data['domain_qps_check'] = waf_cc_protection_result.domain_qps_check
                cc_protection_data['domain_qps'] = waf_cc_protection_result.domain_qps
                cc_protection_data['domin_qps_handle_mode'] = waf_cc_protection_result.domin_qps_handle_mode
                cc_protection_data['bot_check_mode'] = waf_cc_protection_result.bot_check_mode
                cc_protection_data['emergency_mode_check'] = waf_cc_protection_result.emergency_mode_check
                cc_protection_data['emergency_handle_mode'] = waf_cc_protection_result.emergency_handle_mode
                global_data['cc_protection_set'] = cc_protection_data
            if protection_data['cc_attack_ip_protection'] == "true":
                waf_cc_attack_ip_conf_result = waf_cc_attack_ip_conf.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                cc_block_option = {}
                for tmp_block_option in waf_cc_attack_ip_conf_result.block_option.split(','):
                    cc_block_option[tmp_block_option] = True
                cc_attack_ip_data['block_option'] = cc_block_option
                cc_attack_ip_data['check_period'] = waf_cc_attack_ip_conf_result.check_period
                cc_attack_ip_data['check_count'] = waf_cc_attack_ip_conf_result.check_count
                cc_attack_ip_data['block_time'] = waf_cc_attack_ip_conf_result.block_time
                cc_attack_ip_data['block_mode'] = waf_cc_attack_ip_conf_result.block_mode
                global_data['cc_attack_ip_set'] = cc_attack_ip_data
            if protection_data['custom_protection'] == "true":
                custom_rule_results = waf_custom_rule.objects.filter(user_id=user_result.user_id).filter(
                    domain=waf_domain_result.domain)
                for custom_rule_result in custom_rule_results:
                    custom_rule_data.append(
                        {
                            'rule_id': custom_rule_result.rule_id,
                            'rule_action': custom_rule_result.rule_action,
                            'rule_level': custom_rule_result.rule_level,
                            'rule_log': custom_rule_result.rule_log,
                            'rule_name': custom_rule_result.rule_name,
                            'rule_matchs': json.loads(custom_rule_result.rule_matchs),
                        }
                    )
                global_data['custom_rule_set'] = custom_rule_data
            if protection_data['rule_engine'] == "true":
                rule_engine_results = waf_rule_engine.objects.filter(user_id=user_result.user_id).filter(
                    domain=waf_domain_result.domain).filter(~Q(match_action='close'))
                for rule_engine_result in rule_engine_results:
                    if len(rule_engine_result.flow_filter) == 0:
                        flow_filter_keys = []
                    else:
                        flow_filter_keys = rule_engine_result.flow_filter.split(',')
                    for flow_filter_key in flow_filter_keys:
                        flow_filter_key = unicode.upper(flow_filter_key)
                        if check_key_data.has_key(flow_filter_key):
                            if type(check_key_data[flow_filter_key]) == unicode or type(
                                    check_key_data[flow_filter_key]) == str:
                                tmp_list = []
                                tmp_list.append(check_key_data[flow_filter_key])
                                tmp_list.append(rule_engine_result.rule_name)
                                check_key_data[flow_filter_key] = tmp_list
                            else:
                                tmp_list = check_key_data[flow_filter_key]
                                tmp_list.append(rule_engine_result.rule_name)
                                check_key_data[flow_filter_key] = tmp_list
                        else:
                            check_key_data[flow_filter_key] = rule_engine_result.rule_name

                    check_contents = rule_engine_result.check_content.split(',')
                    check_content_data = {}
                    for check_content in check_contents:
                        check_content_data[check_content] = True
                    if len(rule_engine_result.check_uri) == 0:
                        check_uri = False
                    else:
                        check_uri = rule_engine_result.check_uri
                    if len(rule_engine_result.white_url) == 0:
                        white_url = False
                    else:
                        white_url = rule_engine_result.white_url.split(',')
                    flow_filter_count = 0
                    if len(rule_engine_result.flow_filter) != 0:
                        flow_filter_count = len(rule_engine_result.flow_filter.split(','))
                    rule_engine_data.append(
                        {
                            'rule_name': rule_engine_result.rule_name,
                            'check_uri': check_uri,
                            'flow_filter_count': flow_filter_count,
                            'content_handle': rule_engine_result.content_handle.split(','),
                            'check_content': check_content_data,
                            'content_match': json.loads(rule_engine_result.content_match),
                            'match_action': rule_engine_result.match_action,
                            'white_url': white_url,
                        }
                    )
                global_data['check_key_set'] = check_key_data
                global_data['rule_engine_set'] = rule_engine_data
            if protection_data['owasp_protection'] == "true":
                waf_owasp_check_result = waf_owasp_check.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                owasp_check_data['sql_check'] = waf_owasp_check_result.sql_check
                owasp_check_data['xss_check'] = waf_owasp_check_result.xss_check
                owasp_check_data['command_inject_check'] = waf_owasp_check_result.command_inject_check
                owasp_check_data['directory_traversal_check'] = waf_owasp_check_result.directory_traversal_check
                owasp_check_data['upload_check'] = waf_owasp_check_result.upload_check
                owasp_check_data['upload_check_rule'] = waf_owasp_check_result.upload_check_rule
                owasp_check_data['sensitive_file_check'] = waf_owasp_check_result.sensitive_file_check
                owasp_check_data['code_exec_check'] = waf_owasp_check_result.code_exec_check
                global_data['owasp_check_set'] = owasp_check_data
            if protection_data['evil_ip_handle'] == "true":
                waf_evil_ip_conf_result = waf_evil_ip_conf.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                owasp_block_option = {}
                for tmp_block_option in waf_evil_ip_conf_result.block_option.split(','):
                    owasp_block_option[tmp_block_option] = True
                evil_ip_handle_data['period'] = waf_evil_ip_conf_result.period
                evil_ip_handle_data['count'] = waf_evil_ip_conf_result.count
                evil_ip_handle_data['mode'] = waf_evil_ip_conf_result.mode
                evil_ip_handle_data['handle'] = waf_evil_ip_conf_result.handle
                evil_ip_handle_data['block_option'] = owasp_block_option
                global_data['evil_ip_handle_set'] = evil_ip_handle_data
            if protection_data['ip_config'] == "true":
                ip_config_results = waf_ip_rule.objects.filter(user_id=user_result.user_id).filter(
                    domain=waf_domain_result.domain)
                for ip_config_result in ip_config_results:
                    ip_config_data[ip_config_result.ip] = ip_config_result.rule_action
                global_data['ip_config_set'] = ip_config_data
            if protection_data['data_mask'] == "true":
                data_mask_results = waf_data_mask_rule.objects.filter(user_id=user_result.user_id).filter(
                    domain=waf_domain_result.domain)
                for data_mask_result in data_mask_results:
                    get_data = data_mask_result.get
                    if len(get_data) == 0:
                        get_data = False
                    else:
                        if get_data == '*':
                            get_data = True
                        else:
                            get_data = get_data.split(',')
                    post_data = data_mask_result.post
                    if len(post_data) == 0:
                        post_data = False
                    else:
                        if post_data == '*':
                            post_data = True
                        else:
                            post_data = post_data.split(',')
                    header_data = data_mask_result.header
                    if len(header_data) == 0:
                        header_data = False
                    else:
                        if header_data == '*':
                            header_data = True
                        else:
                            header_data = header_data.split(',')
                    data_mask_data[data_mask_result.uri] = {
                        'get': get_data,
                        'post': post_data,
                        'header': header_data
                    }
                global_data['data_mask_set'] = data_mask_data
                try:
                    data_mask_global_result = waf_data_mask_global.objects.get(
                        Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                except:
                    waf_data_mask_global.objects.create(user_id=user_result.user_id, domain=waf_domain_result.domain)
                    data_mask_global_result = waf_data_mask_global.objects.get(
                        Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                global_get_data = data_mask_global_result.get
                if len(global_get_data) == 0:
                    global_get_data = False
                else:
                    global_get_data = global_get_data.split(',')
                global_post_data = data_mask_global_result.post
                if len(global_post_data) == 0:
                    global_post_data = False
                else:
                    global_post_data = global_post_data.split(',')
                global_header_data = data_mask_global_result.header
                if len(global_header_data) == 0:
                    global_header_data = False
                else:
                    global_header_data = global_header_data.split(',')
                data_mask_global_data['get'] = global_get_data
                data_mask_global_data['post'] = global_post_data
                data_mask_global_data['header'] = global_header_data
                global_data['data_mask_global_set'] = data_mask_global_data
            data[waf_domain_result.domain] = global_data
        data_result['waf_rule'] = data
        global_data_result = waf_global.objects.get(user_id=user_result.user_id)
        log_conf = {}
        log_conf['log_local'] = global_data_result.log_local
        log_conf['log_remote'] = global_data_result.log_remote
        log_conf['log_ip'] = global_data_result.log_ip
        log_conf['log_port'] = global_data_result.log_port
        log_conf['all_request_log'] = global_data_result.all_request_log
        data_result['log_conf'] = log_conf
        jxcheck_result = waf_jxcheck.objects.get(user_id="jxwaf")
        data_result['jxcheck'] = jxcheck_result.jxcheck_code
        botcheck_result = waf_botcheck.objects.get(user_id="jxwaf")
        data_result['botcheck'] = botcheck_result.botcheck_code
        try:
            keycheck_result = waf_keycheck.objects.get(user_id="jxwaf")
            data_result['keycheck'] = keycheck_result.keycheck_code
        except:
            data_result['keycheck'] = ""
        bot_data = {}
        bot_standard_data = {}
        bot_image_data = {}
        bot_slipper_data = {}
        bot_standard_results = waf_cc_bot_html_key.objects.filter(user_id='jxwaf').filter(bot_check_mode='standard')
        bot_image_results = waf_cc_bot_html_key.objects.filter(user_id='jxwaf').filter(bot_check_mode='image')
        bot_slipper_results = waf_cc_bot_html_key.objects.filter(user_id='jxwaf').filter(bot_check_mode='slipper')
        for bot_standard_result in bot_standard_results:
            bot_standard_data[bot_standard_result.uuid] = bot_standard_result.key
        for bot_image_result in bot_image_results:
            bot_image_data[bot_image_result.uuid] = bot_image_result.key
        for bot_slipper_result in bot_slipper_results:
            bot_slipper_data[bot_slipper_result.uuid] = bot_slipper_result.key
        bot_data['standard'] = bot_standard_data
        bot_data['image'] = bot_image_data
        bot_data['slipper'] = bot_slipper_data

        jxwaf_website_default = {}
        try:
            jxwaf_website_default_data = waf_default_config.objects.get(user_id=user_result.user_id)
        except:
            waf_default_config.objects.create(user_id=user_result.user_id, type='false', owasp_code='404',
                                              owasp_html='')
            jxwaf_website_default_data = waf_default_config.objects.get(user_id=user_result.user_id)
        jxwaf_website_default['type'] = jxwaf_website_default_data.type
        jxwaf_website_default['owasp_code'] = jxwaf_website_default_data.owasp_code
        jxwaf_website_default['owasp_html'] = jxwaf_website_default_data.owasp_html
        data_result['jxwaf_website_default'] = jxwaf_website_default

        data_result['bot_auth_key'] = bot_data
        data_result['auto_update'] = global_data_result.auto_update
        data_result['auto_update_period'] = global_data_result.auto_update_period
        result_md5 = hashlib.md5()
        result_md5.update(json.dumps(data_result))
        if waf_md5 == result_md5.hexdigest():
            same_result = {}
            same_result['result'] = True
            same_result['no_update'] = True
            return JsonResponse(same_result, safe=False)
        data_result['md5'] = result_md5.hexdigest()
        data_result['result'] = True
        data_result['message'] = "success load waf rule"
        return JsonResponse(data_result, safe=False)
    except Exception, e:
        data_result = {}
        data_result['result'] = False
        data_result['errCode'] = 504
        data_result['message'] = str(e)
        return JsonResponse(data_result, safe=False)


def waf_update_repair(request):
    data_result = {}
    data = {}
    error_domain = []
    try:
        waf_api_key = request.POST['api_key']
        waf_api_password = request.POST['api_password']
        operator = request.POST['operator']
        if operator != 'check' and operator != 'repair':
            data_result['result'] = False
            data_result['errCode'] = 400
            data_result['message'] = "param error"
            return JsonResponse(data_result, safe=False)
    except Exception, e:
        data_result['result'] = False
        data_result['errCode'] = 400
        data_result['message'] = "param error"
        return JsonResponse(data_result, safe=False)
    try:
        user_result = jxwaf_user.objects.get(Q(user_id=waf_api_key) & Q(api_password=waf_api_password))
    except:
        data_result['result'] = False
        data_result['errCode'] = 401
        data_result['message'] = "api_key or api_password error"
        return JsonResponse(data_result, safe=False)
    try:
        waf_domain_results = waf_domain.objects.filter(user_id=user_result.user_id)
        for waf_domain_result in waf_domain_results:
            source_ip = []
            for process_domain in waf_domain_result.source_ip.split(","):
                if isIP(process_domain.strip()):
                    source_ip.append(process_domain.strip())
                else:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 2
                        resolver.lifetime = 2
                        query = resolver.query(process_domain.strip(),'A')
                        for i in query.response.answer:
                            for j in i.items:
                                if j.rdtype == 1:
                                    source_ip.append(j.address)
                    except:
                        error_domain.append(waf_domain_result.domain)
            try:
                protection_result = waf_protection.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                waf_page_custom_result = waf_page_custom.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                waf_cc_protection_result = waf_cc_protection.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                waf_cc_attack_ip_conf_result = waf_cc_attack_ip_conf.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                waf_owasp_check_result = waf_owasp_check.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
                waf_evil_ip_conf_result = waf_evil_ip_conf.objects.get(
                    Q(user_id=user_result.user_id) & Q(domain=waf_domain_result.domain))
            except Exception, e:
                error_domain.append(waf_domain_result.domain)
        if operator == 'repair':
            for domain in error_domain:
                waf_domain.objects.filter(domain=domain).filter(user_id=user_result.user_id).delete()
                waf_protection.objects.filter(domain=domain).filter(user_id=user_result.user_id).delete()
                waf_cc_protection.objects.filter(domain=domain).filter(user_id=user_result.user_id).delete()
                waf_cc_attack_ip_conf.objects.filter(domain=domain).filter(user_id=user_result.user_id).delete()
                waf_ip_rule.objects.filter(domain=domain).filter(user_id=user_result.user_id).delete()
                waf_evil_ip_conf.objects.filter(domain=domain).filter(user_id=user_result.user_id).delete()
                waf_owasp_check.objects.filter(domain=domain).filter(user_id=user_result.user_id).delete()
                waf_custom_rule.objects.filter(domain=domain).filter(user_id=user_result.user_id).delete()
                waf_page_custom.objects.filter(domain=domain).filter(user_id=user_result.user_id).delete()
        if len(error_domain) == 0:
            data_result['result'] = True
            data_result['message'] = "error_domain count is 0"
        else:
            data_result['result'] = True
            data_result['message'] = "error_domain count is "+str(len(error_domain))
            data_result['error_domain'] = error_domain
        return JsonResponse(data_result, safe=False)
    except Exception, e:
        data_result = {}
        data_result['result'] = False
        data_result['errCode'] = 504
        data_result['message'] = str(e)
        return JsonResponse(data_result, safe=False)
