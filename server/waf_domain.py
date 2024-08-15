# -*- coding:utf-8 –*-
from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
from django.core.paginator import Paginator
import sys
import re
import dns.resolver
import traceback

reload(sys)
sys.setdefaultencoding('utf8')


def isIP(str):
    p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
    if p.match(str):
        return True
    else:
        return False


def validate_ip_list(ip_list):
    # 验证 1.1.1.1 格式
    pattern1 = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    # 验证 1.1.1.1/24 格式
    pattern2 = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
    for ip in str(ip_list).split(','):
        if re.match(pattern1, ip) or re.match(pattern2, ip):
            pass
        else:
            return False
    return True


def ip_check(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        ip = json_data['ip']
        if isIP(ip):
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        else:
            return_result['result'] = False
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_domain_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        try:
            json_data = json.loads(request.body)
            page = json_data['page']
        except:
            page = 1
        waf_domain_results = waf_domain.objects.filter(user_id=user_id)
        paginator = Paginator(waf_domain_results, 50)
        is_error = False
        try:
            waf_domain_results = paginator.page(int(page))
        except:
            is_error = True
            waf_domain_results = paginator.page(1)
        for result in waf_domain_results.object_list:
            try:
                waf_protection_result = waf_protection.objects.get(Q(user_id=user_id) & Q(domain=result.domain))
            except:
                return_result['result'] = False
                return_result['message'] = 'error_domain:' + result.domain
                return JsonResponse(return_result, safe=False)
            data.append({'domain': result.domain,
                         'http': result.http,
                         'https': result.https,
                         'ssl_domain': result.ssl_domain,
                         'source_ip': result.source_ip,
                         'source_http_port': result.source_http_port,
                         'proxy_pass_https': result.proxy_pass_https,
                         'balance_type': result.balance_type,
                         'web_engine_protection': waf_protection_result.web_engine_protection,
                         'web_rule_protection': waf_protection_result.web_rule_protection,
                         'web_white_rule': waf_protection_result.web_white_rule,
                         'flow_engine_protection': waf_protection_result.flow_engine_protection,
                         'flow_rule_protection': waf_protection_result.flow_rule_protection,
                         'flow_white_rule': waf_protection_result.flow_white_rule,
                         'flow_ip_region_block': waf_protection_result.flow_ip_region_block,
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return_result['count'] = paginator.count
        return_result['num_pages'] = paginator.num_pages
        if is_error:
            return_result['now_page'] = 1
        else:
            return_result['now_page'] = waf_domain_results.number
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_domain(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        try:
            waf_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_web_engine_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_web_rule_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_web_white_rule.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_flow_engine_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_flow_rule_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_flow_white_rule.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_flow_ip_region_block.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_domain.objects.filter(domain=domain).filter(user_id=user_id).delete()
            return_result['result'] = True
            return_result['message'] = 'del_success'
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)


def waf_create_domain(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        http = unicode.lower(json_data['http'])
        https = unicode.lower(json_data['https'])
        source_ip = json_data['source_ip']
        source_http_port = json_data['source_http_port']
        proxy_pass_https = json_data['proxy_pass_https']
        balance_type = json_data['balance_type']
        advanced_conf = json_data['advanced_conf']
        force_https = json_data['force_https']
        pre_proxy = json_data['pre_proxy']
        real_ip_conf = json_data['real_ip_conf']
        white_ip_list = json_data['white_ip_list']
        ssl_domain = json_data['ssl_domain']
        try:
            domain_count = waf_domain.objects.filter(user_id=user_id).filter(domain=domain).count()
            if domain_count > 0:
                return_result['result'] = False
                return_result['message'] = 'create error,domain is exist'
                return JsonResponse(return_result, safe=False)
            for process_domain in source_ip.split(","):
                if isIP(process_domain.strip()):
                    pass
                else:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        query = resolver.query(process_domain.strip(), 'A')
                        for i in query.response.answer:
                            for j in i.items:
                                if j.rdtype == 1:
                                    pass
                    except:
                        return_result['result'] = False
                        return_result['message'] = 'edit error,%s dns resolver error' % (process_domain)
                        return JsonResponse(return_result, safe=False)
            #if advanced_conf == 'true' and pre_proxy == 'true':
            #    validate_ip_list_result = validate_ip_list(white_ip_list)
            #    if not validate_ip_list_result:
            #        return_result['result'] = False
            #        return_result['message'] = 'validate_ip_list error'
            #        return JsonResponse(return_result, safe=False)
            waf_domain.objects.create(user_id=user_id, domain=domain, http=http, https=https,
                                      source_ip=source_ip,
                                      source_http_port=source_http_port,
                                      ssl_domain=ssl_domain,
                                      proxy_pass_https=proxy_pass_https,
                                      balance_type=balance_type,
                                      advanced_conf=advanced_conf,
                                      force_https=force_https,
                                      pre_proxy=pre_proxy,
                                      real_ip_conf=real_ip_conf,
                                      white_ip_list=white_ip_list
                                      )
            waf_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_protection.objects.create(user_id=user_id, domain=domain)
            waf_web_engine_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_web_engine_protection.objects.create(user_id=user_id, domain=domain)
            waf_web_rule_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_web_white_rule.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_flow_engine_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_flow_engine_protection.objects.create(user_id=user_id, domain=domain)
            waf_flow_rule_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_flow_white_rule.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_flow_ip_region_block.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_flow_ip_region_block.objects.create(user_id=user_id, domain=domain)
            return_result['result'] = True
            return_result['message'] = 'create success'
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = str(traceback.format_exc())
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_domain(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        http = unicode.lower(json_data['http'])
        https = unicode.lower(json_data['https'])
        source_ip = json_data['source_ip']
        source_http_port = json_data['source_http_port']
        ssl_domain = json_data['ssl_domain']
        proxy_pass_https = json_data['proxy_pass_https']
        balance_type = json_data['balance_type']
        advanced_conf = json_data['advanced_conf']
        force_https = json_data['force_https']
        pre_proxy = json_data['pre_proxy']
        real_ip_conf = json_data['real_ip_conf']
        white_ip_list = json_data['white_ip_list']
        try:
            waf_domain.objects.get(Q(domain=domain) & Q(user_id=user_id))
            for process_domain in source_ip.split(","):
                if isIP(process_domain.strip()):
                    pass
                else:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        query = resolver.query(process_domain.strip(), 'A')
                        for i in query.response.answer:
                            for j in i.items:
                                if j.rdtype == 1:
                                    pass
                    except:
                        return_result['result'] = False
                        return_result['message'] = 'edit error,%s dns resolver error' % (process_domain)
                        return JsonResponse(return_result, safe=False)
            #if advanced_conf == 'true' and pre_proxy == 'true':
            #    validate_ip_list_result = validate_ip_list(white_ip_list)
            #    if not validate_ip_list_result:
            #        return_result['result'] = False
            #        return_result['message'] = 'validate_ip_list error'
            #        return JsonResponse(return_result, safe=False)
            waf_domain.objects.filter(domain=domain).filter(user_id=user_id).update(
                http=http, https=https,
                source_ip=source_ip,
                source_http_port=source_http_port,
                ssl_domain=ssl_domain, proxy_pass_https=proxy_pass_https,
                balance_type=balance_type,
                advanced_conf=advanced_conf,
                force_https=force_https,
                pre_proxy=pre_proxy,
                real_ip_conf=real_ip_conf,
                white_ip_list=white_ip_list)
            return_result['result'] = True
            return_result['message'] = 'edit success'
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)


def waf_get_domain(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        waf_domain_result = waf_domain.objects.get(Q(domain=domain) & Q(user_id=user_id))
        data['domain'] = waf_domain_result.domain
        data['http'] = waf_domain_result.http
        data['https'] = waf_domain_result.https
        data['source_ip'] = waf_domain_result.source_ip
        data['source_http_port'] = waf_domain_result.source_http_port
        data['ssl_domain'] = waf_domain_result.ssl_domain
        data['proxy_pass_https'] = waf_domain_result.proxy_pass_https
        data['balance_type'] = waf_domain_result.balance_type
        data['advanced_conf'] = waf_domain_result.advanced_conf
        data['force_https'] = waf_domain_result.force_https
        data['pre_proxy'] = waf_domain_result.pre_proxy
        data['real_ip_conf'] = waf_domain_result.real_ip_conf
        data['white_ip_list'] = waf_domain_result.white_ip_list
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_domain_search_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        try:
            page = json_data['page']
        except:
            page = 1
        waf_domain_results = waf_domain.objects.filter(user_id=user_id).filter(domain__contains=domain)
        paginator = Paginator(waf_domain_results, 50)
        is_error = False
        try:
            waf_domain_results = paginator.page(int(page))
        except:
            is_error = True
            waf_domain_results = paginator.page(1)
        for result in waf_domain_results.object_list:
            try:
                waf_protection_result = waf_protection.objects.get(Q(user_id=user_id) & Q(domain=result.domain))
            except:
                return_result['result'] = False
                return_result['message'] = 'error_domain:' + result.domain
                return JsonResponse(return_result, safe=False)
            data.append({'domain': result.domain,
                         'http': result.http,
                         'https': result.https,
                         'source_ip': result.source_ip,
                         'source_http_port': result.source_http_port,
                         'proxy_pass_https': result.proxy_pass_https,
                         'balance_type': result.balance_type,
                         'web_engine_protection': waf_protection_result.web_engine_protection,
                         'web_rule_protection': waf_protection_result.web_rule_protection,
                         'web_white_rule': waf_protection_result.web_white_rule,
                         'flow_engine_protection': waf_protection_result.flow_engine_protection,
                         'flow_rule_protection': waf_protection_result.flow_rule_protection,
                         'flow_white_rule': waf_protection_result.flow_white_rule,
                         'flow_ip_region_block': waf_protection_result.flow_ip_region_block
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return_result['count'] = paginator.count
        return_result['num_pages'] = paginator.num_pages
        if is_error:
            return_result['now_page'] = 1
        else:
            return_result['now_page'] = waf_domain_results.number
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
