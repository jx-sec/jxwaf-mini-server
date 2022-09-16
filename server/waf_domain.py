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
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)

def waf_get_domain_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        waf_domain_results = waf_domain.objects.filter(user_id=user_id)
        for result in waf_domain_results:
            try:
                waf_protection_result = waf_protection.objects.get(Q(user_id=user_id) & Q(domain=result.domain))
            except:
                return_result['result'] = True
                return_result['message'] = data
                return JsonResponse(return_result, safe=False)
            data.append({'domain': result.domain,
                         'http': result.http,
                         'https': result.https,
                         'web_engine_protection': waf_protection_result.web_engine_protection,
                         'web_rule_protection': waf_protection_result.web_rule_protection,
                         'flow_engine_protection': waf_protection_result.flow_engine_protection,
                         'flow_rule_protection': waf_protection_result.flow_rule_protection,
                         'name_list': waf_protection_result.name_list,
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
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
            waf_domain.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_web_engine_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_web_rule_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_web_white_rule.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_web_deny_page.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_flow_engine_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_flow_rule_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_flow_white_rule.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_flow_deny_page.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_name_list.objects.filter(domain=domain).filter(user_id=user_id).delete()
            return_result['result'] = True
            return_result['message'] = 'del success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return JsonResponse(return_result, safe=False)
    except Exception, e:
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
        ssl_source = json_data['ssl_source']
        ssl_domain = json_data['ssl_domain']
        proxy_pass_https = json_data['proxy_pass_https']
        if https == 'true':
            public_key = json_data['public_key']
            private_key = json_data['private_key']
            redirect_https = "false"
        try:
            result = waf_domain.objects.filter(user_id=user_id).filter(domain=domain)
            if len(result) != 0:
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
                        resolver.lifetime = 3
                        query = resolver.query(process_domain.strip(), 'A')
                        for i in query.response.answer:
                            for j in i.items:
                                if j.rdtype == 1:
                                    pass
                    except:
                        source_ip.append(process_domain)
                        return_result['result'] = False
                        return_result['message'] = 'edit error,%s dns resolver error' % (process_domain)
                        return JsonResponse(return_result, safe=False)
            if https == 'true':
                waf_domain.objects.create(user_id=user_id, domain=domain, http=http, https=https,
                                          source_ip=source_ip,
                                          source_http_port=source_http_port,
                                          public_key=public_key, private_key=private_key,
                                          redirect_https=redirect_https,
                                          ssl_source=ssl_source, ssl_domain=ssl_domain,
                                          proxy_pass_https=proxy_pass_https)
            else:
                waf_domain.objects.create(user_id=user_id, domain=domain, http=http, https=https,
                                          source_ip=source_ip,
                                          source_http_port=source_http_port,
                                          ssl_source=ssl_source, ssl_domain=ssl_domain,
                                          proxy_pass_https=proxy_pass_https)
            waf_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_protection.objects.create(user_id=user_id, domain=domain)
            waf_web_engine_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_web_engine_protection.objects.create(user_id=user_id, domain=domain)
            waf_flow_engine_protection.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_flow_engine_protection.objects.create(user_id=user_id, domain=domain)
            return_result['result'] = True
            return_result['message'] = 'create success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(traceback.format_exc())
            return JsonResponse(return_result, safe=False)
    except Exception, e:
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
        ssl_source = json_data['ssl_source']
        ssl_domain = json_data['ssl_domain']
        proxy_pass_https = json_data['proxy_pass_https']
        if https == 'true':
            public_key = json_data['public_key']
            private_key = json_data['private_key']
            redirect_https = "false"
        try:
            waf_domain.objects.get(Q(domain=domain) & Q(user_id=user_id))
            for process_domain in source_ip.split(","):
                if isIP(process_domain.strip()):
                    pass
                else:
                    try:
                        resolver = dns.resolver.Resolver()
                        resolver.timeout = 3
                        resolver.lifetime = 3
                        query = resolver.query(process_domain.strip(), 'A')
                        for i in query.response.answer:
                            for j in i.items:
                                if j.rdtype == 1:
                                    pass
                    except:
                        source_ip.append(process_domain)
                        return_result['result'] = False
                        return_result['message'] = 'edit error,%s dns resolver error' % (process_domain)
                        return JsonResponse(return_result, safe=False)
            if https == 'true':
                waf_domain.objects.filter(domain=domain).filter(user_id=user_id).update(
                    http=http, https=https, source_ip=source_ip,
                    source_http_port=source_http_port, public_key=public_key,
                    private_key=private_key, redirect_https=redirect_https, ssl_source=ssl_source,
                    ssl_domain=ssl_domain,
                    proxy_pass_https=proxy_pass_https)
            else:
                waf_domain.objects.filter(domain=domain).filter(user_id=user_id).update(
                    http=http, https=https,
                    source_ip=source_ip,
                    source_http_port=source_http_port,
                    ssl_source=ssl_source, ssl_domain=ssl_domain, proxy_pass_https=proxy_pass_https)
            return_result['result'] = True
            return_result['message'] = 'edit success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return JsonResponse(return_result, safe=False)
    except Exception, e:
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
        waf_defense_domain_result = waf_domain.objects.get(Q(domain=domain) & Q(user_id=user_id))
        data['domain'] = waf_defense_domain_result.domain
        data['http'] = waf_defense_domain_result.http
        data['https'] = waf_defense_domain_result.https
        data['redirect_https'] = waf_defense_domain_result.redirect_https
        data['private_key'] = waf_defense_domain_result.private_key
        data['public_key'] = waf_defense_domain_result.public_key
        data['source_ip'] = waf_defense_domain_result.source_ip
        data['source_http_port'] = waf_defense_domain_result.source_http_port
        data['ssl_source'] = waf_defense_domain_result.ssl_source
        data['ssl_domain'] = waf_defense_domain_result.ssl_domain
        data['proxy_pass_https'] = waf_defense_domain_result.proxy_pass_https
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_domain_search_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        try:
            json_data = json.loads(request.body)
            page = json_data['page']
        except:
            page = 1
        results = waf_domain.objects.filter(user_id=user_id)
        paginator = Paginator(results, 50)
        waf_domain_results = paginator.page(page)
        for result in waf_domain_results.object_list:
            try:
                waf_protection_result = waf_protection.objects.get(Q(user_id=user_id) & Q(domain=result.domain))
            except:
                return_result['result'] = True
                return_result['message'] = data
                return JsonResponse(return_result, safe=False)
            data.append({'domain': result.domain,
                         'http': result.http,
                         'https': result.https,
                         'web_engine_protection': waf_protection_result.web_engine_protection,
                         'web_rule_protection': waf_protection_result.web_rule_protection,
                         'flow_engine_protection': waf_protection_result.flow_engine_protection,
                         'flow_rule_protection': waf_protection_result.flow_rule_protection,
                         'name_list': waf_protection_result.name_list,
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return_result['count'] = paginator.count
        return_result['num_pages'] = paginator.num_pages
        return_result['now_page'] = waf_domain_results.number
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
