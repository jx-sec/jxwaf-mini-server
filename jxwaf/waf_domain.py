# -*- coding:utf-8 –*-
from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q
from django.core.paginator import Paginator


def waf_get_domain_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        try:
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
                         'owasp_protection': waf_protection_result.owasp_protection,
                         'evil_ip_handle': waf_protection_result.evil_ip_handle,
                         'cc_protection': waf_protection_result.cc_protection,
                         'cc_attack_ip_protection': waf_protection_result.cc_attack_ip_protection,
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return_result['count'] = paginator.count
        return_result['num_pages'] = paginator.num_pages
        return_result['page_range'] = paginator.page_range
        return_result['now_page'] = waf_domain_results.number
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
            waf_domain.objects.get(Q(user_id=user_id) & Q(domain=domain))
            waf_protection.objects.get(Q(user_id=user_id) & Q(domain=domain))
            waf_cc_protection.objects.get(Q(user_id=user_id) & Q(domain=domain))
            waf_cc_attack_ip_conf.objects.get(Q(user_id=user_id) & Q(domain=domain))
            waf_owasp_check.objects.get(Q(user_id=user_id) & Q(domain=domain))
            waf_page_custom.objects.get(Q(user_id=user_id) & Q(domain=domain))
            waf_evil_ip_conf.objects.get(Q(user_id=user_id) & Q(domain=domain))
            waf_domain.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_cc_protection.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_cc_attack_ip_conf.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_ip_rule.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_evil_ip_conf.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_owasp_check.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_custom_rule.objects.filter(domain=domain).filter(user_id=user_id).delete()
            waf_page_custom.objects.filter(domain=domain).filter(user_id=user_id).delete()
            return_result['result'] = True
            return_result['message'] = 'del success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
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
        proxy = json_data['proxy']
        try:
            proxy_pass_https = json_data['proxy_pass_https']
        except:
            proxy_pass_https = "false"
        try:
            proxy_ip = json_data['proxy_ip']
        except:
            proxy_ip = "false"
        if https == 'true':
            public_key = json_data['public_key']
            private_key = json_data['private_key']
            redirect_https = json_data['redirect_https']
        try:
            user = jxwaf_user.objects.get(user_id=user_id)
            result = waf_domain.objects.filter(user_id=user_id).filter(domain=domain)
            if len(result) != 0:
                return_result['result'] = False
                return_result['errCode'] = 409
                return_result['message'] = 'create error,domain is exist'
                return JsonResponse(return_result, safe=False)
            if https == 'true':
                waf_domain.objects.create(user_id=user_id, email=user.email, domain=domain, http=http, https=https,
                                          source_ip=source_ip,
                                          source_http_port=source_http_port,
                                          public_key=public_key, private_key=private_key, redirect_https=redirect_https,
                                          proxy=proxy, proxy_ip=proxy_ip,
                                          proxy_pass_https=proxy_pass_https)
            else:
                waf_domain.objects.create(user_id=user_id, email=user.email, domain=domain, http=http, https=https,
                                          source_ip=source_ip,
                                          source_http_port=source_http_port,
                                          proxy=proxy, proxy_ip=proxy_ip, proxy_pass_https=proxy_pass_https)
            waf_protection.objects.create(user_id=user_id, domain=domain, email=user.email)
            waf_cc_protection.objects.create(user_id=user_id, domain=domain)
            waf_cc_attack_ip_conf.objects.create(user_id=user_id, domain=domain)
            waf_owasp_check.objects.create(user_id=user_id, domain=domain)
            waf_page_custom.objects.create(user_id=user_id, domain=domain)
            waf_evil_ip_conf.objects.create(user_id=user_id, domain=domain)
            return_result['result'] = True
            return_result['message'] = 'create success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
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
        proxy = json_data['proxy']
        try:
            proxy_pass_https = json_data['proxy_pass_https']
        except:
            proxy_pass_https = "false"
        try:
            proxy_ip = json_data['proxy_ip']
        except:
            proxy_ip = "false"
        if https == 'true':
            public_key = json_data['public_key']
            private_key = json_data['private_key']
            redirect_https = json_data['redirect_https']
        try:
            waf_domain.objects.get(Q(domain=domain) & Q(user_id=user_id))
            user = jxwaf_user.objects.get(user_id=user_id)
            if https == 'true':
                waf_domain.objects.filter(domain=domain).filter(user_id=user_id).update(
                    user_id=user_id, email=user.email, http=http, https=https, source_ip=source_ip,
                    source_http_port=source_http_port, public_key=public_key,
                    private_key=private_key, redirect_https=redirect_https, proxy=proxy, proxy_ip=proxy_ip,
                    proxy_pass_https=proxy_pass_https)
            else:
                waf_domain.objects.filter(domain=domain).filter(user_id=user_id).update(
                    user_id=user_id, email=user.email, http=http, https=https,
                    source_ip=source_ip,
                    source_http_port=source_http_port,
                    proxy=proxy, proxy_ip=proxy_ip, proxy_pass_https=proxy_pass_https)
            return_result['result'] = True
            return_result['message'] = 'edit success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
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
        data['redirect_https'] = waf_domain_result.redirect_https
        data['private_key'] = waf_domain_result.private_key
        data['public_key'] = waf_domain_result.public_key
        data['source_ip'] = waf_domain_result.source_ip
        data['source_http_port'] = waf_domain_result.source_http_port
        # data['source_https_port'] = waf_domain_result.source_https_port
        data['proxy'] = waf_domain_result.proxy
        data['proxy_ip'] = waf_domain_result.proxy_ip
        data['proxy_pass_https'] = waf_domain_result.proxy_pass_https
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_copy_domain(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        old_domain = json_data['old_domain']
        new_domain = json_data['new_domain']
        waf_domain_result = waf_domain.objects.get(Q(domain=old_domain) & Q(user_id=user_id))
        try:
            waf_domain.objects.get(Q(domain=new_domain) & Q(user_id=user_id))
            return_result['result'] = False
            return_result['errCode'] = 409
            return_result['message'] = "domain exist"
            return JsonResponse(return_result, safe=False)
        except:
            pass
        if waf_domain_result.https == 'true':
            waf_domain.objects.create(user_id=user_id, email=waf_domain_result.email, domain=new_domain,
                                      http=waf_domain_result.http, https=waf_domain_result.https,
                                      source_ip=waf_domain_result.source_ip,
                                      source_http_port=waf_domain_result.source_http_port,
                                      public_key=waf_domain_result.public_key,
                                      private_key=waf_domain_result.private_key,
                                      redirect_https=waf_domain_result.redirect_https,
                                      proxy=waf_domain_result.proxy, proxy_ip=waf_domain_result.proxy_ip,
                                      proxy_pass_https=waf_domain_result.proxy_pass_https)
        else:
            waf_domain.objects.create(user_id=user_id, email=waf_domain_result.email, domain=new_domain,
                                      http=waf_domain_result.http, https=waf_domain_result.https,
                                      source_ip=waf_domain_result.source_ip,
                                      source_http_port=waf_domain_result.source_http_port,
                                      proxy=waf_domain_result.proxy, proxy_ip=waf_domain_result.proxy_ip,
                                      proxy_pass_https=waf_domain_result.proxy_pass_https)
        waf_protection.objects.create(user_id=user_id, domain=new_domain, email=waf_domain_result.email)
        waf_cc_protection.objects.create(user_id=user_id, domain=new_domain)
        waf_cc_attack_ip_conf.objects.create(user_id=user_id, domain=new_domain)
        waf_owasp_check.objects.create(user_id=user_id, domain=new_domain)
        waf_page_custom.objects.create(user_id=user_id, domain=new_domain)
        waf_evil_ip_conf.objects.create(user_id=user_id, domain=new_domain)
        return_result['result'] = True
        return_result['message'] = "success"
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
