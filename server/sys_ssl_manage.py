from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import time


def waf_get_sys_ssl_manage_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        results = sys_ssl_manage.objects.filter(user_id=user_id)
        for result in results:
            waf_domain_count = waf_domain.objects.filter(user_id=user_id).filter(ssl_domain=result.ssl_domain).count()
            waf_group_domain_count = waf_group_domain.objects.filter(user_id=user_id).filter(ssl_domain=result.ssl_domain).count()
            data.append({'ssl_domain': result.ssl_domain,
                         'private_key': result.private_key,
                         'public_key': result.public_key,
                         'update_time': result.update_time,
                         'waf_domain_count': waf_domain_count,
                         'waf_group_domain_count': waf_group_domain_count
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


def waf_del_sys_ssl_manage(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        ssl_domain = json_data['ssl_domain']
        try:
            waf_domain_count = waf_domain.objects.filter(user_id=user_id).filter(ssl_domain=ssl_domain).count()
            waf_group_domain_count = waf_group_domain.objects.filter(user_id=user_id).filter(ssl_domain=ssl_domain).count()
            if waf_domain_count == 0 and  waf_group_domain_count == 0:
                sys_ssl_manage.objects.filter(user_id=user_id).filter(ssl_domain=ssl_domain).delete()
                return_result['result'] = True
                return_result['message'] = 'del success'
                return JsonResponse(return_result, safe=False)
            else:
                return_result['result'] = False
                return_result['message'] = 'del fail,exist domain rely ssl'
                return JsonResponse(return_result, safe=False)
        except:
            return_result['result'] = False
            return_result['message'] = 'del error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_sys_ssl_manage(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        ssl_domain = json_data['ssl_domain']
        private_key = json_data['private_key']
        public_key = json_data['public_key']
        try:
            sys_ssl_manage.objects.filter(user_id=user_id).filter(ssl_domain=ssl_domain).update(
                private_key=private_key, public_key=public_key,
                update_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_create_sys_ssl_manage(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        ssl_domain = json_data['ssl_domain']
        private_key = json_data['private_key']
        public_key = json_data['public_key']
        try:
            result = sys_ssl_manage.objects.filter(user_id=user_id).filter(ssl_domain=ssl_domain)
            if len(result) != 0:
                return_result['result'] = False
                return_result['message'] = 'create error,ssl_domain is exist'
                return JsonResponse(return_result, safe=False)
            sys_ssl_manage.objects.create(user_id=user_id, ssl_domain=ssl_domain,
                                          private_key=private_key, public_key=public_key,update_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            return_result['message'] = 'create success'
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = 'create error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_ssl_manage_search_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        search = json_data['search']
        results = sys_ssl_manage.objects.filter(user_id=user_id).filter(ssl_domain__contains=search)
        for result in results:
            data.append({'ssl_domain': result.ssl_domain,
                         'private_key': result.private_key,
                         'public_key': result.public_key,
                         'update_time': result.update_time
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
