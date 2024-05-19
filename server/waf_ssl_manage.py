from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import time


def waf_get_ssl_manage_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        results = waf_ssl_manage.objects.filter(user_id=user_id)
        for result in results:
            domain_count = waf_domain.objects.filter(user_id=user_id).filter(ssl_domain=result.ssl_domain).count()
            if domain_count > 0:
                status = "true"
            else:
                status = "false"
            data.append({'ssl_domain': result.ssl_domain,
                         'detail': result.detail,
                         'update_time': result.update_time,
                         'status': status
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_ssl_manage(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        ssl_domain = json_data['ssl_domain']
        result = waf_ssl_manage.objects.get(Q(user_id=user_id) & Q(ssl_domain=ssl_domain))
        data['ssl_domain'] = result.ssl_domain
        data['private_key'] = result.private_key
        data['public_key'] = result.public_key
        data['detail'] = result.detail
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_ssl_manage(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        ssl_domain = json_data['ssl_domain']
        try:
            domain_count = waf_domain.objects.filter(user_id=user_id).filter(ssl_domain=ssl_domain).count()
            if domain_count == 0:
                waf_ssl_manage.objects.filter(user_id=user_id).filter(ssl_domain=ssl_domain).delete()
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
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_edit_ssl_manage(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        ssl_domain = json_data['ssl_domain']
        private_key = json_data['private_key']
        public_key = json_data['public_key']
        detail = json_data['detail']
        try:
            waf_ssl_manage.objects.filter(user_id=user_id).filter(ssl_domain=ssl_domain).update(
                private_key=private_key, public_key=public_key, detail=detail,
                update_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = 'edit error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_create_ssl_manage(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        ssl_domain = json_data['ssl_domain']
        private_key = json_data['private_key']
        public_key = json_data['public_key']
        detail = json_data['detail']
        try:
            count = waf_ssl_manage.objects.filter(user_id=user_id).filter(ssl_domain=ssl_domain).count()
            if count > 0:
                return_result['result'] = False
                return_result['message'] = 'create error,ssl_domain is exist'
                return JsonResponse(return_result, safe=False)
            waf_ssl_manage.objects.create(user_id=user_id, ssl_domain=ssl_domain,
                                          private_key=private_key, public_key=public_key, detail=detail,
                                          update_time=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
            return_result['message'] = 'create_success'
            return_result['result'] = True
            return JsonResponse(return_result, safe=False)
        except Exception as e:
            return_result['result'] = False
            return_result['message'] = 'create error'
            return_result['errCode'] = 504
            return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
