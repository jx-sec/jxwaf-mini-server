from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import time
import traceback


def waf_get_name_list_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        waf_name_list_results = waf_name_list.objects.filter(user_id=user_id).filter(domain=domain).order_by('order_time')
        for result in waf_name_list_results:
            sys_name_list_result = sys_name_list.objects.get(Q(user_id=user_id) & Q(name_list_uuid=result.name_list_uuid) )
            sys_name_list_item_count = sys_name_list_item.objects.filter(user_id=user_id).filter(name_list_uuid=result.name_list_uuid).count()
            data.append({'name_list_uuid': result.name_list_uuid,
                         'name_list_name': sys_name_list_result.name_list_name,
                         'name_list_detail': sys_name_list_result.name_list_detail,
                         'name_list_item_count': sys_name_list_item_count,
                         'status': result.status
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


def waf_del_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        name_list_uuid = json_data['name_list_uuid']
        try:
            waf_name_list.objects.filter(user_id=user_id).filter(domain=domain).filter(
                name_list_uuid=name_list_uuid).delete()
            return_result['result'] = True
            return_result['message'] = 'del success'
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


def waf_load_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        name_list_uuid = json_data['name_list_uuid']
        try:
            waf_name_list.objects.create(user_id=user_id, domain=domain, name_list_uuid=name_list_uuid,order_time=int(time.time()))
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


def waf_edit_name_list(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        name_list_uuid = json_data['name_list_uuid']
        status = json_data['status']
        try:
            waf_name_list.objects.filter(domain=domain).filter(user_id=user_id).filter(
                name_list_uuid=name_list_uuid).update(status=status)
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

def waf_exchange_name_list_priority(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        type = json_data['type']
        if type == "top":
            name_list_uuid = json_data['name_list_uuid']
            waf_name_list_results = waf_name_list.objects.filter(domain=domain).filter(
                user_id=user_id).order_by('order_time')
            waf_name_list_result = waf_name_list_results[0]
            waf_name_list.objects.filter(domain=domain).filter(user_id=user_id).filter(name_list_uuid=name_list_uuid).update(
                order_time=int(waf_name_list_result.order_time) - 1)
        elif type == "exchange":
            name_list_uuid = json_data['name_list_uuid']
            exchange_name_list_uuid = json_data['exchange_name_list_uuid']
            name_list_uuid_result = waf_name_list.objects.get(
                Q(domain=domain) & Q(user_id=user_id) & Q(name_list_uuid=name_list_uuid))
            exchange_name_list_uuid_result = waf_name_list.objects.get(
                Q(domain=domain) & Q(user_id=user_id) & Q(name_list_uuid=exchange_name_list_uuid))
            waf_name_list.objects.filter(domain=domain).filter(user_id=user_id).filter(name_list_uuid=name_list_uuid_result.name_list_uuid).update(
                order_time=exchange_name_list_uuid_result.order_time)
            waf_name_list.objects.filter(domain=domain).filter(user_id=user_id).filter(
                name_list_uuid=exchange_name_list_uuid_result.name_list_uuid).update(order_time=name_list_uuid_result.order_time)
        return_result['result'] = True
        return_result['message'] = 'exchange priority success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
