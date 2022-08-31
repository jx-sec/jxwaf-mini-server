from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import time
import traceback


def waf_get_component_protection_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        waf_component_protection_results = waf_component_protection.objects.filter(user_id=user_id).filter(
            domain=domain).order_by('order_time')
        for result in waf_component_protection_results:
            sys_component_protection_result = sys_component_protection.objects.get(
                Q(user_id=user_id) & Q(uuid=result.uuid))
            data.append({'uuid': result.uuid,
                         'name': sys_component_protection_result.name,
                         'conf': result.conf,
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


def waf_del_component_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        uuid = json_data['uuid']
        try:
            waf_component_protection.objects.filter(user_id=user_id).filter(domain=domain).filter(
                uuid=uuid).delete()
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


def waf_load_component_protection(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        uuid = json_data['uuid']
        try:
            result = sys_component_protection.objects.get(Q(user_id=user_id) & Q(uuid=uuid))
            waf_component_protection.objects.create(user_id=user_id, domain=domain, uuid=uuid,
                                                    order_time=int(time.time()), conf=result.demo_conf, status='false')
            return_result['result'] = True
            return_result['message'] = 'load success'
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


def waf_edit_component_protection_status(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        uuid = json_data['uuid']
        status = json_data['status']
        try:
            waf_component_protection.objects.filter(domain=domain).filter(user_id=user_id).filter(
                uuid=uuid).update(status=status)
            return_result['result'] = True
            return_result['message'] = 'edit success'
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


def waf_edit_component_protection_conf(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        uuid = json_data['uuid']
        conf = json_data['conf']
        try:
            json_conf = json.loads(conf)
        except:
            return_result['result'] = False
            return_result['message'] = "json error"
            return JsonResponse(return_result, safe=False)
        try:
            waf_component_protection.objects.filter(domain=domain).filter(user_id=user_id).filter(
                uuid=uuid).update(conf=json.dumps(json_conf))
            return_result['result'] = True
            return_result['message'] = 'edit success'
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


def waf_exchange_component_protection_priority(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        type = json_data['type']
        if type == "top":
            uuid = json_data['uuid']
            waf_component_protection_results = waf_component_protection.objects.filter(domain=domain).filter(
                user_id=user_id).order_by('order_time')
            waf_component_protection_result = waf_component_protection_results[0]
            waf_component_protection.objects.filter(domain=domain).filter(user_id=user_id).filter(
                uuid=uuid).update(
                order_time=int(waf_component_protection_result.order_time) - 1)
        elif type == "exchange":
            uuid = json_data['uuid']
            exchange_uuid = json_data['exchange_uuid']
            waf_component_protection_result = waf_component_protection.objects.get(
                Q(domain=domain) & Q(user_id=user_id) & Q(uuid=uuid))
            exchange_waf_component_protection_result = waf_component_protection.objects.get(
                Q(domain=domain) & Q(user_id=user_id) & Q(uuid=exchange_uuid))
            waf_component_protection.objects.filter(domain=domain).filter(user_id=user_id).filter(
                uuid=waf_component_protection_result.uuid).update(
                order_time=exchange_waf_component_protection_result.order_time)
            waf_component_protection.objects.filter(domain=domain).filter(user_id=user_id).filter(
                uuid=exchange_waf_component_protection_result.uuid).update(
                order_time=waf_component_protection_result.order_time)
        return_result['result'] = True
        return_result['message'] = 'exchange priority success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
