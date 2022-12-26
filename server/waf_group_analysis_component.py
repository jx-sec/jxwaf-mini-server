from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q
import time
import traceback


def waf_get_group_analysis_component_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        waf_group_analysis_component_results = waf_group_analysis_component.objects.filter(user_id=user_id).filter(
            group_id=group_id).order_by('order_time')
        for result in waf_group_analysis_component_results:
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


def waf_del_group_analysis_component(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        uuid = json_data['uuid']
        try:
            waf_group_analysis_component.objects.filter(user_id=user_id).filter(group_id=group_id).filter(
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


def waf_load_group_analysis_component(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        uuid = json_data['uuid']
        try:
            result = sys_component_protection.objects.get(Q(user_id=user_id) & Q(uuid=uuid))
            waf_group_analysis_component.objects.create(user_id=user_id, group_id=group_id, uuid=uuid,
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


def waf_edit_group_analysis_component_status(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        uuid = json_data['uuid']
        status = json_data['status']
        try:
            waf_group_analysis_component.objects.filter(group_id=group_id).filter(user_id=user_id).filter(
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


def waf_edit_group_analysis_component_conf(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        uuid = json_data['uuid']
        conf = json_data['conf']
        try:
            json_conf = json.loads(conf)
        except:
            return_result['result'] = False
            return_result['message'] = "json error"
            return JsonResponse(return_result, safe=False)
        try:
            waf_group_analysis_component.objects.filter(group_id=group_id).filter(user_id=user_id).filter(
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


def waf_exchange_group_analysis_component_priority(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        group_id = json_data['group_id']
        type = json_data['type']
        if type == "top":
            uuid = json_data['uuid']
            waf_group_analysis_component_results = waf_group_analysis_component.objects.filter(group_id=group_id).filter(
                user_id=user_id).order_by('order_time')
            waf_group_analysis_component_result = waf_group_analysis_component_results[0]
            waf_group_analysis_component.objects.filter(group_id=group_id).filter(user_id=user_id).filter(
                uuid=uuid).update(
                order_time=int(waf_group_analysis_component_result.order_time) - 1)
        elif type == "exchange":
            uuid = json_data['uuid']
            exchange_uuid = json_data['exchange_uuid']
            waf_group_analysis_component_result = waf_group_analysis_component.objects.get(
                Q(group_id=group_id) & Q(user_id=user_id) & Q(uuid=uuid))
            exchange_group_waf_analysis_component_result = waf_group_analysis_component.objects.get(
                Q(group_id=group_id) & Q(user_id=user_id) & Q(uuid=exchange_uuid))
            waf_group_analysis_component.objects.filter(group_id=group_id).filter(user_id=user_id).filter(
                uuid=waf_group_analysis_component_result.uuid).update(
                order_time=exchange_group_waf_analysis_component_result.order_time)
            waf_group_analysis_component.objects.filter(group_id=group_id).filter(user_id=user_id).filter(
                uuid=exchange_group_waf_analysis_component_result.uuid).update(
                order_time=waf_group_analysis_component_result.order_time)
        return_result['result'] = True
        return_result['message'] = 'exchange priority success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)