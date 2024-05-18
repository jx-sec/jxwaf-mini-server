from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_flow_ip_region_block(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        ip_region_block = json_data['ip_region_block']
        region_white_list = json_data['region_white_list']
        block_action = json_data['block_action']
        action_value = json_data['action_value']
        waf_flow_ip_region_block.objects.filter(user_id=user_id).filter(domain=domain).update(
            ip_region_block=ip_region_block,
            region_white_list=json.dumps(region_white_list), block_action=block_action, action_value=action_value)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_flow_ip_region_block(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        domain = json_data['domain']
        try:
            waf_flow_ip_region_block_results = waf_flow_ip_region_block.objects.get(
                Q(domain=domain) & Q(user_id=user_id))
        except:
            waf_flow_ip_region_block.objects.filter(user_id=user_id).filter(domain=domain).delete()
            waf_flow_ip_region_block.objects.create(user_id=user_id, domain=domain)
            waf_flow_ip_region_block_results = waf_flow_ip_region_block.objects.get(
                Q(domain=domain) & Q(user_id=user_id))
        data['ip_region_block'] = waf_flow_ip_region_block_results.ip_region_block
        data['region_white_list'] = json.loads(waf_flow_ip_region_block_results.region_white_list)
        data['block_action'] = waf_flow_ip_region_block_results.block_action
        data['action_value'] = waf_flow_ip_region_block_results.action_value
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
