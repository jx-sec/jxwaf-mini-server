# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *

def ch_report_get_raw_log(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        sql_query = json_data['sql_query']
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        client = Client(host=sys_report_conf_result.ch_host, port=int(sys_report_conf_result.ch_port),
                        user=sys_report_conf_result.ch_user,
                        password=sys_report_conf_result.ch_password, database=sys_report_conf_result.ch_database)
        result = client.execute(sql_query)
        return_result['result'] = True
        return_result['message'] = result
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)