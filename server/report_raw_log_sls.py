# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from aliyun.log import LogClient
from aliyun.log.getlogsrequest import GetLogsRequest
from server.models import *


def sls_report_get_raw_log(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        sql_query = json_data['sql_query']
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        sls_AccessKey_ID = sys_report_conf_result.sls_AccessKey_ID
        sls_AccessKey_Secret = sys_report_conf_result.sls_AccessKey_Secret
        sls_endpoint = sys_report_conf_result.sls_endpoint.replace('https://', '').replace('http://', '')
        sls_project = sys_report_conf_result.sls_project
        sls_logstore = sys_report_conf_result.sls_logstore
        client = LogClient(sls_endpoint, sls_AccessKey_ID, sls_AccessKey_Secret)
        req = GetLogsRequest(project=sls_project, logstore=sls_logstore, fromTime=int(from_time), toTime=int(to_time), topic='',
                             query=sql_query)
        res = client.get_logs(req)
        return_result['result'] = True
        return_result['message'] = res.get_body()
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
