# -*- coding:utf-8 –*-
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
import time
from django.http import JsonResponse
import json


def cls_query(SecretId, SecretKey, cls_Region, cls_TopicId, From, To, query):
    try:
        from tencentcloud.cls.v20201016 import cls_client, models
        cred = credential.Credential(SecretId, SecretKey)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cls.tencentcloudapi.com"
        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = cls_client.ClsClient(cred, cls_Region, clientProfile)
        req = models.SearchLogRequest()
        params = {
            "TopicId": cls_TopicId,
            "From": From * 1000,
            "To": To * 1000,  # 1660720162000
            "Query": query
        }
        req.from_json_string(json.dumps(params))
        resp = client.SearchLog(req)
        return True, json.loads(resp.to_json_string())
    except TencentCloudSDKException as err:
        return False, err


from server.models import *


def cls_report_get_raw_log(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        sql_query = json_data['sql_query']
        sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        cls_SecretId = sys_report_conf_result.cls_SecretId
        cls_SecretKey = sys_report_conf_result.cls_SecretKey
        cls_Region = sys_report_conf_result.cls_Region
        cls_TopicId = sys_report_conf_result.cls_TopicId
        cls_result, cls_message = cls_query(cls_SecretId, cls_SecretKey, cls_Region, cls_TopicId, int(from_time),
                                            int(to_time),
                                            sql_query)
        if cls_result == True:
            return_result['result'] = True
            return_result['message'] = cls_message
            return JsonResponse(return_result, safe=False)
        else:
            return_result['result'] = False
            return_result['message'] = cls_message
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
