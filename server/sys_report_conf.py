# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
import hashlib
from DjangoCaptcha import Captcha
import sys
from django.conf import settings
import requests
import traceback
import time

reload(sys)
sys.setdefaultencoding('utf8')

from django.http import JsonResponse
import json
from server.models import *
from django.db.models import Q


def waf_edit_sys_report_conf(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        log_source = json_data['log_source']
        cls_SecretId = json_data['cls_SecretId']
        cls_SecretKey = json_data['cls_SecretKey']
        cls_Region = json_data['cls_Region']
        cls_TopicId = json_data['cls_TopicId']
        sls_AccessKey_ID = json_data['sls_AccessKey_ID']
        sls_AccessKey_Secret = json_data['sls_AccessKey_Secret']
        sls_endpoint = json_data['sls_endpoint']
        sls_project = json_data['sls_project']
        sls_logstore = json_data['sls_logstore']
        sys_report_conf.objects.filter(user_id=user_id).update(
            log_source=log_source,
            cls_SecretId=cls_SecretId, cls_SecretKey=cls_SecretKey, cls_Region=cls_Region, cls_TopicId=cls_TopicId,
            sls_AccessKey_ID=sls_AccessKey_ID, sls_AccessKey_Secret=sls_AccessKey_Secret, sls_endpoint=sls_endpoint,
            sls_project=sls_project, sls_logstore=sls_logstore)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_report_conf(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        try:
            sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        except:
            sys_report_conf.objects.create(user_id=user_id)
            sys_report_conf_result = sys_report_conf.objects.get(user_id=user_id)
        data['log_source'] = sys_report_conf_result.log_source
        data['cls_SecretId'] = sys_report_conf_result.cls_SecretId
        data['cls_SecretKey'] = sys_report_conf_result.cls_SecretKey
        data['cls_Region'] = sys_report_conf_result.cls_Region
        data['cls_TopicId'] = sys_report_conf_result.cls_TopicId
        data['sls_AccessKey_ID'] = sys_report_conf_result.sls_AccessKey_ID
        data['sls_AccessKey_Secret'] = sys_report_conf_result.sls_AccessKey_Secret
        data['sls_endpoint'] = sys_report_conf_result.sls_endpoint
        data['sls_project'] = sys_report_conf_result.sls_project
        data['sls_logstore'] = sys_report_conf_result.sls_logstore
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)
