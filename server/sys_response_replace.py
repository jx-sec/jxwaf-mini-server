# -*- coding:utf-8 –*-
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse
import json
from server.models import *
from django.db.models import Q
import hashlib
from DjangoCaptcha import Captcha
import sys
from django.conf import settings
import requests
import traceback
import time

reload(sys)
sys.setdefaultencoding('utf8')


def waf_get_sys_response_replace_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        sys_response_replace_results = sys_response_replace.objects.filter(user_id=user_id)
        for result in sys_response_replace_results:
            data.append({'name': result.name,
                         'detail': result.detail,
                         'response_header_status': result.response_header_status,
                         'response_header_replace_data': result.response_header_replace_data,
                         'response_data_status': result.response_data_status,
                         'response_data_replace_match': result.response_data_replace_match,
                         'response_data_replace_data': result.response_data_replace_data
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


def waf_edit_sys_response_replace(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        detail = json_data['detail']
        response_header_status = json_data['response_header_status']
        response_header_replace_data = json_data['response_header_replace_data']
        response_data_status = json_data['response_data_status']
        response_data_replace_match = json_data['response_data_replace_match']
        response_data_replace_data = json_data['response_data_replace_data']
        sys_response_replace.objects.filter(user_id=user_id).filter(name=name).update(
            detail=detail,
            response_header_status=response_header_status, response_header_replace_data=response_header_replace_data,
            response_data_status=response_data_status,
            response_data_replace_match=response_data_replace_match,
            response_data_replace_data=response_data_replace_data)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_response_replace(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        sys_response_replace_result = sys_response_replace.objects.get(
            Q(name=name) & Q(user_id=user_id))
        data['name'] = sys_response_replace_result.name
        data['detail'] = sys_response_replace_result.detail
        data['response_header_status'] = sys_response_replace_result.response_header_status
        data['response_header_replace_data'] = sys_response_replace_result.response_header_replace_data
        data['response_data_status'] = sys_response_replace_result.response_data_status
        data['response_data_replace_match'] = sys_response_replace_result.response_data_replace_match
        data['response_data_replace_data'] = sys_response_replace_result.response_data_replace_data
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_sys_response_replace(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        try:
            sys_response_replace.objects.filter(user_id=user_id).filter(name=name).delete()
            return_result['result'] = True
            return_result['message'] = 'del success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(e)
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return JsonResponse(return_result, safe=False)


def waf_create_sys_response_replace(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        detail = json_data['detail']
        response_header_status = json_data['response_header_status']
        response_header_replace_data = json_data['response_header_replace_data']
        response_data_status = json_data['response_data_status']
        response_data_replace_match = json_data['response_data_replace_match']
        response_data_replace_data = json_data['response_data_replace_data']
        try:
            result = sys_response_replace.objects.create(user_id=user_id, name=name, detail=detail,
                                                                    response_header_status=response_header_status,
                                                                    response_header_replace_data=response_header_replace_data,
                                                                    response_data_status=response_data_status,
                                                                    response_data_replace_match=response_data_replace_match,
                                                                    response_data_replace_data=response_data_replace_data)
            return_result['result'] = True
            return_result['message'] = 'create success'
            return JsonResponse(return_result, safe=False)
        except Exception, e:
            return_result['result'] = False
            return_result['message'] = str(traceback.format_exc())
            return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(traceback.format_exc())
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)