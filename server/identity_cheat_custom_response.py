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


def waf_get_identity_cheat_custom_response_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        identity_cheat_custom_response_results = identity_cheat_custom_response.objects.filter(user_id=user_id)
        for result in identity_cheat_custom_response_results:
            data.append({'name': result.name,
                         'detail': result.detail,
                         'set_return_header_status': result.set_return_header_status,
                         'set_return_header_value': result.set_return_header_value,
                         'return_code': result.return_code,
                         'return_html': result.return_html
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


def waf_edit_identity_cheat_custom_response(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        detail = json_data['detail']
        set_return_header_status = json_data['set_return_header_status']
        set_return_header_value = json_data['set_return_header_value']
        return_code = json_data['return_code']
        return_html = json_data['return_html']
        identity_cheat_custom_response.objects.filter(user_id=user_id).filter(name=name).update(
            set_return_header_status=set_return_header_status,
            set_return_header_value=set_return_header_value, return_code=return_code, return_html=return_html,detail=detail)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_identity_cheat_custom_response(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        identity_cheat_custom_response_result = identity_cheat_custom_response.objects.get(
            Q(name=name) & Q(user_id=user_id))
        data['name'] = identity_cheat_custom_response_result.name
        data['detail'] = identity_cheat_custom_response_result.detail
        data['set_return_header_status'] = identity_cheat_custom_response_result.set_return_header_status
        data['set_return_header_value'] = identity_cheat_custom_response_result.set_return_header_value
        data['return_code'] = identity_cheat_custom_response_result.return_code
        data['return_html'] = identity_cheat_custom_response_result.return_html
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_identity_cheat_custom_response(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        try:
            identity_cheat_custom_response.objects.filter(user_id=user_id).filter(name=name).delete()
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


def waf_create_identity_cheat_custom_response(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        detail = json_data['detail']
        set_return_header_status = json_data['set_return_header_status']
        set_return_header_value = json_data['set_return_header_value']
        return_code = json_data['return_code']
        return_html = json_data['return_html']
        try:
            result = identity_cheat_custom_response.objects.create(user_id=user_id, name=name, detail=detail,
                                                                   set_return_header_status=set_return_header_status,
                                                                   set_return_header_value=set_return_header_value,
                                                                   return_code=return_code, return_html=return_html)
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
