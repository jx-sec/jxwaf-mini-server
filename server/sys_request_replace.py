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


def waf_get_sys_request_replace_list(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        sys_request_replace_results = sys_request_replace.objects.filter(user_id=user_id)
        for result in sys_request_replace_results:
            data.append({'name': result.name,
                         'detail': result.detail,
                         'get_status': result.get_status,
                         'get_replace_match': result.get_replace_match,
                         'get_replace_data': result.get_replace_data,
                         'header_status': result.header_status,
                         'header_replace_data': result.header_replace_data,
                         'post_status': result.post_status,
                         'post_replace_match': result.post_replace_match,
                         'post_replace_data': result.post_replace_data
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


def waf_edit_sys_request_replace(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        detail = json_data['detail']
        get_status = json_data['get_status']
        get_replace_match = json_data['get_replace_match']
        get_replace_data = json_data['get_replace_data']
        header_status = json_data['header_status']
        header_replace_data = json_data['header_replace_data']
        post_status = json_data['post_status']
        post_replace_match = json_data['post_replace_match']
        post_replace_data = json_data['post_replace_data']
        sys_request_replace.objects.filter(user_id=user_id).filter(name=name).update(
            detail=detail,
            get_status=get_status, get_replace_match=get_replace_match, get_replace_data=get_replace_data,
            header_status=header_status, header_replace_data=header_replace_data,
            post_status=post_status, post_replace_match=post_replace_match, post_replace_data=post_replace_data)
        return_result['result'] = True
        return_result['message'] = 'edit success'
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_get_sys_request_replace(request):
    return_result = {}
    data = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        sys_request_replace_result = sys_request_replace.objects.get(
            Q(name=name) & Q(user_id=user_id))
        data['name'] = sys_request_replace_result.name
        data['detail'] = sys_request_replace_result.detail
        data['get_status'] = sys_request_replace_result.get_status
        data['get_replace_match'] = sys_request_replace_result.get_replace_match
        data['get_replace_data'] = sys_request_replace_result.get_replace_data
        data['header_status'] = sys_request_replace_result.header_status
        data['header_replace_data'] = sys_request_replace_result.header_replace_data
        data['post_status'] = sys_request_replace_result.post_status
        data['post_replace_match'] = sys_request_replace_result.post_replace_match
        data['post_replace_data'] = sys_request_replace_result.post_replace_data
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 400
        return JsonResponse(return_result, safe=False)


def waf_del_sys_request_replace(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        try:
            sys_request_replace.objects.filter(user_id=user_id).filter(name=name).delete()
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


def waf_create_sys_request_replace(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        json_data = json.loads(request.body)
        name = json_data['name']
        detail = json_data['detail']
        get_status = json_data['get_status']
        get_replace_match = json_data['get_replace_match']
        get_replace_data = json_data['get_replace_data']
        header_status = json_data['header_status']
        header_replace_data = json_data['header_replace_data']
        post_status = json_data['post_status']
        post_replace_match = json_data['post_replace_match']
        post_replace_data = json_data['post_replace_data']
        try:
            result = sys_request_replace.objects.create(user_id=user_id, name=name, detail=detail,
                                                                   get_status=get_status,
                                                                   get_replace_match=get_replace_match,
                                                                   get_replace_data=get_replace_data,
                                                                   header_status=header_status,
                                                                   header_replace_data=header_replace_data,
                                                                   post_status=post_status,
                                                                   post_replace_match=post_replace_match,
                                                                   post_replace_data=post_replace_data)
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