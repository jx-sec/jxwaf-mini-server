# -*- coding:utf-8 –*-
from django.http import JsonResponse
import json
from jxwaf.models import *
from django.db.models import Q
import datetime

def waf_get_login_log(request):
    return_result = {}
    data = []
    try:
        user_id = request.session['user_id']
        results = jxwaf_login_log.objects.filter(user_id=user_id).order_by('-time')[:100]
        for result in results:
            data.append({'email': result.email,
                         'status': result.status,
                         'time': result.time.strftime('%Y-%m-%d %H:%M:%S')
                         }
                        )
        return_result['result'] = True
        return_result['message'] = data
        return JsonResponse(return_result, safe=False)
    except Exception, e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['errCode'] = 108
        return JsonResponse(return_result, safe=False)