# -*- coding:utf-8 –*-
import json
from jxwaf.models import *
import datetime
from django.core.mail import send_mail


def monitor_check_server_status():
    waf_global_results = waf_global.objects.filter(monitor="true")
    for waf_global_result in waf_global_results:
        waf_monitor_results = waf_monitor_log.objects.filter(user_id=waf_global_result.user_id).filter(
            waf_monitor_node_status="true").filter(waf_monitor_node_alert="true")
        for waf_monitor_result in waf_monitor_results:
            now = datetime.datetime.now()
            old_time = waf_monitor_result.waf_monitor_node_time
            if (now - old_time).seconds > int(waf_global_result.monitor_alert_period):
                print "time|"
                print now
                print old_time
                waf_monitor_log.objects.filter(user_id=waf_monitor_result.user_id).filter(
                    waf_monitor_node_uuid=waf_monitor_result.waf_monitor_node_uuid).update(
                    waf_monitor_node_status="false")
                user_info = jxwaf_user.objects.get(user_id=waf_global_result.user_id)
                try:
                    send_emails = []
                    send_emails.append(user_info.email)
                    send_message = '[JXWAF]WAF节点异常告警'
                    send_body = '尊敬的用户' + user_info.email + '您好，您的WAF节点' + waf_monitor_result.waf_monitor_node_uuid + '(' + waf_monitor_result.waf_monitor_node_detail + ')已下线，请知悉，详情请登陆控制台查看。'
                    send_mail(send_message, send_body, 'security@jxwaf.com',
                              send_emails, fail_silently=False)
                    print "email|" + send_body
                except Exception, e:
                    print str(e)
