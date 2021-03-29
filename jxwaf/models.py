# -*- coding:utf-8 –*-
from __future__ import unicode_literals
from django.db import models
import uuid
from django.utils import timezone
import datetime


# Create your models here.

class jxwaf_user(models.Model):
    email = models.EmailField(blank=False, max_length=100, unique=True)
    password = models.CharField(blank=False, max_length=40, null=False)
    user_id = models.CharField(primary_key=True, auto_created=True, default=uuid.uuid4, editable=False, max_length=100)
    api_password = models.CharField(default=uuid.uuid4, editable=True, max_length=100, null=False)

    def __unicode__(self):
        return str(self.user_id)


class jxwaf_login_log(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    email = models.EmailField(blank=False, max_length=100)
    status = models.CharField(max_length=100, default="true")
    time = models.DateTimeField(auto_now=True)


class waf_domain(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    email = models.EmailField(blank=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    http = models.CharField(default="true", max_length=50)
    https = models.CharField(default="false", max_length=50)
    redirect_https = models.CharField(default="false", max_length=50)
    private_key = models.TextField(blank=True, null=True)
    public_key = models.TextField(blank=True, null=True)
    source_ip = models.CharField(null=False, max_length=500)
    source_http_port = models.CharField(default="80", max_length=50)
    proxy = models.CharField(default="false", max_length=50)
    proxy_ip = models.CharField(blank=True, max_length=500)
    proxy_pass_https = models.CharField(default="false", max_length=100)

    def __unicode__(self):
        return self.email


class waf_protection(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    email = models.EmailField(blank=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    owasp_protection = models.CharField(default="true", max_length=50)
    cc_protection = models.CharField(default="false", max_length=50)
    cc_attack_ip_protection = models.CharField(default="false", max_length=50)
    custom_protection = models.CharField(default="false", max_length=50)
    page_custom = models.CharField(default="false", max_length=50)
    evil_ip_handle = models.CharField(default="false", max_length=50)
    ip_config = models.CharField(default="false", max_length=50)
    data_mask = models.CharField(default="false", max_length=50)
    rule_engine = models.CharField(default="false", max_length=50)

    def __unicode__(self):
        return self.email

class waf_page_custom(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    owasp_code = models.CharField(default="403", max_length=50)
    owasp_html = models.TextField(blank=True, null=True)

class waf_cc_protection(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    count_check = models.CharField(default='false', max_length=50)
    count = models.CharField(default='600', max_length=50)
    black_ip_time = models.CharField(default='60', max_length=50)
    req_count_handle_mode = models.CharField(default='block', max_length=50)
    qps_check = models.CharField(default='false', max_length=50)
    ip_qps = models.CharField(default='10', max_length=50)
    ip_expire_qps = models.CharField(default='10', max_length=50)
    req_freq_handle_mode = models.CharField(default='block', max_length=50)
    domain_qps_check = models.CharField(default='false', max_length=50)
    domain_qps = models.CharField(default='1000', max_length=50)
    domin_qps_handle_mode = models.CharField(default='bot_check', max_length=50)
    bot_check_mode = models.CharField(default='standard', max_length=50)
    emergency_mode_check = models.CharField(default='false', max_length=50)
    emergency_handle_mode = models.CharField(default='bot_check', max_length=50)
    def __unicode__(self):
        return self.user_id

class waf_cc_attack_ip_conf(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    block_option = models.CharField(default='', max_length=50) #captche slide stand
    check_period = models.CharField(default='300', max_length=50)
    check_count = models.CharField(default='120', max_length=50)
    block_time = models.CharField(default='3600', max_length=50)
    block_mode = models.CharField(default='block', max_length=500)

    def __unicode__(self):
        return self.user_id

class waf_ip_rule(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    ip = models.CharField(default="false", max_length=500)
    rule_action = models.CharField(default="block", max_length=500)
    time = models.DateTimeField(auto_now_add=True)

    def __unicode__(self):
        return self.domain

class waf_evil_ip_conf(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    period  = models.CharField(default='300', max_length=50)
    count = models.CharField(default='60', max_length=50)
    mode = models.CharField(default='black', max_length=50)
    handle = models.CharField(default='none', max_length=50)
    block_option = models.CharField(default='', max_length=500)

    def __unicode__(self):
        return self.domain

class waf_custom_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    rule_id = models.CharField(max_length=100, default="0")
    rule_action = models.CharField(max_length=100)
    rule_level = models.CharField(max_length=100, default="10")
    rule_name = models.CharField(max_length=1000, default="")
    rule_log = models.CharField(max_length=100)
    rule_matchs = models.CharField(max_length=5000)

    def __unicode__(self):
        return self.rule_id


class waf_owasp_check(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    owasp_protection_mode = models.CharField(default="block", max_length=50)
    sql_check = models.CharField(max_length=100, default="block")
    xss_check = models.CharField(max_length=100, default="block")
    command_inject_check = models.CharField(max_length=100, default="block")
    code_exec_check = models.CharField(max_length=100, default="block")
    directory_traversal_check = models.CharField(max_length=100, default="block")
    sensitive_file_check = models.CharField(max_length=100, default="block")
    upload_check = models.CharField(max_length=100, default="close")
    upload_check_rule = models.CharField(max_length=1000, default="(.jpg|.png)$")

class waf_global(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    auto_update = models.CharField(max_length=100, default="true")
    auto_update_period = models.CharField(max_length=100, default="3")
    monitor = models.CharField(max_length=100, default="true")
    monitor_alert_period = models.CharField(max_length=100, default="120")
    log_local = models.CharField(max_length=100, default="true")
    log_remote = models.CharField(max_length=100, default="false")
    log_ip = models.CharField(max_length=100, default="127.0.0.1")
    log_port = models.CharField(max_length=100, default="5555")
    all_request_log = models.CharField(max_length=100, default="false")
    aliyun_access_id = models.CharField(max_length=200, default="false")
    aliyun_access_secret = models.CharField(max_length=200, default="false")
    aliyun_log_endpoint = models.CharField(max_length=200, default="false")
    aliyun_project = models.CharField(max_length=200, default="false")
    aliyun_logstore = models.CharField(max_length=200, default="false")

    def __unicode__(self):
        return self.user_id


class waf_jxcheck(models.Model):
    user_id = models.CharField(null=False, max_length=50, default="1")
    jxcheck_code = models.TextField(blank=True, null=True)
    version= models.CharField(max_length=100, default="null")

    def __unicode__(self):
        return self.user_id


class waf_botcheck(models.Model):
    user_id = models.CharField(null=False, max_length=50, default="1")
    botcheck_code = models.TextField(blank=True, null=True)
    version = models.CharField(max_length=100, default="null")

    def __unicode__(self):
        return self.user_id

class waf_keycheck(models.Model):
    user_id = models.CharField(null=False, max_length=50, default="jxwaf")
    keycheck_code = models.TextField(blank=True, null=True)
    version = models.CharField(max_length=100, default="null")

    def __unicode__(self):
        return self.user_id

class waf_monitor_log(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    waf_monitor_node_uuid = models.CharField(max_length=100, default="")
    waf_monitor_node_detail = models.CharField(max_length=100, default="")
    waf_monitor_node_status = models.CharField(max_length=100, default="true")
    waf_monitor_node_alert = models.CharField(max_length=100, default="true")
    waf_monitor_node_time = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return self.user_id


class waf_cc_bot_html_key(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    uuid = models.CharField(default="false", max_length=50)
    key = models.CharField(default="fals", max_length=50)
    create_time = models.DateTimeField(auto_now_add=True)
    bot_check_mode = models.CharField(default='standard', max_length=50)

    def __unicode__(self):
        return self.user_id

class waf_data_mask_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    uri = models.CharField(max_length=100, default="/")
    header = models.CharField(max_length=100,default="")
    get = models.CharField(max_length=100, default="")
    post = models.CharField(max_length=1000, default="")


    def __unicode__(self):
        return self.user_id

class waf_data_mask_global(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    header = models.CharField(max_length=100,default="")
    get = models.CharField(max_length=100, default="")
    post = models.CharField(max_length=1000, default="")


    def __unicode__(self):
        return self.user_id

class waf_rule_engine(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    rule_name = models.CharField(max_length=1000, default="jxwaf")
    flow_filter = models.CharField(max_length=2000,default="")
    detail = models.CharField(max_length=2000,default="")
    check_uri = models.CharField(max_length=1000,default="")
    check_content = models.CharField(max_length=1000,default="")
    content_handle = models.CharField(max_length=1000,default="")
    content_match = models.CharField(max_length=2000)
    match_action = models.CharField(max_length=1000)
    white_url = models.CharField(max_length=2000,default="")

    def __unicode__(self):
        return self.user_id


class waf_default_config(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    type = models.CharField(default="true", max_length=50)
    owasp_code = models.CharField(null=False, max_length=500, default="404")
    owasp_html = models.CharField(null=False, max_length=500, default="")

    def __unicode__(self):
        return self.email
