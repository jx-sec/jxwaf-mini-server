# -*- coding:utf-8 –*-
from __future__ import unicode_literals

from django.db import models
import uuid


# Create your models here.

class jxwaf_user(models.Model):
    user_id = models.CharField(primary_key=True, auto_created=True, default=uuid.uuid4, editable=False, max_length=100)
    user_name = models.CharField(blank=False, max_length=100, unique=True)
    user_password = models.CharField(blank=False, max_length=100, null=False)
    waf_auth = models.CharField(default=uuid.uuid4, editable=True, max_length=100, null=False)

    def __unicode__(self):
        return str(self.user_id)


# domain
class waf_domain(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    http = models.CharField(default="true", max_length=50)
    https = models.CharField(default="false", max_length=50)
    ssl_domain = models.CharField(blank=True, null=True, max_length=1000)
    source_ip = models.CharField(blank=True, max_length=500)
    source_http_port = models.CharField(default="80", max_length=50)
    proxy_pass_https = models.CharField(default="false", max_length=100)
    balance_type = models.CharField(default="round_robin", max_length=100)
    advanced_conf = models.CharField(default="false", max_length=100)
    force_https = models.CharField(default="false", max_length=100)
    pre_proxy = models.CharField(default="false", max_length=100)
    real_ip_conf = models.CharField(default="XRI", max_length=100)  # XRI(X-Real-IP) or XFF(X-Forwarded-For)
    white_ip_list = models.TextField(blank=True, null=True)

    def __unicode__(self):
        return self.user_id


class waf_protection(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    web_engine_protection = models.CharField(default="true", max_length=50)
    web_rule_protection = models.CharField(default="true", max_length=50)
    web_white_rule = models.CharField(default="true", max_length=50)
    scan_attack_protection = models.CharField(default="false", max_length=50)
    web_page_tamper_proof = models.CharField(default="false", max_length=50)
    flow_engine_protection = models.CharField(default="false", max_length=50)
    flow_rule_protection = models.CharField(default="true", max_length=50)
    flow_white_rule = models.CharField(default="true", max_length=50)
    flow_ip_region_block = models.CharField(default="false", max_length=50)
    flow_black_ip = models.CharField(default="false", max_length=50)

    def __unicode__(self):
        return self.user_id


class waf_web_engine_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    sql_check = models.CharField(max_length=100, default="block")
    xss_check = models.CharField(max_length=100, default="block")
    cmd_exec_check = models.CharField(max_length=100, default="block")
    code_exec_check = models.CharField(max_length=100, default="block")
    webshell_update_check = models.CharField(max_length=100, default="block")
    sensitive_file_check = models.CharField(max_length=100, default="block")
    path_traversal_check = models.CharField(max_length=100, default="block")
    high_nday_check = models.CharField(max_length=100, default="block")

    def __unicode__(self):
        return self.user_id


class waf_web_rule_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=1000, default="")
    rule_matchs = models.TextField(null=False)
    rule_action = models.CharField(max_length=1000, default="")
    action_value = models.CharField(max_length=1000, default="")
    status = models.CharField(max_length=1000, default="true")
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return str(self.user_id)


class waf_scan_attack_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=2000, default="")
    rule_module = models.CharField(max_length=1000, default="")
    statics_object = models.CharField(max_length=1000, default="")
    statics_time = models.CharField(max_length=1000, default="")
    statics_count = models.CharField(max_length=1000, default="")
    rule_action = models.CharField(max_length=1000, default="")
    action_value = models.CharField(max_length=1000, default="")
    status = models.CharField(max_length=1000, default="true")
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return str(self.user_id)


class waf_web_page_tamper_proof(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=2000, default="")
    rule_matchs = models.TextField(null=False)
    cache_page_url = models.CharField(max_length=1000, default="")
    cache_content_type = models.CharField(max_length=1000, default="")
    cache_page_content = models.TextField(null=False)
    status = models.CharField(max_length=1000, default="true")
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return str(self.user_id)


class waf_web_white_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=1000, default="")
    rule_matchs = models.TextField(null=False)
    rule_action = models.CharField(max_length=1000, default="")
    action_value = models.CharField(max_length=1000, default="")
    status = models.CharField(max_length=1000, default="true")
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return self.user_id


class waf_flow_engine_protection(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    high_freq_cc_check = models.CharField(default='false', max_length=50)
    req_count = models.CharField(default='6000', max_length=50)
    req_count_stat_time_period = models.CharField(default='60', max_length=50)
    req_count_block_mode = models.CharField(default='block', max_length=50)  # 403 444
    req_count_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    req_count_block_time = models.CharField(default='', max_length=50)
    req_rate = models.CharField(default='100', max_length=50)
    req_rate_block_mode = models.CharField(default='block', max_length=50)
    req_rate_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    req_rate_block_time = models.CharField(default='', max_length=50)
    slow_cc_check = models.CharField(default='false', max_length=50)
    domain_rate = models.CharField(default='1000', max_length=50)
    slow_cc_block_mode = models.CharField(default='block', max_length=50)
    slow_cc_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    ip_count = models.CharField(default='1000', max_length=50)
    ip_count_stat_time_period = models.CharField(default='60', max_length=50)
    ip_count_block_mode = models.CharField(default='block', max_length=50)
    ip_count_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    emergency_mode_check = models.CharField(default='false', max_length=50)
    emergency_mode_block_mode = models.CharField(default='bot_check', max_length=50)  # ignore
    emergency_mode_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)

    def __unicode__(self):
        return self.user_id


class waf_flow_rule_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=1000, default="")
    filter = models.CharField(max_length=1000, default="false")
    rule_matchs = models.TextField(null=False)
    entity = models.TextField(null=False)
    stat_time = models.CharField(max_length=1000, default="")
    exceed_count = models.CharField(max_length=1000, default="")
    rule_action = models.CharField(max_length=1000, default="")
    action_value = models.CharField(max_length=1000, default="")
    status = models.CharField(max_length=1000, default="true")
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return str(self.user_id)

class waf_flow_white_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=1000, default="")
    rule_matchs = models.TextField(null=False)
    rule_action = models.CharField(max_length=1000, default="")
    action_value = models.CharField(max_length=1000, default="")
    status = models.CharField(max_length=1000, default="true")
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return self.user_id


class waf_flow_ip_region_block(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    ip_region_block = models.CharField(default="false", max_length=50)
    region_white_list = models.TextField(blank=True, null=True)
    block_action = models.CharField(null=False, max_length=1000)
    action_value = models.CharField(max_length=1000, default="")

    def __unicode__(self):
        return self.user_id


class waf_flow_black_ip(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    ip = models.CharField(default="", max_length=50)
    detail = models.CharField(default="", max_length=1000)
    ip_expire = models.CharField(default="false", max_length=1000)
    expire_time = models.BigIntegerField(default=0)
    block_action = models.CharField(null=False, max_length=1000)
    action_value = models.CharField(max_length=1000, default="")

    def __unicode__(self):
        return self.user_id


class waf_name_list(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name_list_name = models.CharField(null=False, max_length=1000)
    name_list_detail = models.CharField(null=False, max_length=1000)
    name_list_rule = models.CharField(null=False, max_length=2000)
    name_list_action = models.CharField(null=False, max_length=1000)
    name_list_expire = models.CharField(default="false", max_length=1000)
    name_list_expire_time = models.BigIntegerField(default=0)
    action_value = models.CharField(max_length=1000, default="")
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")


class waf_name_list_item(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name_list_name = models.CharField(null=False, max_length=1000)
    name_list_item = models.CharField(null=False, max_length=2000)
    name_list_expire = models.CharField(default="false", max_length=1000)
    name_list_item_expire_time = models.BigIntegerField(default=0)


class waf_base_component(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name = models.CharField(null=False, max_length=1000)
    detail = models.CharField(null=False, max_length=1000)
    code = models.TextField(blank=True, null=True)
    conf = models.TextField(blank=True, null=True)  # json
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")

    def __unicode__(self):
        return str(self.user_id)


class waf_analysis_component(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name = models.CharField(null=False, max_length=1000)
    detail = models.CharField(null=False, max_length=1000)
    code = models.TextField(blank=True, null=True)
    conf = models.TextField(blank=True, null=True)  # json
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")

    def __unicode__(self):
        return str(self.user_id)


class waf_ssl_manage(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    ssl_domain = models.CharField(null=False, max_length=1000)
    detail = models.CharField(null=False, max_length=2000)
    private_key = models.TextField(blank=True, null=True)
    public_key = models.TextField(blank=True, null=True)
    update_time = models.CharField(null=False, max_length=50)
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")

    def __unicode__(self):
        return str(self.user_id)


class sys_conf(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    log_conf_local_debug = models.CharField(max_length=100, default="false")
    log_conf_remote = models.CharField(max_length=100, default="false")
    log_ip = models.CharField(max_length=100, default="127.0.0.1")
    log_port = models.CharField(max_length=100, default="5555")
    log_response = models.CharField(max_length=100, default="false")
    log_all = models.CharField(max_length=100, default="false")
    report_conf = models.CharField(max_length=100, default="false")
    report_conf_ch_host = models.CharField(max_length=100, default="")
    report_conf_ch_port = models.CharField(max_length=100, default="")
    report_conf_ch_user = models.CharField(max_length=100, default="")
    report_conf_ch_password = models.CharField(max_length=100, default="")
    report_conf_ch_database = models.CharField(max_length=100, default="")
    custom_deny_page = models.CharField(max_length=100, default="false")
    waf_deny_code = models.CharField(default="403", max_length=50)
    waf_deny_html = models.TextField(blank=True, null=True, default="")


class waf_node_monitor(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    node_uuid = models.CharField(max_length=100, default="")
    node_hostname = models.CharField(max_length=1000, default="")
    node_ip = models.CharField(max_length=1000, default="")
    node_status_update_time = models.CharField(max_length=100, default="")
