# -*- coding:utf-8 –*-
from __future__ import unicode_literals

from django.db import models
import uuid


# Create your models here.

class jxwaf_user(models.Model):
    user_name = models.CharField(blank=False, max_length=100, unique=True)
    user_password = models.CharField(blank=False, max_length=100, null=False)
    api_key = models.CharField(primary_key=True, auto_created=True, default=uuid.uuid4, editable=False, max_length=100)
    api_password = models.CharField(default=uuid.uuid4, editable=True, max_length=100, null=False)

    def __unicode__(self):
        return str(self.api_key)


# domain
class waf_domain(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    http = models.CharField(default="true", max_length=50)
    https = models.CharField(default="false", max_length=50)
    redirect_https = models.CharField(default="false", max_length=50)
    ssl_source = models.CharField(default="ssl_manage", max_length=50)  # ssl_manage  or custom
    ssl_domain = models.CharField(blank=True, null=True, max_length=1000)
    balance_type = models.CharField(default="round_robin", max_length=100)
    private_key = models.TextField(blank=True, null=True)
    public_key = models.TextField(blank=True, null=True)
    source_ip = models.CharField(blank=True, max_length=500)
    source_http_port = models.CharField(default="80", max_length=50)
    proxy_pass_https = models.CharField(default="false", max_length=100)

    def __unicode__(self):
        return self.user_id


class waf_protection(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    domain = models.CharField(null=False, max_length=500)
    web_engine_protection = models.CharField(default="true", max_length=50)
    web_rule_protection = models.CharField(default="true", max_length=50)
    web_white_rule = models.CharField(default="true", max_length=50)
    web_deny_page = models.CharField(default="false", max_length=50)
    flow_engine_protection = models.CharField(default="false", max_length=50)
    flow_rule_protection = models.CharField(default="true", max_length=50)
    flow_white_rule = models.CharField(default="true", max_length=50)
    flow_deny_page = models.CharField(default="false", max_length=50)
    name_list = models.CharField(default="false", max_length=50)
    component_protection = models.CharField(default="false", max_length=50)
    analysis_component = models.CharField(default="false", max_length=50)


    def __unicode__(self):
        return self.user_id


class waf_web_engine_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    sql_check = models.CharField(max_length=100, default="block")
    xss_check = models.CharField(max_length=100, default="block")
    command_inject_check = models.CharField(max_length=100, default="block")
    webshell_update_check = models.CharField(max_length=100, default="block")
    sensitive_file_check = models.CharField(max_length=100, default="block")
    path_traversal_check = models.CharField(max_length=100, default="block")
    high_nday_check = models.CharField(max_length=100, default="block")

    def __unicode__(self):
        return self.user_id


class waf_web_rule_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_type = models.CharField(max_length=100, default='')
    rule_status = models.CharField(max_length=100, default='true')
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return str(self.user_id)


class waf_web_white_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_type = models.CharField(max_length=100, default='')
    rule_status = models.CharField(max_length=100, default='true')
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return self.user_id


class waf_web_deny_page(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    owasp_code = models.CharField(default="403", max_length=50)
    owasp_html = models.TextField(blank=True, null=True)

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
    req_rate = models.CharField(default='100', max_length=50)
    req_rate_block_mode = models.CharField(default='block', max_length=50)
    req_rate_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    slow_cc_check = models.CharField(default='false', max_length=50)
    domain_rate = models.CharField(default='1000', max_length=50)
    slow_cc_block_mode = models.CharField(default='block', max_length=50)
    slow_cc_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    ip_count = models.CharField(default='1000', max_length=50)
    ip_count_stat_time_period = models.CharField(default='60', max_length=50)
    ip_count_block_mode = models.CharField(default='block', max_length=50)
    ip_count_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    emergency_mode_check = models.CharField(default='false', max_length=50)
    emergency_mode_block_mode = models.CharField(default='block', max_length=50)
    emergency_mode_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)

    def __unicode__(self):
        return self.user_id


class waf_flow_rule_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_type = models.CharField(max_length=100, default='')
    rule_status = models.CharField(max_length=100, default='true')
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return str(self.user_id)


class waf_flow_white_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_type = models.CharField(max_length=100, default='')
    rule_status = models.CharField(max_length=100, default='true')
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return self.user_id


class waf_flow_deny_page(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    owasp_code = models.CharField(default="403", max_length=50)
    owasp_html = models.TextField(blank=True, null=True)

    def __unicode__(self):
        return self.user_id


class waf_name_list(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    name_list_uuid = models.CharField(null=False, max_length=500)
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")


class waf_component_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    uuid = models.CharField(null=False, max_length=500)
    conf = models.CharField(null=False, max_length=2000)
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")

class waf_analysis_component(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    domain = models.CharField(null=False, max_length=500)
    uuid = models.CharField(null=False, max_length=500)
    conf = models.CharField(null=False, max_length=2000)
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")


# group_domain

class waf_group_id(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    group_id = models.CharField(default=uuid.uuid4, max_length=500)
    group_name = models.CharField(null=False, max_length=500)
    group_detail = models.CharField(blank=True, null=True, max_length=1000)

    def __unicode__(self):
        return self.user_id


class waf_group_domain(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    group_id = models.CharField(null=False, max_length=500)
    domain = models.CharField(null=False, max_length=500)
    http = models.CharField(default="true", max_length=50)
    https = models.CharField(default="false", max_length=50)
    redirect_https = models.CharField(default="false", max_length=50)
    ssl_source = models.CharField(default="ssl_manage", max_length=50)  # ssl_manage  or custom
    ssl_domain = models.CharField(blank=True, null=True, max_length=1000)
    balance_type = models.CharField(default="round_robin", max_length=100)
    private_key = models.TextField(blank=True, null=True)
    public_key = models.TextField(blank=True, null=True)
    source_ip = models.CharField(blank=True, max_length=500)
    source_http_port = models.CharField(default="80", max_length=50)
    proxy_pass_https = models.CharField(default="false", max_length=100)

    def __unicode__(self):
        return self.user_id


class waf_group_protection(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    group_id = models.CharField(null=False, max_length=500)
    web_engine_protection = models.CharField(default="true", max_length=50)
    web_rule_protection = models.CharField(default="true", max_length=50)
    web_white_rule = models.CharField(default="true", max_length=50)
    web_deny_page = models.CharField(default="false", max_length=50)
    flow_engine_protection = models.CharField(default="false", max_length=50)
    flow_rule_protection = models.CharField(default="true", max_length=50)
    flow_white_rule = models.CharField(default="true", max_length=50)
    flow_deny_page = models.CharField(default="false", max_length=50)
    name_list = models.CharField(default="false", max_length=50)
    component_protection = models.CharField(default="false", max_length=50)
    analysis_component = models.CharField(default="false", max_length=50)

    def __unicode__(self):
        return self.user_id


class waf_group_web_engine_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    sql_check = models.CharField(max_length=100, default="block")
    xss_check = models.CharField(max_length=100, default="block")
    command_inject_check = models.CharField(max_length=100, default="block")
    webshell_update_check = models.CharField(max_length=100, default="block")
    sensitive_file_check = models.CharField(max_length=100, default="block")
    path_traversal_check = models.CharField(max_length=100, default="block")
    high_nday_check = models.CharField(max_length=100, default="block")

    def __unicode__(self):
        return self.user_id


class waf_group_web_rule_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_type = models.CharField(max_length=100, default='')
    rule_status = models.CharField(max_length=100, default='true')
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return str(self.user_id)


class waf_group_web_white_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_type = models.CharField(max_length=100, default='')
    rule_status = models.CharField(max_length=100, default='true')
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return self.user_id


class waf_group_web_deny_page(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    owasp_code = models.CharField(default="403", max_length=50)
    owasp_html = models.TextField(blank=True, null=True)

    def __unicode__(self):
        return self.user_id


class waf_group_flow_engine_protection(models.Model):
    user_id = models.CharField(null=False, max_length=100)
    group_id = models.CharField(null=False, max_length=500)
    high_freq_cc_check = models.CharField(default='false', max_length=50)
    req_count = models.CharField(default='6000', max_length=50)
    req_count_stat_time_period = models.CharField(default='60', max_length=50)
    req_count_block_mode = models.CharField(default='block', max_length=50)  # 403 444
    req_count_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    req_rate = models.CharField(default='100', max_length=50)
    req_rate_block_mode = models.CharField(default='block', max_length=50)
    req_rate_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    slow_cc_check = models.CharField(default='false', max_length=50)
    domain_rate = models.CharField(default='1000', max_length=50)
    slow_cc_block_mode = models.CharField(default='block', max_length=50)
    slow_cc_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    ip_count = models.CharField(default='1000', max_length=50)
    ip_count_stat_time_period = models.CharField(default='60', max_length=50)
    ip_count_block_mode = models.CharField(default='block', max_length=50)
    ip_count_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)
    emergency_mode_check = models.CharField(default='false', max_length=50)
    emergency_mode_block_mode = models.CharField(default='block', max_length=50)
    emergency_mode_block_mode_extra_parameter = models.CharField(default='standard', max_length=500)

    def __unicode__(self):
        return self.user_id


class waf_group_flow_rule_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_type = models.CharField(max_length=100, default='')
    rule_status = models.CharField(max_length=100, default='true')
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return str(self.user_id)


class waf_group_flow_white_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_type = models.CharField(max_length=100, default='')
    rule_status = models.CharField(max_length=100, default='true')
    rule_order_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return self.user_id


class waf_group_flow_deny_page(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    owasp_code = models.CharField(default="403", max_length=50)
    owasp_html = models.TextField(blank=True, null=True)

    def __unicode__(self):
        return self.user_id


class waf_group_name_list(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    name_list_uuid = models.CharField(null=False, max_length=500)
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")


class waf_group_component_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    uuid = models.CharField(null=False, max_length=500)
    conf = models.CharField(null=False, max_length=2000)
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")

class waf_group_analysis_component(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    group_id = models.CharField(null=False, max_length=500)
    uuid = models.CharField(null=False, max_length=500)
    conf = models.CharField(null=False, max_length=2000)
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")


# global_default_conf

class waf_global_name_list(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name_list_uuid = models.CharField(null=False, max_length=500)
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="true")


class waf_global_component_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    uuid = models.CharField(null=False, max_length=500)
    conf = models.CharField(null=False, max_length=2000)
    order_time = models.BigIntegerField(default=0)
    status = models.CharField(max_length=1000, default="false")


# sys manage

class sys_web_rule_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    rule_type = models.CharField(max_length=100, default="single_rule")  # single_rule or group_rule
    rule_group_uuid = models.CharField(max_length=100, default="")
    rule_group_name = models.CharField(max_length=1000, default="")
    rule_uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=1000, default="")
    rule_matchs = models.TextField(null=False)
    rule_action = models.CharField(max_length=1000, default="")
    action_value = models.CharField(max_length=1000, default="")
    rule_log = models.CharField(max_length=100, default="true")
    rule_order_time = models.BigIntegerField(default=0)  # only group_rule use
    update_time = models.CharField(null=False, max_length=50)

    def __unicode__(self):
        return str(self.user_id)


class sys_web_rule_protection_group(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    rule_group_uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_group_name = models.CharField(max_length=1000, default="")
    rule_group_detail = models.CharField(max_length=1000, default="")

    def __unicode__(self):
        return str(self.user_id)


class sys_web_white_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    rule_type = models.CharField(max_length=100, default="single_rule")  # single_rule or group_rule
    rule_group_uuid = models.CharField(max_length=100, default="")
    rule_group_name = models.CharField(max_length=1000, default="")
    rule_uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=1000, default="")
    rule_matchs = models.TextField(null=False)
    rule_action = models.CharField(max_length=1000, default="")
    action_value = models.CharField(max_length=1000, default="")
    rule_log = models.CharField(max_length=100, default="true")
    rule_order_time = models.BigIntegerField(default=0)  # only group_rule use
    update_time = models.CharField(null=False, max_length=50)

    def __unicode__(self):
        return str(self.user_id)


class sys_web_white_rule_group(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    rule_group_uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_group_name = models.CharField(max_length=1000, default="")
    rule_group_detail = models.CharField(max_length=1000, default="")

    def __unicode__(self):
        return str(self.user_id)


class sys_flow_rule_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    rule_type = models.CharField(max_length=100, default="single_rule")  # single_rule or group_rule
    rule_group_uuid = models.CharField(max_length=1000, default="")
    rule_group_name = models.CharField(max_length=1000, default="")
    rule_uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=1000, default="")
    rule_pre_match = models.CharField(max_length=100, default="true")
    rule_matchs = models.TextField(blank=True, null=True)
    rule_action = models.CharField(max_length=1000, default="")
    action_value = models.CharField(max_length=1000, default="")
    rule_log = models.CharField(max_length=100, default="true")
    rule_order_time = models.BigIntegerField(default=0)  # only group_rule use
    update_time = models.CharField(null=False, max_length=50)

    def __unicode__(self):
        return str(self.user_id)


class sys_flow_rule_protection_group(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    rule_group_uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_group_name = models.CharField(max_length=1000, default="")
    rule_group_detail = models.CharField(max_length=1000, default="")

    def __unicode__(self):
        return str(self.user_id)


class sys_flow_white_rule(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    rule_type = models.CharField(max_length=100, default="single_rule")  # single_rule or group_rule
    rule_group_uuid = models.CharField(max_length=100, null=True)
    rule_group_name = models.CharField(max_length=1000, default="")
    rule_uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_name = models.CharField(max_length=1000, default="")
    rule_detail = models.CharField(max_length=1000, default="")
    rule_pre_match = models.CharField(max_length=100, default="true")
    rule_matchs = models.TextField(blank=True, null=True)
    rule_action = models.CharField(max_length=1000, default="")
    action_value = models.CharField(max_length=1000, default="")
    rule_log = models.CharField(max_length=100, default="true")
    rule_order_time = models.BigIntegerField(default=0)  # only group_rule use
    update_time = models.CharField(null=False, max_length=100)

    def __unicode__(self):
        return str(self.user_id)


class sys_flow_white_rule_group(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    rule_group_uuid = models.CharField(max_length=100, default=uuid.uuid4)
    rule_group_name = models.CharField(max_length=1000, default="")
    rule_group_detail = models.CharField(max_length=1000, default="")

    def __unicode__(self):
        return str(self.user_id)


class sys_shared_dict(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    shared_dict_uuid = models.CharField(default=uuid.uuid4, max_length=500)
    shared_dict_name = models.CharField(null=False, max_length=1000)
    shared_dict_detail = models.CharField(null=False, max_length=1000)
    shared_dict_key = models.CharField(null=False, max_length=2000)
    shared_dict_type = models.CharField(null=False, max_length=500)
    shared_dict_value = models.CharField(default="true", max_length=500)
    shared_dict_expire_time = models.CharField(default='3600', max_length=100)


class sys_name_list(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name_list_uuid = models.CharField(default=uuid.uuid4, max_length=500)
    name_list_name = models.CharField(null=False, max_length=1000)
    name_list_detail = models.CharField(null=False, max_length=1000)
    name_list_limit = models.CharField(default='100000000', max_length=100)
    name_list_expire_time = models.CharField(default='3155760000', max_length=100)
    name_list_rule = models.CharField(null=False, max_length=2000)
    name_list_action = models.CharField(null=False, max_length=1000)
    action_value = models.CharField(max_length=1000, default="")
    repeated_writing_suppression = models.CharField(default='60', max_length=100)

    def __unicode__(self):
        return self.user_id


class sys_name_list_item(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name_list_uuid = models.CharField(null=False, max_length=500)
    name_list_item = models.CharField(null=False, max_length=2000)
    name_list_item_create_time = models.BigIntegerField(default=0)
    name_list_item_expire_time = models.BigIntegerField(default=0)

    def __unicode__(self):
        return self.user_id


class sys_ssl_manage(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    ssl_domain = models.CharField(null=False, max_length=1000)
    private_key = models.TextField(blank=True, null=True)
    public_key = models.TextField(blank=True, null=True)
    update_time = models.CharField(null=False, max_length=50)

    def __unicode__(self):
        return str(self.user_id)


class sys_web_engine_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    code = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=1000, default="")
    detail = models.CharField(max_length=1000, default="")
    default = models.CharField(max_length=100, default="false")
    update_time = models.CharField(null=False, max_length=50, default="")

    def __unicode__(self):
        return str(self.user_id)


class sys_flow_engine_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    code = models.TextField(blank=True, null=True)
    name = models.CharField(max_length=1000, default="")
    detail = models.CharField(max_length=1000, default="")
    default = models.CharField(max_length=100, default="false")
    update_time = models.CharField(null=False, max_length=50, default="")

    def __unicode__(self):
        return str(self.user_id)


class sys_component_protection(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    uuid = models.CharField(null=False, max_length=500)
    code = models.TextField(blank=True, null=True)
    name = models.CharField(null=False, max_length=1000)
    detail = models.CharField(null=False, max_length=1000)
    demo_conf = models.CharField(null=False, max_length=2000)  # json

    def __unicode__(self):
        return str(self.user_id)


class sys_abnormal_handle(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    bypass_check = models.CharField(default='true', max_length=50)
    same_name_args_check = models.CharField(default='true', max_length=50)
    truncated_agrs_check = models.CharField(default='true', max_length=50)
    client_body_size_check = models.CharField(default='true', max_length=50)
    ssl_attack_check = models.CharField(default='false', max_length=50)
    ssl_attack_count = models.CharField(default='1000', max_length=50)
    ssl_attack_count_stat_time_period = models.CharField(default='60', max_length=50)
    ssl_attack_block_name_list_uuid = models.CharField(default='false', max_length=50)

    def __unicode__(self):
        return str(self.user_id)


class sys_global_default_page(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    web_deny_code = models.CharField(default="403", max_length=50)
    web_deny_html = models.TextField(blank=True, null=True, default="")
    flow_deny_code = models.CharField(default="444", max_length=50)
    flow_deny_html = models.TextField(blank=True, null=True, default="")
    name_list_deny_code = models.CharField(default="403", max_length=50)
    name_list_deny_html = models.TextField(blank=True, null=True, default="")
    domain_404_code = models.CharField(default="404", max_length=50)
    domain_404_html = models.TextField(blank=True, null=True, default="domain is not exist")


class sys_base_conf(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    jxwaf_login = models.CharField(default="false", max_length=50)
    jxwaf_login_token = models.CharField(default="", max_length=100)
    proxie = models.CharField(default="false", max_length=50)
    proxie_site = models.CharField(default="", max_length=50)


class sys_mimetic_defense_conf(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    mimetic_defense = models.CharField(default="false", max_length=50)
    proxy_host = models.CharField(default="", max_length=100)
    proxy_port = models.CharField(default="", max_length=100)
    token = models.CharField(default="", max_length=100)


class sys_log_conf(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    log_local_debug = models.CharField(max_length=100, default="false")
    log_remote = models.CharField(max_length=100, default="false")
    log_remote_type = models.CharField(max_length=100, default="syslog") # syslog or kafka
    kafka_bootstrap_servers = models.CharField(max_length=1000, default="")
    kafka_topic = models.CharField(max_length=1000, default="")
    log_ip = models.CharField(max_length=100, default="127.0.0.1")
    log_port = models.CharField(max_length=100, default="5555")
    log_all = models.CharField(max_length=100, default="false")


class sys_report_conf(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    log_source = models.CharField(max_length=100, default="")  # cls sls  ch
    cls_SecretId = models.CharField(max_length=100, default="")
    cls_SecretKey = models.CharField(max_length=100, default="")
    cls_Region = models.CharField(max_length=100, default="")
    cls_TopicId = models.CharField(max_length=100, default="")
    sls_AccessKey_ID = models.CharField(max_length=100, default="")
    sls_AccessKey_Secret = models.CharField(max_length=100, default="")
    sls_endpoint = models.CharField(max_length=100, default="")
    sls_project = models.CharField(max_length=100, default="")
    sls_logstore = models.CharField(max_length=100, default="")
    ch_host = models.CharField(max_length=100, default="")
    ch_port = models.CharField(max_length=100, default="")
    ch_user = models.CharField(max_length=100, default="")
    ch_password = models.CharField(max_length=100, default="")
    ch_database = models.CharField(max_length=100, default="")




class node_monitor(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    node_uuid = models.CharField(max_length=100, default="")
    node_hostname = models.CharField(max_length=1000, default="")
    node_ip = models.CharField(max_length=1000, default="")
    node_waf_conf_update = models.CharField(max_length=100, default="true")
    node_waf_conf_update_time = models.CharField(max_length=100, default="")
    node_name_list_data_update = models.CharField(max_length=100, default="true")
    node_name_list_data_update_time = models.CharField(max_length=100, default="")
    node_status = models.CharField(max_length=100, default="true")
    node_status_update_time = models.CharField(max_length=100, default="")


class report_name_list_item_action_log(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name_list_name = models.CharField(default="", max_length=1000)
    name_list_uuid = models.CharField(default="", max_length=1000)
    name_list_item = models.CharField(default="", max_length=1000)
    name_list_item_action_time = models.CharField(default="", max_length=1000)
    name_list_item_action_ip = models.CharField(default="", max_length=1000)
    name_list_item_action = models.CharField(default="", max_length=1000)

    def __unicode__(self):
        return self.user_id

class sys_custom_response(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name = models.CharField(null=False, max_length=1000)
    detail = models.CharField(max_length=1000, default="")
    set_return_header_status = models.CharField(default="false", max_length=50)
    set_return_header_value = models.CharField(default="{}", max_length=2000)  # {"key":"","value":""}
    return_code = models.CharField(default="200", max_length=50)
    return_html = models.TextField(blank=True, null=True, default="")

    def __unicode__(self):
        return self.user_id


class sys_request_replace(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name = models.CharField(null=False, max_length=1000)
    detail = models.CharField(max_length=1000, default="")
    get_status = models.CharField(default="false", max_length=50)
    get_replace_match = models.CharField(default="", max_length=2000)
    get_replace_data = models.CharField(default="", max_length=2000)
    header_status = models.CharField(default="false", max_length=50)
    header_replace_data = models.CharField(default="{}",
                                           max_length=2000)  # {"cookie":{"replace_match":"","replace_data":""}}
    post_status = models.CharField(default="false", max_length=50)
    post_replace_match = models.CharField(default="", max_length=2000)
    post_replace_data = models.CharField(default="", max_length=2000)

    def __unicode__(self):
        return self.user_id


class sys_response_replace(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name = models.CharField(null=False, max_length=1000)
    detail = models.CharField(max_length=1000, default="")
    response_header_status = models.CharField(default="false", max_length=50)
    response_header_replace_data = models.CharField(default="{}",
                                                    max_length=2000)  # {"cookie":{"replace_match":"","replace_data":""}}
    response_data_status = models.CharField(default="false", max_length=50)
    response_data_replace_match = models.CharField(default="", max_length=2000)
    response_data_replace_data = models.CharField(default="", max_length=2000)

    def __unicode__(self):
        return self.user_id


class sys_traffic_forward(models.Model):
    user_id = models.CharField(null=False, max_length=50)
    name = models.CharField(null=False, max_length=1000)
    detail = models.CharField(max_length=1000, default="")
    set_request_header_status = models.CharField(default="false", max_length=50)
    set_request_header_value = models.CharField(default="{}", max_length=2000) # [{"key":"","value":"","type":"set_value/del_value"}]
    traffic_forward_ip = models.CharField(null=False, max_length=1000)
    traffic_forward_port = models.CharField(null=False, max_length=1000)

    def __unicode__(self):
        return self.user_id
