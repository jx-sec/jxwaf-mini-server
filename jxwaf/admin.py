from django.contrib import admin
from models import *


# Register your models here.

class UserAdmin(admin.ModelAdmin):
    list_display = (
        'user_id', 'email', 'api_password', 'password')


class waf_domain_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'email', 'domain', 'http', 'https', 'redirect_https', 'private_key', 'public_key', 'source_ip',
        'source_http_port', 'proxy', 'proxy_ip')


class waf_protection_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'email', 'domain')


class waf_cc_protection_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'domain')


class waf_cc_attack_ip_conf_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'domain')


class waf_custom_rule_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'domain', 'rule_id', 'rule_action', 'rule_level', 'rule_name', 'rule_log',
        'rule_matchs')


class waf_log_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'domain', 'log_local', 'log_remote', 'log_ip', 'log_port', 'log_sock_type', 'aliyun_log',
        'aliyun_server')


class waf_global_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'auto_update', 'auto_update_period')


class waf_jxcheck_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'version')


class waf_owasp_check_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'domain', 'owasp_protection_mode',
        'sql_check', 'xss_check', 'command_inject_check', 'directory_traversal_check',
        'upload_check', 'upload_check_rule')


class waf_page_custom_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'domain', 'owasp_code', 'owasp_html')


class waf_monitor_log_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'waf_monitor_node_uuid', 'waf_monitor_node_detail', 'waf_monitor_node_status',
        'waf_monitor_node_alert', 'waf_monitor_node_time')


class waf_cc_bot_html_key_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'uuid', 'key', 'bot_check_mode', 'create_time')


class waf_botcheck_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'botcheck_code')


class jxwaf_login_log_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'email', 'status')


class waf_data_mask_rule_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'domain', 'uri', 'get', 'post', 'header')


class waf_data_mask_global_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'domain', 'get', 'post', 'header')

class waf_rule_engine_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'domain', 'rule_name')

class waf_keycheck_admin(admin.ModelAdmin):
    list_display = (
        'user_id', 'version')

admin.site.register(jxwaf_user, UserAdmin)
admin.site.register(jxwaf_login_log, jxwaf_login_log_admin)
admin.site.register(waf_domain, waf_domain_admin)
admin.site.register(waf_protection, waf_protection_admin)
admin.site.register(waf_cc_protection, waf_cc_protection_admin)
admin.site.register(waf_cc_attack_ip_conf, waf_cc_attack_ip_conf_admin)
admin.site.register(waf_custom_rule, waf_custom_rule_admin)
admin.site.register(waf_global, waf_global_admin)
admin.site.register(waf_jxcheck, waf_jxcheck_admin)
admin.site.register(waf_owasp_check, waf_owasp_check_admin)
admin.site.register(waf_page_custom, waf_page_custom_admin)
admin.site.register(waf_monitor_log, waf_monitor_log_admin)
admin.site.register(waf_cc_bot_html_key, waf_cc_bot_html_key_admin)
admin.site.register(waf_botcheck, waf_botcheck_admin)
admin.site.register(waf_data_mask_rule, waf_data_mask_rule_admin)
admin.site.register(waf_data_mask_global, waf_data_mask_global_admin)

admin.site.register(waf_rule_engine, waf_rule_engine_admin)
admin.site.register(waf_keycheck, waf_keycheck_admin)