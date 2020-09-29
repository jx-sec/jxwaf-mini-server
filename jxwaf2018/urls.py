"""jxwaf2018 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from jxwaf.views import *
from jxwaf.waf_cc import *
from jxwaf.waf_domain import *
from jxwaf.waf_protection import *
from jxwaf.waf_custom import *
from jxwaf.waf_global import *
# from jxwaf.waf_owasp import *
from jxwaf.waf_owasp_jxcheck import *
from jxwaf.waf_page_custom import *
from jxwaf.waf_monitor import *
from jxwaf.waf_login_log import *
from jxwaf.waf_attack_ip_heandle import *
from jxwaf.waf_ip_config import *
from jxwaf.waf_flow_chart import *
from jxwaf.waf_cc_attack_ip import *
from jxwaf.waf_sync_update import *
from jxwaf.waf_attack_chart import *
from jxwaf.waf_cc_chart import *

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^$', index),
    url(r'^index\.html$', index),
    url(r'^login\.html$', login_html),
    url(r'^register\.html$', regist_html),
    url(r'^regist$', regist),
    url(r'^login$', login),
    url(r'^captcha$', captcha),
    url(r'^logout$', logout),
    url(r'^login', login),
    url(r'^waf/waf_get_login_log', waf_get_login_log),
    url(r'^index$', index),
    url(r'^waf/waf_get_domain_list$', waf_get_domain_list),
    url(r'^waf/waf_get_domain$', waf_get_domain),
    url(r'^waf/waf_del_domain$', waf_del_domain),
    url(r'^waf/waf_create_domain$', waf_create_domain),
    url(r'^waf/waf_edit_domain$', waf_edit_domain),
    url(r'^waf/waf_edit_protection$', waf_edit_protection),
    url(r'^waf/waf_get_protection$', waf_get_protection),
    url(r'^waf/waf_get_cc_attack_ip', waf_get_cc_attack_ip),
    url(r'^waf/waf_edit_cc_attack_ip', waf_edit_cc_attack_ip),
    url(r'^waf/waf_get_cc_protection', waf_get_cc_protection),
    url(r'^waf/waf_edit_cc_protection', waf_edit_cc_protection),
    url(r'^waf/waf_get_custom_rule_list', waf_get_custom_rule_list),
    url(r'^waf/waf_get_custom_rule', waf_get_custom_rule),
    url(r'^waf/waf_del_custom_rule', waf_del_custom_rule),
    url(r'^waf/waf_create_custom_rule', waf_create_custom_rule),
    url(r'^waf/waf_edit_custom_rule', waf_edit_custom_rule),
    url(r'^waf/waf_edit_global', waf_edit_global),
    url(r'^waf/waf_get_global', waf_get_global),
    url(r'^waf/waf_get_golbal', waf_get_global),
    url(r'^waf_update$', waf_update),
    url(r'^waf_monitor$', waf_monitor),
    url(r'^waf/waf_copy_domain$', waf_copy_domain),
    url(r'^waf/waf_edit_owasp_check$', waf_edit_owasp_check),
    url(r'^waf/waf_get_owasp_check$', waf_get_owasp_check),
    url(r'^waf/waf_edit_page_custom$', waf_edit_page_custom),
    url(r'^waf/waf_get_page_custom$', waf_get_page_custom),
    url(r'^waf/waf_get_monitor_list$', waf_get_monitor_list),
    url(r'^waf/waf_edit_monitor_alert$', waf_edit_monitor_alert),
    url(r'^waf/waf_delete_monitor$', waf_delete_monitor),

    url(r'^waf/waf_get_jxcheck_version', waf_get_jxcheck_version),
    url(r'^waf/waf_get_jxwaf_jxcheck_version', waf_get_jxwaf_jxcheck_version),
    url(r'^waf/waf_download_jxwaf_jxcheck', waf_download_jxwaf_jxcheck),

    url(r'^waf/waf_get_evil_ip_handle', waf_get_evil_ip_handle),
    url(r'^waf/waf_edit_evil_ip_handle', waf_edit_evil_ip_handle),


    url(r'^waf/waf_get_ip_rule_list', waf_get_ip_rule_list),
    url(r'^waf/waf_del_ip_rule', waf_del_ip_rule),
    url(r'^waf/waf_create_ip_rule', waf_create_ip_rule),
    url(r'^waf/waf_edit_ip_rule', waf_edit_ip_rule),


    url(r'^waf/flow_chart_get_totle_count', flow_chart_get_totle_count),
    url(r'^waf/flow_chart_get_req_count_trend', flow_chart_get_req_count_trend),
    url(r'^waf/flow_chart_get_upstream_count_trend', flow_chart_get_upstream_count_trend),
    url(r'^waf/flow_chart_get_input_byte_trend', flow_chart_get_input_byte_trend),
    url(r'^waf/flow_chart_get_upstream_input_byte_trend', flow_chart_get_upstream_input_byte_trend),
    url(r'^waf/flow_chart_get_output_byte_trend', flow_chart_get_output_byte_trend),
    url(r'^waf/flow_chart_get_upstream_output_byte_trend', flow_chart_get_upstream_output_byte_trend),
    url(r'^waf/flow_chart_get_process_time_trend', flow_chart_get_process_time_trend),
    url(r'^waf/flow_chart_get_upstream_process_time_trend', flow_chart_get_upstream_process_time_trend),
    url(r'^waf/flow_chart_get_bad_req_count_trend', flow_chart_get_bad_req_count_trend),
    url(r'^waf/flow_chart_get_bad_upstream_count_trend', flow_chart_get_bad_upstream_count_trend),
    url(r'^waf/flow_chart_get_ip_trend', flow_chart_get_ip_trend),
    url(r'^waf/waf_sync_update_get_jxcheck_list', waf_sync_update_get_jxcheck_list),
    url(r'^waf/waf_sync_update_get_botcheck_list', waf_sync_update_get_botcheck_list),
    url(r'^waf/waf_sync_update_get_botcheck_key_update', waf_sync_update_get_botcheck_key_update),
    url(r'^waf/waf_sync_update_get_jxcheck_update', waf_sync_update_get_jxcheck_update),
    url(r'^waf/waf_sync_update_get_botcheck_update', waf_sync_update_get_botcheck_update),

    url(r'^chart/attack_chart_get_type_trend', attack_chart_get_type_trend),
    url(r'^chart/attack_chart_get_ip_trend', attack_chart_get_ip_trend),
    url(r'^chart/attack_chart_get_black_ip_trend', attack_chart_get_black_ip_trend),
    url(r'^chart/attack_chart_get_req_count_and_ip_count', attack_chart_get_req_count_and_ip_count),
    url(r'^chart/attack_chart_get_black_ip_count', attack_chart_get_black_ip_count),
    url(r'^chart/attack_chart_get_type_top10', attack_chart_get_type_top10),
    url(r'^chart/attack_chart_get_uri_top10', attack_chart_get_uri_top10),

    url(r'^chart/cc_chart_get_type', cc_chart_get_type),
    url(r'^chart/cc_chart_get_type_top10', cc_chart_get_type_top10),
    url(r'^chart/cc_chart_get_black_ip_count', cc_chart_get_black_ip_count),
    url(r'^chart/cc_chart_get_black_ip_trend', cc_chart_get_black_ip_trend),
    url(r'^chart/cc_chart_get_botauth_ip_count', cc_chart_get_botauth_ip_count),
    url(r'^chart/cc_chart_get_botauth_ip_trend', cc_chart_get_botauth_ip_trend),
    url(r'^chart/cc_chart_get_botcheck_ip_count', cc_chart_get_botcheck_ip_count),
    url(r'^chart/cc_chart_get_botcheck_ip_trend', cc_chart_get_botcheck_ip_trend),
    url(r'^chart/cc_chart_get_geoip', cc_chart_get_geoip),
    url(r'^chart/cc_chart_get_ip_count', cc_chart_get_ip_count),
    url(r'^chart/cc_chart_get_ip_trend', cc_chart_get_ip_trend),
]
