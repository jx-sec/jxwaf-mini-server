"""jxwaf_base_server URL Configuration

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
from server.waf_update import *
from server.jxwaf_user import *
from server.waf_name_list import *
from server.waf_name_list_item import *
from server.waf_base_component import *
from server.waf_analysis_component import *
from server.waf_domain import *
from server.waf_protection import *
from server.waf_web_engine_protection import *
from server.waf_web_rule_protection import *
from server.waf_web_white_rule import *
from server.waf_flow_engine_protection import *
from server.waf_flow_rule_protection import *
from server.waf_flow_white_rule import *
from server.waf_flow_ip_region_block import *
from server.waf_ssl_manage import *
from server.waf_node_monitor import *
from server.sys_conf import *
from server.soc_log_query import *
from server.soc_web_report import *
from server.soc_flow_report import *
from server.soc_attack_event import *
from server.soc_request_statistics import *

urlpatterns = [
    #    url(r'^admin/', admin.site.urls),
    url(r'^$', index),
    url(r'^waf_update$', waf_update),
    url(r'^waf_monitor$', waf_monitor),
    url(r'^ip_check$', ip_check),
    url(r'^waf_name_list_item_update$', waf_name_list_item_update),
    url(r'^index\.html$', index),
    url(r'^login\.html$', login_html),
    url(r'^account_regist$', account_regist),
    url(r'^login$', login),
    url(r'^captcha$', captcha),
    url(r'^logout$', logout),
    url(r'^account_init_check$', account_init_check),
    url(r'^waf_sys_conf_log_and_report_init$', waf_sys_conf_log_and_report_init),
    url(r'^waf/waf_get_domain_list$', waf_get_domain_list),
    url(r'^waf/waf_del_domain$', waf_del_domain),
    url(r'^waf/waf_create_domain$', waf_create_domain),
    url(r'^waf/waf_edit_domain$', waf_edit_domain),
    url(r'^waf/waf_get_domain$', waf_get_domain),
    url(r'^waf/waf_get_domain_search_list$', waf_get_domain_search_list),
    url(r'^waf/waf_get_ssl_manage_list$', waf_get_ssl_manage_list),
    url(r'^waf/waf_get_ssl_manage$', waf_get_ssl_manage),
    url(r'^waf/waf_del_ssl_manage$', waf_del_ssl_manage),
    url(r'^waf/waf_edit_ssl_manage$', waf_edit_ssl_manage),
    url(r'^waf/waf_create_ssl_manage$', waf_create_ssl_manage),
    url(r'^waf/waf_edit_protection$', waf_edit_protection),
    url(r'^waf/waf_get_protection$', waf_get_protection),
    url(r'^waf/waf_edit_web_engine_protection$', waf_edit_web_engine_protection),
    url(r'^waf/waf_get_web_engine_protection$', waf_get_web_engine_protection),

    url(r'^waf/waf_get_web_rule_protection_list$', waf_get_web_rule_protection_list),
    url(r'^waf/waf_del_web_rule_protection$', waf_del_web_rule_protection),
    url(r'^waf/waf_edit_web_rule_protection_status$', waf_edit_web_rule_protection_status),
    url(r'^waf/waf_edit_web_rule_protection$', waf_edit_web_rule_protection),
    url(r'^waf/waf_get_web_rule_protection$', waf_get_web_rule_protection),
    url(r'^waf/waf_create_web_rule_protection$', waf_create_web_rule_protection),
    url(r'^waf/waf_exchange_web_rule_protection_priority$', waf_exchange_web_rule_protection_priority),
    url(r'^waf/waf_load_web_rule_protection$', waf_load_web_rule_protection),
    url(r'^waf/waf_backup_web_rule_protection$', waf_backup_web_rule_protection),

    url(r'^waf/waf_get_web_white_rule_list$', waf_get_web_white_rule_list),
    url(r'^waf/waf_del_web_white_rule$', waf_del_web_white_rule),
    url(r'^waf/waf_edit_web_white_rule_status$', waf_edit_web_white_rule_status),
    url(r'^waf/waf_edit_web_white_rule$', waf_edit_web_white_rule),
    url(r'^waf/waf_get_web_white_rule$', waf_get_web_white_rule),
    url(r'^waf/waf_create_web_white_rule$', waf_create_web_white_rule),
    url(r'^waf/waf_exchange_web_white_rule_priority$', waf_exchange_web_white_rule_priority),
    url(r'^waf/waf_load_web_white_rule$', waf_load_web_white_rule),
    url(r'^waf/waf_backup_web_white_rule$', waf_backup_web_white_rule),

    url(r'^waf/waf_edit_flow_engine_protection$', waf_edit_flow_engine_protection),
    url(r'^waf/waf_get_flow_engine_protection$', waf_get_flow_engine_protection),

    url(r'^waf/waf_get_flow_rule_protection_list$', waf_get_flow_rule_protection_list),
    url(r'^waf/waf_del_flow_rule_protection$', waf_del_flow_rule_protection),
    url(r'^waf/waf_edit_flow_rule_protection_status$', waf_edit_flow_rule_protection_status),
    url(r'^waf/waf_edit_flow_rule_protection$', waf_edit_flow_rule_protection),
    url(r'^waf/waf_get_flow_rule_protection$', waf_get_flow_rule_protection),
    url(r'^waf/waf_create_flow_rule_protection$', waf_create_flow_rule_protection),
    url(r'^waf/waf_exchange_flow_rule_protection_priority$', waf_exchange_flow_rule_protection_priority),
    url(r'^waf/waf_load_flow_rule_protection$', waf_load_flow_rule_protection),
    url(r'^waf/waf_backup_flow_rule_protection$', waf_backup_flow_rule_protection),

    url(r'^waf/waf_get_flow_white_rule_list$', waf_get_flow_white_rule_list),
    url(r'^waf/waf_del_flow_white_rule$', waf_del_flow_white_rule),
    url(r'^waf/waf_edit_flow_white_rule_status$', waf_edit_flow_white_rule_status),
    url(r'^waf/waf_edit_flow_white_rule$', waf_edit_flow_white_rule),
    url(r'^waf/waf_get_flow_white_rule$', waf_get_flow_white_rule),
    url(r'^waf/waf_create_flow_white_rule$', waf_create_flow_white_rule),
    url(r'^waf/waf_exchange_flow_white_rule_priority$', waf_exchange_flow_white_rule_priority),
    url(r'^waf/waf_load_flow_white_rule$', waf_load_flow_white_rule),
    url(r'^waf/waf_backup_flow_white_rule$', waf_backup_flow_white_rule),

    url(r'^waf/waf_edit_flow_ip_region_block$', waf_edit_flow_ip_region_block),
    url(r'^waf/waf_get_flow_ip_region_block$', waf_get_flow_ip_region_block),

    url(r'^waf/waf_get_name_list_list$', waf_get_name_list_list),
    url(r'^waf/waf_get_name_list$', waf_get_name_list),
    url(r'^waf/waf_del_name_list$', waf_del_name_list),
    url(r'^waf/waf_edit_name_list$', waf_edit_name_list),
    url(r'^waf/waf_edit_name_list_status$', waf_edit_name_list_status),
    url(r'^waf/waf_create_name_list$', waf_create_name_list),
    url(r'^waf/waf_exchange_name_list_priority$', waf_exchange_name_list_priority),

    url(r'^waf/waf_get_name_list_item_list$', waf_get_name_list_item_list),
    url(r'^waf/waf_del_name_list_item$', waf_del_name_list_item),
    url(r'^waf/waf_create_name_list_item$', waf_create_name_list_item),
    url(r'^waf/waf_search_name_list_item$', waf_search_name_list_item),

    url(r'^waf/waf_get_base_component_list$', waf_get_base_component_list),
    url(r'^waf/waf_get_base_component$', waf_get_base_component),
    url(r'^waf/waf_del_base_component$', waf_del_base_component),
    url(r'^waf/waf_edit_base_component$', waf_edit_base_component),
    url(r'^waf/waf_edit_base_component_status$', waf_edit_base_component_status),
    url(r'^waf/waf_create_base_component$', waf_create_base_component),
    url(r'^waf/waf_exchange_base_component_priority$', waf_exchange_base_component_priority),

    url(r'^waf/waf_get_analysis_component_list$', waf_get_analysis_component_list),
    url(r'^waf/waf_get_analysis_component$', waf_get_analysis_component),
    url(r'^waf/waf_del_analysis_component$', waf_del_analysis_component),
    url(r'^waf/waf_edit_analysis_component$', waf_edit_analysis_component),
    url(r'^waf/waf_edit_analysis_component_status$', waf_edit_analysis_component_status),
    url(r'^waf/waf_create_analysis_component$', waf_create_analysis_component),
    url(r'^waf/waf_exchange_analysis_component_priority$', waf_exchange_analysis_component_priority),

    url(r'^waf/waf_get_node_monitor_list$', waf_get_node_monitor_list),
    url(r'^waf/waf_del_node_monitor$', waf_del_node_monitor),

    url(r'^waf/waf_edit_sys_log_conf$', waf_edit_sys_log_conf),
    url(r'^waf/waf_get_sys_log_conf$', waf_get_sys_log_conf),
    url(r'^waf/waf_edit_sys_report_conf_conf$', waf_edit_sys_report_conf_conf),
    url(r'^waf/waf_get_sys_report_conf_conf$', waf_get_sys_report_conf_conf),
    url(r'^waf/waf_edit_sys_custom_deny_page_conf$', waf_edit_sys_custom_deny_page_conf),
    url(r'^waf/waf_get_sys_custom_deny_page_conf$', waf_get_sys_custom_deny_page_conf),
    url(r'^waf/waf_get_waf_auth$', waf_get_waf_auth),
    url(r'^waf/waf_edit_waf_auth$', waf_edit_waf_auth),
    url(r'^waf/waf_conf_backup$', waf_conf_backup),
    url(r'^waf/waf_conf_load$', waf_conf_load),

    url(r'^soc/soc_query_log$', soc_query_log),
    url(r'^soc/soc_query_log_all$', soc_query_log_all),
    url(r'^soc/soc_web_report_attack_count_total$', soc_web_report_attack_count_total),
    url(r'^soc/soc_web_report_attack_api_count_total$', soc_web_report_attack_api_count_total),
    url(r'^soc/soc_web_report_attack_ip_count_total$', soc_web_report_attack_ip_count_total),
    url(r'^soc/soc_web_report_attack_isocode_count_total$', soc_web_report_attack_isocode_count_total),
    url(r'^soc/soc_web_report_attack_geoip$', soc_web_report_attack_geoip),
    url(r'^soc/soc_web_report_attack_count_trend$', soc_web_report_attack_count_trend),
    url(r'^soc/soc_web_report_attack_api_top$', soc_web_report_attack_api_top),
    url(r'^soc/soc_web_report_attack_type_top$', soc_web_report_attack_type_top),
    url(r'^soc/soc_web_report_attack_ip_top$', soc_web_report_attack_ip_top),
    url(r'^soc/soc_web_report_attack_isocode_top$', soc_web_report_attack_isocode_top),

    url(r'^soc/soc_flow_report_attack_count_total$', soc_flow_report_attack_count_total),
    url(r'^soc/soc_flow_report_attack_api_count_total$', soc_flow_report_attack_api_count_total),
    url(r'^soc/soc_flow_report_attack_ip_count_total$', soc_flow_report_attack_ip_count_total),
    url(r'^soc/soc_flow_report_attack_isocode_count_total$', soc_flow_report_attack_isocode_count_total),
    url(r'^soc/soc_flow_report_attack_geoip$', soc_flow_report_attack_geoip),
    url(r'^soc/soc_flow_report_attack_count_trend$', soc_flow_report_attack_count_trend),
    url(r'^soc/soc_flow_report_attack_api_top$', soc_flow_report_attack_api_top),
    url(r'^soc/soc_flow_report_attack_type_top$', soc_flow_report_attack_type_top),
    url(r'^soc/soc_flow_report_attack_ip_top$', soc_flow_report_attack_ip_top),
    url(r'^soc/soc_flow_report_attack_isocode_top$', soc_flow_report_attack_isocode_top),

    url(r'^soc/soc_attack_event_get_list$', soc_attack_event_get_list),
    url(r'^soc/soc_attack_event_get_behave_track$', soc_attack_event_get_behave_track),
    url(r'^soc/soc_attack_event_get_all_log_list$', soc_attack_event_get_all_log_list),
    url(r'^soc/soc_attack_event_get_all_log_behave_track$', soc_attack_event_get_all_log_behave_track),

    url(r'^soc/soc_query_request_statistics$', soc_query_request_statistics),
    url(r'^soc/soc_query_request_statistics_detail$', soc_query_request_statistics_detail),
    url(r'^demo_env_init$', demo_env_init),

    url(r'^api/add_name_list_item$', api_add_name_list_item),
]
