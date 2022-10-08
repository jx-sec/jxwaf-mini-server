"""jxwaf_min_server URL Configuration

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
# from django.contrib import admin
from server.jxwaf_user import *
from server.waf_domain import *
from server.waf_protection import *
from server.waf_web_engine_protection import *
from server.waf_web_rule_protection import *
from server.waf_web_white_rule import *
from server.waf_web_deny_page import *
from server.waf_flow_engine_protection import *
from server.waf_flow_rule_protection import *
from server.waf_flow_white_rule import *
from server.waf_flow_deny_page import *
from server.waf_name_list import *
from server.waf_group_id import *
from server.waf_group_domain import *
from server.waf_group_protection import *
from server.waf_group_web_engine_protection import *
from server.waf_group_web_rule_protection import *
from server.waf_group_web_white_rule import *
from server.waf_group_web_deny_page import *
from server.waf_group_flow_engine_protection import *
from server.waf_group_flow_rule_protection import *
from server.waf_group_flow_white_rule import *
from server.waf_group_flow_deny_page import *
from server.waf_group_name_list import *
from server.sys_ssl_manage import *
from server.sys_name_list import *
from server.sys_flow_rule_protection import *
from server.sys_flow_rule_protection_group import *
from server.sys_flow_white_rule import *
from server.sys_flow_white_rule_group import *
from server.sys_web_rule_protection import *
from server.sys_web_rule_protection_group import *
from server.sys_web_white_rule import *
from server.sys_web_white_rule_group import *
from server.sys_name_list import *
from server.sys_name_list_item import *
from server.sys_shared_dict import *
from server.update import *
from server.api_sys_name_list_item import *
from server.sys_web_engine_protection import *
from server.sys_flow_engine_protection import *
from server.sys_component_protection import *
from server.sys_abnormal_handle import *
from server.sys_global_default_page import *
from server.waf_component_protection import *
from server.waf_group_component_protection import *
from server.waf_global_component_protection import *
from server.waf_global_name_list import *
from server.sys_base_conf import *
from server.service_center_engine_update import *
from server.node_monitor import *
from server.sys_report_conf import *
from server.sys_log_conf import *
from server.sys_mimetic_defense_conf import *
from server.report_name_list_item_action_log import *
from server.report_raw_log_cls import *
from server.report_raw_log_sls import *
from server.report_name_list_cls import *
from server.report_name_list_sls import *
from server.report_flow_cls import *
from server.report_flow_sls import *
from server.report_web_cls import *
from server.report_web_sls import *

urlpatterns = [
    # url(r'^admin/', admin.site.urls),
    url(r'^$', index),
    url(r'^waf_update$', waf_update),
    url(r'^waf_monitor$', waf_monitor),
    url(r'^ip_check$', ip_check),
    url(r'^waf_name_list_item_update$', waf_name_list_item_update),
    url(r'^index\.html$', index),
    url(r'^login\.html$', login_html),
    url(r'^account_init_check$', account_init_check),
    url(r'^sys_init_check$', sys_init_check),
    url(r'^sys_init$', sys_init),
    url(r'^account_regist$', account_regist),
    url(r'^login$', login),
    url(r'^captcha$', captcha),
    url(r'^logout$', logout),
    url(r'^waf/waf_get_domain_list$', waf_get_domain_list),
    url(r'^waf/waf_del_domain$', waf_del_domain),
    url(r'^waf/waf_create_domain$', waf_create_domain),
    url(r'^waf/waf_edit_domain$', waf_edit_domain),
    url(r'^waf/waf_get_domain$', waf_get_domain),
    url(r'^waf/waf_get_domain_search_list$', waf_get_domain_search_list),
    url(r'^waf/waf_edit_protection$', waf_edit_protection),
    url(r'^waf/waf_get_protection$', waf_get_protection),
    url(r'^waf/waf_edit_web_engine_protection$', waf_edit_web_engine_protection),
    url(r'^waf/waf_get_web_engine_protection$', waf_get_web_engine_protection),
    url(r'^waf/waf_get_web_rule_list$', waf_get_web_rule_list),
    url(r'^waf/waf_del_web_rule$', waf_del_web_rule),
    url(r'^waf/waf_load_web_rule$', waf_load_web_rule),
    url(r'^waf/waf_edit_web_rule$', waf_edit_web_rule),
    url(r'^waf/waf_get_web_white_rule_list$', waf_get_web_white_rule_list),
    url(r'^waf/waf_del_web_white_rule$', waf_del_web_white_rule),
    url(r'^waf/waf_load_web_white_rule$', waf_load_web_white_rule),
    url(r'^waf/waf_edit_web_white_rule$', waf_edit_web_white_rule),
    url(r'^waf/waf_edit_web_deny_page$', waf_edit_web_deny_page),
    url(r'^waf/waf_get_flow_engine_protection$', waf_get_flow_engine_protection),
    url(r'^waf/waf_edit_flow_engine_protection$', waf_edit_flow_engine_protection),
    url(r'^waf/waf_get_web_deny_page$', waf_get_web_deny_page),
    url(r'^waf/waf_get_flow_rule_list$', waf_get_flow_rule_list),
    url(r'^waf/waf_del_flow_rule$', waf_del_flow_rule),
    url(r'^waf/waf_load_flow_rule$', waf_load_flow_rule),
    url(r'^waf/waf_edit_flow_rule$', waf_edit_flow_rule),
    url(r'^waf/waf_get_flow_white_rule_list$', waf_get_flow_white_rule_list),
    url(r'^waf/waf_del_flow_white_rule$', waf_del_flow_white_rule),
    url(r'^waf/waf_load_flow_white_rule$', waf_load_flow_white_rule),
    url(r'^waf/waf_edit_flow_white_rule$', waf_edit_flow_white_rule),
    url(r'^waf/waf_edit_flow_deny_page$', waf_edit_flow_deny_page),
    url(r'^waf/waf_get_flow_deny_page$', waf_get_flow_deny_page),
    url(r'^waf/waf_get_name_list_list$', waf_get_name_list_list),
    url(r'^waf/waf_del_name_list$', waf_del_name_list),
    url(r'^waf/waf_load_name_list$', waf_load_name_list),
    url(r'^waf/waf_edit_name_list$', waf_edit_name_list),
    url(r'^waf/waf_exchange_name_list_priority$', waf_exchange_name_list_priority),
    url(r'^waf/waf_get_group_list$', waf_get_group_list),
    url(r'^waf/waf_del_group$', waf_del_group),
    url(r'^waf/waf_create_group$', waf_create_group),
    url(r'^waf/waf_edit_group$', waf_edit_group),
    url(r'^waf/waf_get_group$', waf_get_group),
    url(r'^waf/waf_get_group_domain_list$', waf_get_group_domain_list),
    url(r'^waf/waf_del_group_domain$', waf_del_group_domain),
    url(r'^waf/waf_create_group_domain$', waf_create_group_domain),
    url(r'^waf/waf_edit_group_domain$', waf_edit_group_domain),
    url(r'^waf/waf_get_group_domain$', waf_get_group_domain),
    url(r'^waf/waf_get_group_domain_search_list$', waf_get_group_domain_search_list),
    url(r'^waf/waf_edit_group_protection$', waf_edit_group_protection),
    url(r'^waf/waf_get_group_protection$', waf_get_group_protection),
    url(r'^waf/waf_edit_group_web_engine_protection$', waf_edit_group_web_engine_protection),
    url(r'^waf/waf_get_group_web_engine_protection$', waf_get_group_web_engine_protection),
    url(r'^waf/waf_get_group_web_rule_list$', waf_get_group_web_rule_list),
    url(r'^waf/waf_del_group_web_rule$', waf_del_group_web_rule),
    url(r'^waf/waf_load_group_web_rule$', waf_load_group_web_rule),
    url(r'^waf/waf_edit_group_web_rule$', waf_edit_group_web_rule),
    url(r'^waf/waf_get_group_web_white_rule_list$', waf_get_group_web_white_rule_list),
    url(r'^waf/waf_del_group_web_white_rule$', waf_del_group_web_white_rule),
    url(r'^waf/waf_load_group_web_white_rule$', waf_load_group_web_white_rule),
    url(r'^waf/waf_edit_group_web_white_rule$', waf_edit_group_web_white_rule),
    url(r'^waf/waf_edit_group_web_deny_page$', waf_edit_group_web_deny_page),
    url(r'^waf/waf_get_group_web_deny_page$', waf_get_group_web_deny_page),
    url(r'^waf/waf_get_group_flow_engine_protection$', waf_get_group_flow_engine_protection),
    url(r'^waf/waf_edit_group_flow_engine_protection$', waf_edit_group_flow_engine_protection),
    url(r'^waf/waf_get_group_flow_rule_list$', waf_get_group_flow_rule_list),
    url(r'^waf/waf_del_group_flow_rule$', waf_del_group_flow_rule),
    url(r'^waf/waf_load_group_flow_rule$', waf_load_group_flow_rule),
    url(r'^waf/waf_edit_group_flow_rule$', waf_edit_group_flow_rule),
    url(r'^waf/waf_get_group_flow_white_rule_list$', waf_get_group_flow_white_rule_list),
    url(r'^waf/waf_del_group_flow_white_rule$', waf_del_group_flow_white_rule),
    url(r'^waf/waf_load_group_flow_white_rule$', waf_load_group_flow_white_rule),
    url(r'^waf/waf_edit_group_flow_white_rule$', waf_edit_group_flow_white_rule),
    url(r'^waf/waf_edit_group_flow_deny_page$', waf_edit_group_flow_deny_page),
    url(r'^waf/waf_get_group_flow_deny_page$', waf_get_group_flow_deny_page),
    url(r'^waf/waf_get_group_name_list_list$', waf_get_group_name_list_list),
    url(r'^waf/waf_del_group_name_list$', waf_del_group_name_list),
    url(r'^waf/waf_load_group_name_list$', waf_load_group_name_list),
    url(r'^waf/waf_edit_group_name_list$', waf_edit_group_name_list),
    url(r'^waf/waf_exchange_group_name_list_priority$', waf_exchange_group_name_list_priority),
    url(r'^waf/waf_get_sys_ssl_manage_list$', waf_get_sys_ssl_manage_list),
    url(r'^waf/waf_del_sys_ssl_manage$', waf_del_sys_ssl_manage),
    url(r'^waf/waf_edit_sys_ssl_manage$', waf_edit_sys_ssl_manage),
    url(r'^waf/waf_create_sys_ssl_manage$', waf_create_sys_ssl_manage),
    url(r'^waf/waf_get_sys_ssl_manage_search_list$', waf_get_sys_ssl_manage_search_list),

    url(r'^waf/waf_get_sys_flow_rule_protection_list$', waf_get_sys_flow_rule_protection_list),
    url(r'^waf/waf_del_sys_flow_rule_protection$', waf_del_sys_flow_rule_protection),
    url(r'^waf/waf_edit_sys_flow_rule_protection$', waf_edit_sys_flow_rule_protection),
    url(r'^waf/waf_create_sys_flow_rule_protection$', waf_create_sys_flow_rule_protection),
    url(r'^waf/waf_search_sys_flow_rule_protection$', waf_search_sys_flow_rule_protection),

    url(r'^waf/waf_get_sys_flow_rule_protection_group_list$', waf_get_sys_flow_rule_protection_group_list),
    url(r'^waf/waf_del_sys_flow_rule_protection_group$', waf_del_sys_flow_rule_protection_group),
    url(r'^waf/waf_edit_sys_flow_rule_protection_group$', waf_edit_sys_flow_rule_protection_group),
    url(r'^waf/waf_create_sys_flow_rule_protection_group$', waf_create_sys_flow_rule_protection_group),
    url(r'^waf/waf_search_sys_flow_rule_protection_group$', waf_search_sys_flow_rule_protection_group),

    url(r'^waf/waf_get_sys_flow_white_rule_list$', waf_get_sys_flow_white_rule_list),
    url(r'^waf/waf_del_sys_flow_white_rule$', waf_del_sys_flow_white_rule),
    url(r'^waf/waf_edit_sys_flow_white_rule$', waf_edit_sys_flow_white_rule),
    url(r'^waf/waf_create_sys_flow_white_rule$', waf_create_sys_flow_white_rule),
    url(r'^waf/waf_search_sys_flow_white_rule$', waf_search_sys_flow_white_rule),

    url(r'^waf/waf_get_sys_flow_white_rule_group_list$', waf_get_sys_flow_white_rule_group_list),
    url(r'^waf/waf_del_sys_flow_white_rule_group$', waf_del_sys_flow_white_rule_group),
    url(r'^waf/waf_edit_sys_flow_white_rule_group$', waf_edit_sys_flow_white_rule_group),
    url(r'^waf/waf_create_sys_flow_white_rule_group$', waf_create_sys_flow_white_rule_group),
    url(r'^waf/waf_search_sys_flow_white_rule_group$', waf_search_sys_flow_white_rule_group),

    url(r'^waf/waf_get_sys_web_rule_protection_list$', waf_get_sys_web_rule_protection_list),
    url(r'^waf/waf_get_sys_web_rule_protection$', waf_get_sys_web_rule_protection),
    url(r'^waf/waf_del_sys_web_rule_protection$', waf_del_sys_web_rule_protection),
    url(r'^waf/waf_edit_sys_web_rule_protection$', waf_edit_sys_web_rule_protection),
    url(r'^waf/waf_create_sys_web_rule_protection$', waf_create_sys_web_rule_protection),
    url(r'^waf/waf_search_sys_web_rule_protection$', waf_search_sys_web_rule_protection),

    url(r'^waf/waf_get_sys_web_rule_protection_group_list$', waf_get_sys_web_rule_protection_group_list),
    url(r'^waf/waf_del_sys_web_rule_protection_group$', waf_del_sys_web_rule_protection_group),
    url(r'^waf/waf_edit_sys_web_rule_protection_group$', waf_edit_sys_web_rule_protection_group),
    url(r'^waf/waf_create_sys_web_rule_protection_group$', waf_create_sys_web_rule_protection_group),
    url(r'^waf/waf_search_sys_web_rule_protection_group$', waf_search_sys_web_rule_protection_group),

    url(r'^waf/waf_get_sys_web_white_rule_list$', waf_get_sys_web_white_rule_list),
    url(r'^waf/waf_del_sys_web_white_rule$', waf_del_sys_web_white_rule),
    url(r'^waf/waf_edit_sys_web_white_rule$', waf_edit_sys_web_white_rule),
    url(r'^waf/waf_create_sys_web_white_rule$', waf_create_sys_web_white_rule),
    url(r'^waf/waf_search_sys_web_white_rule$', waf_search_sys_web_white_rule),

    url(r'^waf/waf_get_sys_web_white_rule_group_list$', waf_get_sys_web_white_rule_group_list),
    url(r'^waf/waf_del_sys_web_white_rule_group$', waf_del_sys_web_white_rule_group),
    url(r'^waf/waf_edit_sys_web_white_rule_group$', waf_edit_sys_web_white_rule_group),
    url(r'^waf/waf_create_sys_web_white_rule_group$', waf_create_sys_web_white_rule_group),
    url(r'^waf/waf_search_sys_web_white_rule_group$', waf_search_sys_web_white_rule_group),

    url(r'^waf/waf_get_sys_name_list_list$', waf_get_sys_name_list_list),
    url(r'^waf/waf_del_sys_name_list$', waf_del_sys_name_list),
    url(r'^waf/waf_edit_sys_name_list$', waf_edit_sys_name_list),
    url(r'^waf/waf_create_sys_name_list$', waf_create_sys_name_list),
    url(r'^waf/waf_search_sys_name_list$', waf_search_sys_name_list),

    url(r'^waf/waf_get_sys_name_list_item_list$', waf_get_sys_name_list_item_list),
    url(r'^waf/waf_del_sys_name_list_item$', waf_del_sys_name_list_item),
    url(r'^waf/waf_create_sys_name_list_item$', waf_create_sys_name_list_item),
    url(r'^waf/waf_search_sys_name_list_item$', waf_search_sys_name_list_item),

    url(r'^waf/waf_get_sys_shared_dict_list$', waf_get_sys_shared_dict_list),
    url(r'^waf/waf_del_sys_shared_dict$', waf_del_sys_shared_dict),
    url(r'^waf/waf_get_sys_shared_dict$', waf_get_sys_shared_dict),
    url(r'^waf/waf_edit_sys_shared_dict$', waf_edit_sys_shared_dict),
    url(r'^waf/waf_create_sys_shared_dict$', waf_create_sys_shared_dict),

    url(r'^api/add_name_list_item$', api_add_sys_name_list_item),
    url(r'^waf/waf_exchange_web_rule_priority$', waf_exchange_web_rule_priority),
    url(r'^waf/waf_exchange_web_white_rule_priority$', waf_exchange_web_white_rule_priority),

    url(r'^waf/waf_exchange_flow_rule_priority$', waf_exchange_flow_rule_priority),
    url(r'^waf/waf_exchange_flow_white_rule_priority$', waf_exchange_flow_white_rule_priority),
    url(r'^waf/waf_exchange_group_web_rule_priority$', waf_exchange_group_web_rule_priority),
    url(r'^waf/waf_exchange_group_web_white_rule_priority$', waf_exchange_group_web_white_rule_priority),
    url(r'^waf/waf_get_sys_web_rule_protection_group$', waf_get_sys_web_rule_protection_group),
    url(r'^waf/waf_get_sys_web_white_rule$', waf_get_sys_web_white_rule),
    url(r'^waf/waf_get_sys_web_white_rule_group$', waf_get_sys_web_white_rule_group),
    url(r'^waf/waf_get_sys_flow_rule_protection$', waf_get_sys_flow_rule_protection),
    url(r'^waf/waf_get_sys_flow_rule_protection_group$', waf_get_sys_flow_rule_protection_group),
    url(r'^waf/waf_get_sys_flow_white_rule$', waf_get_sys_flow_white_rule),
    url(r'^waf/waf_get_sys_flow_white_rule_group$', waf_get_sys_flow_white_rule_group),
    url(r'^waf/waf_exchange_group_flow_rule_priority$', waf_exchange_group_flow_rule_priority),
    url(r'^waf/waf_get_sys_name_list$', waf_get_sys_name_list),

    url(r'^waf/waf_get_sys_web_engine_protection_list$', waf_get_sys_web_engine_protection_list),
    url(r'^waf/waf_edit_sys_web_engine_protection$', waf_edit_sys_web_engine_protection),
    url(r'^waf/waf_delete_sys_web_engine_protection$', waf_delete_sys_web_engine_protection),

    url(r'^waf/waf_get_sys_flow_engine_protection_list$', waf_get_sys_flow_engine_protection_list),
    url(r'^waf/waf_edit_sys_flow_engine_protection$', waf_edit_sys_flow_engine_protection),
    url(r'^waf/waf_delete_sys_flow_engine_protection$', waf_delete_sys_flow_engine_protection),

    url(r'^waf/waf_get_sys_component_protection_list$', waf_get_sys_component_protection_list),
    url(r'^waf/waf_edit_sys_component_protection$', waf_edit_sys_component_protection),
    url(r'^waf/waf_delete_sys_component_protection$', waf_delete_sys_component_protection),

    url(r'^waf/waf_edit_sys_abnormal_handle$', waf_edit_sys_abnormal_handle),
    url(r'^waf/waf_get_sys_abnormal_handle$', waf_get_sys_abnormal_handle),

    url(r'^waf/waf_edit_sys_global_default_page$', waf_edit_sys_global_default_page),
    url(r'^waf/waf_get_sys_global_default_page$', waf_get_sys_global_default_page),

    url(r'^waf/waf_get_component_protection_list$', waf_get_component_protection_list),
    url(r'^waf/waf_del_component_protection$', waf_del_component_protection),
    url(r'^waf/waf_load_component_protection$', waf_load_component_protection),
    url(r'^waf/waf_edit_component_protection_status$', waf_edit_component_protection_status),
    url(r'^waf/waf_edit_component_protection_conf$', waf_edit_component_protection_conf),
    url(r'^waf/waf_exchange_component_protection_priority$', waf_exchange_component_protection_priority),

    url(r'^waf/waf_get_group_component_protection_list$', waf_get_group_component_protection_list),
    url(r'^waf/waf_del_group_component_protection$', waf_del_group_component_protection),
    url(r'^waf/waf_load_group_component_protection$', waf_load_group_component_protection),
    url(r'^waf/waf_edit_group_component_protection_status$', waf_edit_group_component_protection_status),
    url(r'^waf/waf_edit_group_component_protection_conf$', waf_edit_group_component_protection_conf),
    url(r'^waf/waf_exchange_group_component_protection_priority$', waf_exchange_group_component_protection_priority),

    url(r'^waf/waf_get_global_component_protection_list$', waf_get_global_component_protection_list),
    url(r'^waf/waf_del_global_component_protection$', waf_del_global_component_protection),
    url(r'^waf/waf_load_global_component_protection$', waf_load_global_component_protection),
    url(r'^waf/waf_edit_global_component_protection_status$', waf_edit_global_component_protection_status),
    url(r'^waf/waf_edit_global_component_protection_conf$', waf_edit_global_component_protection_conf),
    url(r'^waf/waf_exchange_global_component_protection_priority$', waf_exchange_global_component_protection_priority),

    url(r'^waf/waf_get_global_name_list_list$', waf_get_global_name_list_list),
    url(r'^waf/waf_del_global_name_list$', waf_del_global_name_list),
    url(r'^waf/waf_load_global_name_list$', waf_load_global_name_list),
    url(r'^waf/waf_edit_global_name_list$', waf_edit_global_name_list),
    url(r'^waf/waf_exchange_global_name_list_priority$', waf_exchange_global_name_list_priority),

    url(r'^waf/waf_edit_sys_base_conf$', waf_edit_sys_base_conf),
    url(r'^waf/waf_get_sys_base_conf$', waf_get_sys_base_conf),

    url(r'^waf/waf_get_remote_service_center_engine_list$', waf_get_remote_service_center_engine_list),
    url(r'^waf/waf_load_remote_service_center_engine$', waf_load_remote_service_center_engine),

    url(r'^waf/waf_get_node_monitor_list$', waf_get_node_monitor_list),
    url(r'^waf/waf_edit_node_conf_status$', waf_edit_node_conf_status),
    url(r'^waf/waf_del_node_monitor$', waf_del_node_monitor),

    url(r'^waf/waf_edit_sys_report_conf$', waf_edit_sys_report_conf),
    url(r'^waf/waf_get_sys_report_conf$', waf_get_sys_report_conf),

    url(r'^waf/waf_edit_sys_log_conf$', waf_edit_sys_log_conf),
    url(r'^waf/waf_get_sys_log_conf$', waf_get_sys_log_conf),

    url(r'^waf/waf_edit_sys_mimetic_defense_conf$', waf_edit_sys_mimetic_defense_conf),
    url(r'^waf/waf_get_sys_mimetic_defense_conf$', waf_get_sys_mimetic_defense_conf),

    url(r'^report/get_name_list_item_action_log$', report_get_name_list_item_action_log),

    url(r'^report/cls_get_raw_log$', cls_report_get_raw_log),
    url(r'^report/sls_get_raw_log$', sls_report_get_raw_log),

    url(r'^report/cls_name_list_request_count_trend$', cls_report_name_list_request_count_trend),
    url(r'^report/cls_name_list_ip_count_trend$', cls_report_name_list_ip_count_trend),
    url(r'^report/cls_name_list_request_count_totle$', cls_report_name_list_request_count_totle),
    url(r'^report/cls_name_list_request_ip_totle$', cls_report_name_list_request_ip_totle),
    url(r'^report/cls_name_list_att_type_top10$', cls_report_name_list_att_type_top10),
    url(r'^report/cls_name_list_att_ip_top10$', cls_report_name_list_att_ip_top10),
    url(r'^report/cls_name_list_att_uri_top10$', cls_report_name_list_att_uri_top10),
    url(r'^report/cls_name_list_att_ip_country_top10$', cls_report_name_list_att_ip_country_top10),

    url(r'^report/sls_name_list_request_count_trend$', sls_report_name_list_request_count_trend),
    url(r'^report/sls_name_list_ip_count_trend$', sls_report_name_list_ip_count_trend),
    url(r'^report/sls_name_list_request_count_totle$', sls_report_name_list_request_count_totle),
    url(r'^report/sls_name_list_request_ip_totle$', sls_report_name_list_request_ip_totle),
    url(r'^report/sls_name_list_att_type_top10$', sls_report_name_list_att_type_top10),
    url(r'^report/sls_name_list_att_ip_top10$', sls_report_name_list_att_ip_top10),
    url(r'^report/sls_name_list_att_uri_top10$', sls_report_name_list_att_uri_top10),
    url(r'^report/sls_name_list_att_ip_country_top10$', sls_report_name_list_att_ip_country_top10),

    url(r'^report/cls_flow_request_count_trend$', cls_report_flow_request_count_trend),
    url(r'^report/cls_flow_ip_count_trend$', cls_report_flow_ip_count_trend),
    url(r'^report/cls_flow_request_count_totle$', cls_report_flow_request_count_totle),
    url(r'^report/cls_flow_request_ip_totle$', cls_report_flow_request_ip_totle),
    url(r'^report/cls_flow_att_type_top10$', cls_report_flow_att_type_top10),
    url(r'^report/cls_flow_att_ip_top10$', cls_report_flow_att_ip_top10),
    url(r'^report/cls_flow_att_uri_top10$', cls_report_flow_att_uri_top10),
    url(r'^report/cls_flow_att_ip_country_top10$', cls_report_flow_att_ip_country_top10),

    url(r'^report/sls_flow_request_count_trend$', sls_report_flow_request_count_trend),
    url(r'^report/sls_flow_ip_count_trend$', sls_report_flow_ip_count_trend),
    url(r'^report/sls_flow_request_count_totle$', sls_report_flow_request_count_totle),
    url(r'^report/sls_flow_request_ip_totle$', sls_report_flow_request_ip_totle),
    url(r'^report/sls_flow_att_type_top10$', sls_report_flow_att_type_top10),
    url(r'^report/sls_flow_att_ip_top10$', sls_report_flow_att_ip_top10),
    url(r'^report/sls_flow_att_uri_top10$', sls_report_flow_att_uri_top10),
    url(r'^report/sls_flow_att_ip_country_top10$', sls_report_flow_att_ip_country_top10),

    url(r'^report/cls_web_request_count_trend$', cls_report_web_request_count_trend),
    url(r'^report/cls_web_ip_count_trend$', cls_report_web_ip_count_trend),
    url(r'^report/cls_web_request_count_totle$', cls_report_web_request_count_totle),
    url(r'^report/cls_web_request_ip_totle$', cls_report_web_request_ip_totle),
    url(r'^report/cls_web_att_type_top10$', cls_report_web_att_type_top10),
    url(r'^report/cls_web_att_ip_top10$', cls_report_web_att_ip_top10),
    url(r'^report/cls_web_att_uri_top10$', cls_report_web_att_uri_top10),
    url(r'^report/cls_web_att_ip_country_top10$', cls_report_web_att_ip_country_top10),

    url(r'^report/sls_web_request_count_trend$', sls_report_web_request_count_trend),
    url(r'^report/sls_web_ip_count_trend$', sls_report_web_ip_count_trend),
    url(r'^report/sls_web_request_count_totle$', sls_report_web_request_count_totle),
    url(r'^report/sls_web_request_ip_totle$', sls_report_web_request_ip_totle),
    url(r'^report/sls_web_att_type_top10$', sls_report_web_att_type_top10),
    url(r'^report/sls_web_att_ip_top10$', sls_report_web_att_ip_top10),
    url(r'^report/sls_web_att_uri_top10$', sls_report_web_att_uri_top10),
    url(r'^report/sls_web_att_ip_country_top10$', sls_report_web_att_ip_country_top10),
]
