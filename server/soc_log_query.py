# -*- coding:utf-8 –*-
import time
from django.http import JsonResponse
import json
from clickhouse_driver import Client
from server.models import *
import traceback


def soc_query_log(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        sql_rules = json_data.get('sql_rules', [])
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        page_number = int(json_data.get('page_number', 1))
        page_size = 20
        offset = (page_number - 1) * page_size

        where_conditions = []
        for rule in sql_rules:
            field_name = rule['field']
            operation = rule['operation']
            value = rule['value']
            if operation == 'contains':
                where_conditions.append("{} LIKE '%%{}%%'".format(field_name, value))
            elif operation == 'prefix':
                where_conditions.append("{} LIKE '{}%%'".format(field_name, value))
            elif operation == 'suffix':
                where_conditions.append("{} LIKE '%%{}'".format(field_name, value))
            elif operation == 'equals':
                where_conditions.append("{} = '{}'".format(field_name, value))
            elif operation == 'not_equals':
                where_conditions.append("{} <> '{}'".format(field_name, value))

        parse_sql_rule = ' AND '.join(where_conditions)

        additional_where = (' AND ' + parse_sql_rule) if parse_sql_rule else ''

        total_count_query = ('SELECT COUNT(*) FROM jxlog '
                             'WHERE toDateTime(RequestTime) BETWEEN toDateTime(%(from_time)s) '
                             'AND toDateTime(%(to_time)s){additional_where}').format(additional_where=additional_where)

        req_sql = (
            'SELECT Host,RequestUuid,WafNodeUUID,UpstreamAddr,UpstreamResponseTime,UpstreamStatus,Status,ProcessTime,RequestTime,RawHeaders,Scheme,Version,URI,RequestUri,Method,QueryString,RawBody,SrcIP,UserAgent,Cookie,RawRespHeaders,RawRespBody,IsoCode,City,WafModule,WafPolicy,WafAction,WafExtra,RawSrcIP FROM jxlog '
            'WHERE toDateTime(RequestTime) BETWEEN toDateTime(%(from_time)s) '
            'AND toDateTime(%(to_time)s){additional_where} order by toDateTime(RequestTime) desc LIMIT %(page_size)s OFFSET %(offset)s ').format(
            additional_where=additional_where)

        client = Client(host=sys_conf_result.report_conf_ch_host,
                        port=int(sys_conf_result.report_conf_ch_port),
                        user=sys_conf_result.report_conf_ch_user,
                        password=sys_conf_result.report_conf_ch_password,
                        database=sys_conf_result.report_conf_ch_database,
                        send_receive_timeout=30)

        query_params = {
            'from_time': from_time,
            'to_time': to_time,
            'page_size': page_size,
            'offset': offset,
        }

        total_count_result = client.execute(total_count_query, query_params)
        total_count = total_count_result[0][0]
        total_pages = (total_count + page_size - 1) // page_size
        result = client.execute(req_sql, query_params, with_column_types=True)
        column_names = [col[0] for col in result[1]]
        rows = result[0]
        data_dicts = [{column_names[i]: row[i] for i in range(len(row))} for row in rows]
        for data in data_dicts:
            request_content_parts = []

            request_line = "{method} {request_uri} HTTP/{version}".format(
                method=data.get('Method', data['Scheme'].upper()),  # 使用Method，如果不存在则使用Scheme
                request_uri=data['RequestUri'],
                version=data['Version']
            )
            request_content_parts.append(request_line)

            if data['RawHeaders']:
                raw_headers = data['RawHeaders'].split('\r\n')
                request_content_parts.extend(raw_headers)

            if data['RawBody']:
                if data['RawHeaders']:
                    request_content_parts.append('')
                request_content_parts.append(data['RawBody'])

            data['RequestContent'] = '\r\n'.join(request_content_parts)
        return_result['result'] = True
        return_result['message'] = data_dicts
        return_result['total_count'] = total_count
        return_result['total_pages'] = total_pages
        return_result['now_page'] = page_number
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)


def soc_query_log_all(request):
    return_result = {}
    try:
        user_id = request.session['user_id']
        sys_conf_result = sys_conf.objects.get(user_id=user_id)
        if sys_conf_result.report_conf == 'false':
            return_result['result'] = False
            return_result['message'] = "ClickHouse connect is not configured"
            return JsonResponse(return_result, safe=False)

        json_data = json.loads(request.body)
        sql_rules = json_data.get('sql_rules', [])
        from_time = json_data['from_time']
        to_time = json_data['to_time']
        page_number = int(json_data.get('page_number', 1))
        page_size = 20
        offset = (page_number - 1) * page_size

        where_conditions = []
        for rule in sql_rules:
            field_name = rule['field']
            operation = rule['operation']
            value = rule['value']
            if operation == 'contains':
                where_conditions.append("{} LIKE '%%{}%%'".format(field_name, value))
            elif operation == 'prefix':
                where_conditions.append("{} LIKE '{}%%'".format(field_name, value))
            elif operation == 'suffix':
                where_conditions.append("{} LIKE '%%{}'".format(field_name, value))
            elif operation == 'equals':
                where_conditions.append("{} = '{}'".format(field_name, value))
            elif operation == 'not_equals':
                where_conditions.append("{} <> '{}'".format(field_name, value))

        parse_sql_rule = ' AND '.join(where_conditions)

        additional_where = (' AND ' + parse_sql_rule) if parse_sql_rule else ''

        total_count_query = ('SELECT COUNT(*) FROM jxlog '
                             'WHERE toDateTime(RequestTime) BETWEEN toDateTime(%(from_time)s) '
                             'AND toDateTime(%(to_time)s){additional_where}').format(additional_where=additional_where)

        req_sql = (
            'SELECT * FROM jxlog '
            'WHERE toDateTime(RequestTime) BETWEEN toDateTime(%(from_time)s) '
            'AND toDateTime(%(to_time)s){additional_where} order by toDateTime(RequestTime) desc LIMIT %(page_size)s OFFSET %(offset)s ').format(
            additional_where=additional_where)

        client = Client(host=sys_conf_result.report_conf_ch_host,
                        port=int(sys_conf_result.report_conf_ch_port),
                        user=sys_conf_result.report_conf_ch_user,
                        password=sys_conf_result.report_conf_ch_password,
                        database=sys_conf_result.report_conf_ch_database,
                        send_receive_timeout=30)

        query_params = {
            'from_time': from_time,
            'to_time': to_time,
            'page_size': page_size,
            'offset': offset,
        }

        total_count_result = client.execute(total_count_query, query_params)
        total_count = total_count_result[0][0]
        total_pages = (total_count + page_size - 1) // page_size
        result = client.execute(req_sql, query_params, with_column_types=True)
        return_result['result'] = True
        return_result['message'] = result[0]
        return_result['column'] = result[1]
        return_result['total_count'] = total_count
        return_result['total_pages'] = total_pages
        return_result['now_page'] = page_number
        return JsonResponse(return_result, safe=False)
    except Exception as e:
        return_result['result'] = False
        return_result['message'] = str(e)
        return_result['detail'] = traceback.format_exc()
        return JsonResponse(return_result, safe=False)
