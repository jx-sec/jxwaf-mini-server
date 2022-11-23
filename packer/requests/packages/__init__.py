import sys

# This code exists for backwards compatibility reasons.

modules_list = [
     'urllib3', 'chardet', 'chardet.big5prober', 'chardet.chardetect',
     'chardet.chardistribution', 'chardet.charsetgroupprober', 'chardet.charsetprober',
     'chardet.codingstatemachine', 'chardet.compat', 'chardet.constants',
     'chardet.cp949prober', 'chardet.escprober', 'chardet.escsm', 'chardet.eucjpprober',
     'chardet.euckrfreq', 'chardet.euckrprober', 'chardet.euctwfreq', 'chardet.euctwprober',
     'chardet.gb2312freq', 'chardet.gb2312prober', 'chardet.hebrewprober',
     'chardet.jisfreq', 'chardet.jpcntx', 'chardet.langbulgarianmodel',
     'chardet.langcyrillicmodel', 'chardet.langgreekmodel', 'chardet.langhebrewmodel',
     'chardet.langhungarianmodel', 'chardet.langthaimodel', 'chardet.latin1prober',
     'chardet.mbcharsetprober', 'chardet.mbcsgroupprober', 'chardet.mbcssm',
     'chardet.sbcharsetprober', 'chardet.sbcsgroupprober', 'chardet.sjisprober',
     'chardet.universaldetector', 'chardet.utf8prober', 'urllib3._collections',
     'urllib3.connectionpool', 'urllib3.connection', 'urllib3.contrib', 'urllib3.exceptions',
     'urllib3.fields', 'urllib3.filepost', 'urllib3.packages', 'urllib3.poolmanager',
     'urllib3.request', 'urllib3.response', 'urllib3.util', 'urllib3.contrib.ntlmpool',
     'urllib3.contrib.pyopenssl', 'urllib3.util.connection', 'urllib3.util.request',
     'urllib3.util.response', 'urllib3.util.retry', 'urllib3.util.ssl_', 'urllib3.util.timeout',
     'urllib3.util.url', 'urllib3.packages.ordered_dict', 'urllib3.packages.six',
     'urllib3.packages.ssl_match_hostname', 'urllib3.packages.ssl_match_hostname.implementation'
     ]


for package in modules_list:
    try:
        __import__(package)
    except ImportError:
        pass
    else:
        sys.modules['requests.packages.' + package] = sys.modules[package]
        globals()[package] = sys.modules[package]
