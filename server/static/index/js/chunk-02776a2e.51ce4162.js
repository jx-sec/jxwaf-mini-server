(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-02776a2e"],{"3e0a":function(e,t,o){"use strict";o("d092")},"528c":function(e,t,o){"use strict";o.r(t);var a=o("7a23");const n=Object(a["createVNode"])("h3",null,"名单防护报表",-1),i={class:"echart-select"},r=Object(a["createVNode"])("div",{class:"margin-4x"},null,-1),l=Object(a["createVNode"])("div",{class:"card-header"},[Object(a["createVNode"])("span",null,"攻击总数")],-1),s={class:"card-text"},c=Object(a["createVNode"])("div",{class:"card-header"},[Object(a["createVNode"])("span",null,"攻击IP总数")],-1),d={class:"card-text"},u=Object(a["createVNode"])("div",{class:"margin-4x"},null,-1),p=Object(a["createVNode"])("div",{id:"request-count-trend"},null,-1),m=Object(a["createVNode"])("div",{id:"ip-count-trend"},null,-1),_=Object(a["createVNode"])("div",{id:"att-type-top"},null,-1),g=Object(a["createVNode"])("div",{id:"att-ip-top"},null,-1),h=Object(a["createVNode"])("div",{id:"att-uri-top"},null,-1),b=Object(a["createVNode"])("div",{id:"att-ip-country-top"},null,-1);function O(e,t,o,O,j,T){const C=Object(a["resolveComponent"])("el-col"),f=Object(a["resolveComponent"])("el-option"),v=Object(a["resolveComponent"])("el-select"),y=Object(a["resolveComponent"])("el-row"),w=Object(a["resolveComponent"])("el-divider"),V=Object(a["resolveComponent"])("el-card"),q=Object(a["resolveDirective"])("loading");return Object(a["withDirectives"])((Object(a["openBlock"])(),Object(a["createBlock"])(y,{class:"echart-container"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{span:24},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(y,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[n]),_:1}),Object(a["createVNode"])(C,{span:12,class:"text-align-right"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])("div",i,[Object(a["createVNode"])(v,{modelValue:j.domain,"onUpdate:modelValue":t[1]||(t[1]=e=>j.domain=e),placeholder:"请选择",onChange:T.onChangeDomain,size:"small"},{default:Object(a["withCtx"])(()=>[(Object(a["openBlock"])(!0),Object(a["createBlock"])(a["Fragment"],null,Object(a["renderList"])(j.domainList,e=>(Object(a["openBlock"])(),Object(a["createBlock"])(f,{key:e.domain,label:e.domain,value:e.domain},null,8,["label","value"]))),128))]),_:1},8,["modelValue","onChange"]),Object(a["createVNode"])(v,{modelValue:j.timeZone,"onUpdate:modelValue":t[2]||(t[2]=e=>j.timeZone=e),placeholder:"请选择",onChange:T.onChangeTime,size:"small"},{default:Object(a["withCtx"])(()=>[(Object(a["openBlock"])(!0),Object(a["createBlock"])(a["Fragment"],null,Object(a["renderList"])(j.timeList,e=>(Object(a["openBlock"])(),Object(a["createBlock"])(f,{key:e.key,label:e.value,value:e.key},null,8,["label","value"]))),128))]),_:1},8,["modelValue","onChange"])])]),_:1})]),_:1}),Object(a["createVNode"])(w),r,Object(a["createVNode"])(y,null,{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[Object(a["withDirectives"])(Object(a["createVNode"])(V,{class:"box-card",shadow:"never"},{header:Object(a["withCtx"])(()=>[l]),default:Object(a["withCtx"])(()=>[Object(a["createVNode"])("div",s,[Object(a["createVNode"])("span",null,Object(a["toDisplayString"])(j.requestCountTotle),1)])]),_:1},512),[[q,j.loading.requestCountTotle]])]),_:1}),Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[Object(a["withDirectives"])(Object(a["createVNode"])(V,{class:"box-card",shadow:"never"},{header:Object(a["withCtx"])(()=>[c]),default:Object(a["withCtx"])(()=>[Object(a["createVNode"])("div",d,[Object(a["createVNode"])("span",null,Object(a["toDisplayString"])(j.requestIpTotle),1)])]),_:1},512),[[q,j.loading.requestIpTotle]]),u]),_:1})]),_:1}),Object(a["createVNode"])(y,null,{default:Object(a["withCtx"])(()=>[Object(a["withDirectives"])(Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[p]),_:1},512),[[q,j.loading.requestCountTrend]]),Object(a["withDirectives"])(Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[m]),_:1},512),[[q,j.loading.ipCountTrend]])]),_:1}),Object(a["createVNode"])(y,null,{default:Object(a["withCtx"])(()=>[Object(a["withDirectives"])(Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[_]),_:1},512),[[q,j.loading.attTypeTop]]),Object(a["withDirectives"])(Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[g]),_:1},512),[[q,j.loading.attIpTop]])]),_:1}),Object(a["createVNode"])(y,null,{default:Object(a["withCtx"])(()=>[Object(a["withDirectives"])(Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[h]),_:1},512),[[q,j.loading.attUriTop]]),Object(a["withDirectives"])(Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[b]),_:1},512),[[q,j.loading.attIpCountryTop]])]),_:1})]),_:1})]),_:1},512)),[[q,j.loadingPage,void 0,{fullscreen:!0,lock:!0}]])}var j=o("87b8"),T=o("362c"),C={mixins:[T["b"]],data(){return{loadingPage:!1,logSource:"",domainList:[],domain:"",timeZone:"7day",timeList:[{key:"7day",value:"7天"},{key:"24hour",value:"24小时"},{key:"1hour",value:"1小时"}],loading:{requestCountTotle:!0,requestIpTotle:!0,requestCountTrend:!0,ipCountTrend:!0,attTypeTop:!0,attIpTop:!0,attUriTop:!0,attIpCountryTop:!0},requestCountTotle:"0",requestIpTotle:"0"}},computed:{rules(){return{public_key:[{required:!0,message:"请输入公钥",trigger:"blur"}]}}},created(){-1==location.href.indexOf("#reloaded")&&(location.href=location.href+"#reloaded",location.reload())},mounted(){this.getdomainListData(),this.getData()},methods:{getdomainListData(){var e=this;Object(T["a"])("get","/waf/waf_get_domain_list",{},(function(t){e.loadingPage=!1,e.domainList=t.data.message,e.domainList.unshift({domain:"All"}),e.domain=e.domainList[0].domain}),(function(){e.loadingPage=!1}))},getData(){var e=this;Object(T["a"])("get","/waf/waf_get_sys_report_conf",{},(function(t){e.loadingPage=!1,e.logSource=t.data.message.log_source,""==e.logSource?e.$message({duration:0,showClose:!0,message:"报表配置未设置日志数据来源，<a href='/#/sys-report-conf' class='error-message-btn'>请前往配置</a>",type:"warning",dangerouslyUseHTMLString:!0}):(e.getRequestCountTotle(),e.getRequestIpTotle(),e.getRequestCountTrend(),e.getIpCountTrend(),e.getAttTypeTop(),e.getAttIpTop(),e.getAttUriTop(),e.getAttIpCountryTop())}),(function(){e.loadingPage=!1}))},getRequestCountTotle(){var e=this;e.loading.requestCountTotle=!0;var t="/report/cls_name_list_request_count_totle";"sls"==e.logSource&&(t="/report/sls_name_list_request_count_totle"),"ch"==e.logSource&&(t="/report/ch_name_list_request_count_totle");var o={time_zone:e.timeZone,domain:e.domain};""!=e.domain&&"All"!=e.domain||(o={time_zone:e.timeZone}),Object(T["a"])("post",t,o,(function(t){if("cls"==e.logSource){var o=t.data.message.AnalysisResults;e.requestCountTotle=o[0].Data[0].Value}else"sls"==e.logSource?e.requestCountTotle=t.data.message[0].count:"ch"==e.logSource&&(e.requestCountTotle=t.data.message[0][0]);e.loading.requestCountTotle=!1}),(function(){e.loading.requestCountTotle=!1}),"no-message")},getRequestIpTotle(){var e=this;e.loading.requestIpTotle=!0;var t="/report/cls_name_list_request_ip_totle";"sls"==e.logSource&&(t="/report/sls_name_list_request_ip_totle"),"ch"==e.logSource&&(t="/report/ch_name_list_request_ip_totle");var o={time_zone:e.timeZone,domain:e.domain};""!=e.domain&&"All"!=e.domain||(o={time_zone:e.timeZone}),Object(T["a"])("post",t,o,(function(t){if("cls"==e.logSource){var o=t.data.message.AnalysisResults;e.requestIpTotle=o[0].Data[0].Value}else"sls"==e.logSource?e.requestIpTotle=t.data.message[0].count:"ch"==e.logSource&&(e.requestIpTotle=t.data.message[0][0]);e.loading.requestIpTotle=!1}),(function(){e.loading.requestIpTotle=!1}),"no-message")},getRequestCountTrend(){var e=this;e.loading.requestCountTrend=!0;var t="/report/cls_name_list_request_count_trend";"sls"==e.logSource&&(t="/report/sls_name_list_request_count_trend"),"ch"==e.logSource&&(t="/report/ch_name_list_request_count_trend");var o={time_zone:e.timeZone,domain:e.domain};""!=e.domain&&"All"!=e.domain||(o={time_zone:e.timeZone}),Object(T["a"])("post",t,o,(function(t){e.requestCountTrend=t.data.message,e.loading.requestCountTrend=!1,e.initLineChart(e.requestCountTrend,"request-count-trend","攻击流量趋势图")}),(function(){e.loading.requestCountTrend=!1}),"no-message")},getIpCountTrend(){var e=this;e.loading.ipCountTrend=!0;var t="/report/cls_name_list_ip_count_trend";"sls"==e.logSource&&(t="/report/sls_name_list_ip_count_trend"),"ch"==e.logSource&&(t="/report/ch_name_list_ip_count_trend");var o={time_zone:e.timeZone,domain:e.domain};""!=e.domain&&"All"!=e.domain||(o={time_zone:e.timeZone}),Object(T["a"])("post",t,o,(function(t){e.loading.ipCountTrend=!1,e.ipCountTrend=t.data.message,e.initLineChart(e.ipCountTrend,"ip-count-trend","攻击IP数量趋势图")}),(function(){e.loading.ipCountTrend=!1}),"no-message")},getAttTypeTop(){var e=this;e.loading.attTypeTop=!0;var t="/report/cls_name_list_att_type_top10";"sls"==e.logSource&&(t="/report/sls_name_list_att_type_top10"),"ch"==e.logSource&&(t="/report/ch_name_list_att_type_top10");var o={time_zone:e.timeZone,domain:e.domain};""!=e.domain&&"All"!=e.domain||(o={time_zone:e.timeZone}),Object(T["a"])("post",t,o,(function(t){e.loading.attTypeTop=!1,e.attTypeTop=t.data.message,e.initBarChart(e.attTypeTop,"att-type-top","命中防护-TOP10","waf_policy")}),(function(){e.loading.attTypeTop=!1}),"no-message")},getAttIpTop(){var e=this;e.loading.attIpTop=!0;var t="/report/cls_name_list_att_ip_top10";"sls"==e.logSource&&(t="/report/sls_name_list_att_ip_top10"),"ch"==e.logSource&&(t="/report/ch_name_list_att_ip_top10");var o={time_zone:e.timeZone,domain:e.domain};""!=e.domain&&"All"!=e.domain||(o={time_zone:e.timeZone}),Object(T["a"])("post",t,o,(function(t){e.loading.attIpTop=!1,e.attIpTop=t.data.message,e.initBarChart(e.attIpTop,"att-ip-top","攻击IP-TOP10","src_ip")}),(function(){e.loading.attIpTop=!1}),"no-message")},getAttUriTop(){var e=this;e.loading.attUriTop=!0;var t="/report/cls_name_list_att_uri_top10";"sls"==e.logSource&&(t="/report/sls_name_list_att_uri_top10"),"ch"==e.logSource&&(t="/report/ch_name_list_att_uri_top10");var o={time_zone:e.timeZone,domain:e.domain};""!=e.domain&&"All"!=e.domain||(o={time_zone:e.timeZone}),Object(T["a"])("post",t,o,(function(t){e.loading.attUriTop=!1,e.attUriTop=t.data.message,e.initBarChart(e.attUriTop,"att-uri-top","攻击URL-TOP10","src_ip")}),(function(){e.loading.attUriTop=!1}),"no-message")},getAttIpCountryTop(){var e=this;e.loading.attIpCountryTop=!0;var t="/report/cls_name_list_att_ip_country_top10";"sls"==e.logSource&&(t="/report/sls_name_list_att_ip_country_top10"),"ch"==e.logSource&&(t="/report/ch_name_list_att_ip_country_top10");var o={time_zone:e.timeZone,domain:e.domain};""!=e.domain&&"All"!=e.domain||(o={time_zone:e.timeZone}),Object(T["a"])("post",t,o,(function(t){e.loading.attIpCountryTop=!1,e.attIpCountryTop=t.data.message,e.initBarChart(e.attIpCountryTop,"att-ip-country-top","攻击来源地区-TOP10","src_ip")}),(function(){e.loading.attIpCountryTop=!1}),"no-message")},onChangeDomain(e){var t={};t=this.domainList.find(t=>t.domain===e),this.domain=t.domain,this.getData()},onChangeTime(e){var t={};t=this.timeList.find(t=>t.key===e),this.timeZone=t.key,this.getData()},initLineChart(e,t,o){var a=[],n=[],i=o||"";if("cls"==this.logSource)for(var r=e.AnalysisResults,l=e.ColNames,s=0;s<r.length;s++)for(var c=r[s].Data,d=0;d<c.length;d++)c[d].Key==l[0]&&a.push(c[d].Value),c[d].Key==l[1]&&n.push(c[d].Value);if("sls"==this.logSource)for(var u=e,p=0;p<u.length;p++)a.push(u[p].time),n.push(u[p].count);if("ch"==this.logSource)for(var m=e,_=0;_<m.length;_++)a.push(m[_][0]),n.push(m[_][1]);var g={title:{text:i},color:["#c23531"],tooltip:{trigger:"axis"},xAxis:{type:"category",data:a,axisLabel:{formatter:function(e){return e.length>20?e.slice(0,20)+"...":e}}},yAxis:{type:"value"},series:[{data:n,type:"line"}]};this.buildChart(t,g)},initBarChart(e,t,o,a){var n=[],i=[],r=o||"";if("cls"==this.logSource)for(var l=e.AnalysisResults,s=e.ColNames,c=0;c<l.length;c++)for(var d=l[c].Data,u=0;u<d.length;u++)d[u].Key==s[0]&&i.push(d[u].Value),d[u].Key==s[1]&&n.push(d[u].Value);else if("sls"==this.logSource)for(var p=e,m=0;m<p.length;m++)i.push(p[m][a]),n.push(p[m].count);else if("ch"==this.logSource)for(var _=e,g=0;g<_.length;g++)i.push(_[g][0]),n.push(_[g][1]);var h={title:{text:r},color:["#c23531","#2f4554","#61a0a8","#d48265","#91c7ae","#749f83","#ca8622","#bda29a","#6e7074","#546570","#c4ccd3"],tooltip:{trigger:"axis",axisPointer:{type:"shadow"}},grid:{left:"3%",right:"4%",bottom:"3%",containLabel:!0},yAxis:{type:"category",data:i,axisLabel:{formatter:function(e){return e.length>20?e.slice(0,20)+"...":e}}},xAxis:{type:"value"},series:[{data:n,type:"bar"}]};this.buildChart(t,h)},buildChart(e,t){if(document.querySelector("#"+e)){var o=t||[],a=j["a"].init(document.getElementById(e));o&&"object"===typeof o&&a.setOption(o,!0)}}}},f=(o("3e0a"),o("d959")),v=o.n(f);const y=v()(C,[["render",O]]);t["default"]=y},d092:function(e,t,o){}}]);
//# sourceMappingURL=chunk-02776a2e.51ce4162.js.map