(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-edf08d12"],{"2a43":function(t,e,o){},"663e":function(t,e,o){"use strict";o("2a43")},e366:function(t,e,o){"use strict";o.r(e);var n=o("7a23"),a=Object(n["createVNode"])("h3",null,"流量安全报表",-1),i={class:"echart-select"},r=Object(n["createVNode"])("div",{class:"margin-4x"},null,-1),c=Object(n["createVNode"])("div",{class:"card-header"},[Object(n["createVNode"])("span",null,"攻击总数")],-1),l={class:"card-text"},u=Object(n["createVNode"])("div",{class:"card-header"},[Object(n["createVNode"])("span",null,"攻击IP总数")],-1),s={class:"card-text"},d=Object(n["createVNode"])("div",{class:"margin-4x"},null,-1),p=Object(n["createVNode"])("div",{id:"request-count-trend-flow"},null,-1),f=Object(n["createVNode"])("div",{id:"ip-count-trend-flow"},null,-1),g=Object(n["createVNode"])("div",{id:"att-type-top-flow"},null,-1),m=Object(n["createVNode"])("div",{id:"att-ip-top-flow"},null,-1),_=Object(n["createVNode"])("div",{id:"att-uri-top-flow"},null,-1),h=Object(n["createVNode"])("div",{id:"att-ip-country-top-flow"},null,-1);function b(t,e){var o=Object(n["resolveComponent"])("el-col"),b=Object(n["resolveComponent"])("el-option"),O=Object(n["resolveComponent"])("el-select"),j=Object(n["resolveComponent"])("el-row"),T=Object(n["resolveComponent"])("el-divider"),v=Object(n["resolveComponent"])("el-card"),C=Object(n["resolveDirective"])("loading");return Object(n["withDirectives"])((Object(n["openBlock"])(),Object(n["createBlock"])(j,{class:"echart-container"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:24},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(j,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[a]})),_:1}),Object(n["createVNode"])(o,{span:12,class:"text-align-right"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])("div",i,[Object(n["createVNode"])(O,{modelValue:t.domain,"onUpdate:modelValue":e[1]||(e[1]=function(e){return t.domain=e}),placeholder:"请选择",onChange:t.onChangeDomain,size:"small"},{default:Object(n["withCtx"])((function(){return[(Object(n["openBlock"])(!0),Object(n["createBlock"])(n["Fragment"],null,Object(n["renderList"])(t.domainList,(function(t){return Object(n["openBlock"])(),Object(n["createBlock"])(b,{key:t.domain,label:t.domain,value:t.domain},null,8,["label","value"])})),128))]})),_:1},8,["modelValue","onChange"]),Object(n["createVNode"])(O,{modelValue:t.timeZone,"onUpdate:modelValue":e[2]||(e[2]=function(e){return t.timeZone=e}),placeholder:"请选择",onChange:t.onChangeTime,size:"small"},{default:Object(n["withCtx"])((function(){return[(Object(n["openBlock"])(!0),Object(n["createBlock"])(n["Fragment"],null,Object(n["renderList"])(t.timeList,(function(t){return Object(n["openBlock"])(),Object(n["createBlock"])(b,{key:t.key,label:t.value,value:t.key},null,8,["label","value"])})),128))]})),_:1},8,["modelValue","onChange"])])]})),_:1})]})),_:1}),Object(n["createVNode"])(T),r,Object(n["createVNode"])(j,null,{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[Object(n["withDirectives"])(Object(n["createVNode"])(v,{class:"box-card",shadow:"never"},{header:Object(n["withCtx"])((function(){return[c]})),default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])("div",l,[Object(n["createVNode"])("span",null,Object(n["toDisplayString"])(t.requestCountTotle),1)])]})),_:1},512),[[C,t.loading.requestCountTotle]])]})),_:1}),Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[Object(n["withDirectives"])(Object(n["createVNode"])(v,{class:"box-card",shadow:"never"},{header:Object(n["withCtx"])((function(){return[u]})),default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])("div",s,[Object(n["createVNode"])("span",null,Object(n["toDisplayString"])(t.requestIpTotle),1)])]})),_:1},512),[[C,t.loading.requestIpTotle]]),d]})),_:1})]})),_:1}),Object(n["createVNode"])(j,null,{default:Object(n["withCtx"])((function(){return[Object(n["withDirectives"])(Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[p]})),_:1},512),[[C,t.loading.requestCountTrend]]),Object(n["withDirectives"])(Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[f]})),_:1},512),[[C,t.loading.ipCountTrend]])]})),_:1}),Object(n["createVNode"])(j,null,{default:Object(n["withCtx"])((function(){return[Object(n["withDirectives"])(Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[g]})),_:1},512),[[C,t.loading.attTypeTop]]),Object(n["withDirectives"])(Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[m]})),_:1},512),[[C,t.loading.attIpTop]])]})),_:1}),Object(n["createVNode"])(j,null,{default:Object(n["withCtx"])((function(){return[Object(n["withDirectives"])(Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[_]})),_:1},512),[[C,t.loading.attUriTop]]),Object(n["withDirectives"])(Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[h]})),_:1},512),[[C,t.loading.attIpCountryTop]])]})),_:1})]})),_:1})]})),_:1},512)),[[C,t.loadingPage,void 0,{fullscreen:!0,lock:!0}]])}var O=o("53ca"),j=(o("7db0"),o("fb6a"),o("87b8")),T=o("362c"),v={mixins:[T["b"]],data:function(){return{loadingPage:!1,logSource:"",domainList:[],domain:"",timeZone:"7day",timeList:[{key:"7day",value:"7天"},{key:"24hour",value:"24小时"},{key:"1hour",value:"1小时"}],loading:{requestCountTotle:!0,requestIpTotle:!0,requestCountTrend:!0,ipCountTrend:!0,attTypeTop:!0,attIpTop:!0,attUriTop:!0,attIpCountryTop:!0},requestCountTotle:"0",requestIpTotle:"0"}},computed:{rules:function(){return{public_key:[{required:!0,message:"请输入公钥",trigger:"blur"}]}}},created:function(){-1==location.href.indexOf("#reloaded")&&(location.href=location.href+"#reloaded",location.reload())},mounted:function(){this.getdomainListData(),this.getData()},methods:{getdomainListData:function(){var t=this;Object(T["a"])("get","/waf/waf_get_domain_list",{},(function(e){t.loadingPage=!1,t.domainList=e.data.message,t.domainList.unshift({domain:"All"}),t.domain=t.domainList[0].domain}),(function(){t.loadingPage=!1}))},getData:function(){var t=this;Object(T["a"])("get","/waf/waf_get_sys_report_conf",{},(function(e){t.loadingPage=!1,t.logSource=e.data.message.log_source,""==t.logSource?t.$message({duration:0,showClose:!0,message:"报表配置未设置日志数据来源，<a href='/#/sys-report-conf' class='error-message-btn'>请前往配置</a>",type:"warning",dangerouslyUseHTMLString:!0}):(t.getRequestCountTotle(),t.getRequestIpTotle(),t.getRequestCountTrend(),t.getIpCountTrend(),t.getAttTypeTop(),t.getAttIpTop(),t.getAttUriTop(),t.getAttIpCountryTop())}),(function(){t.loadingPage=!1}))},getRequestCountTotle:function(){var t=this;t.loading.requestCountTotle=!0;var e="/report/cls_flow_request_count_totle";"sls"==t.logSource&&(e="/report/sls_flow_request_count_totle"),"ch"==t.logSource&&(e="/report/ch_flow_request_count_totle");var o={time_zone:t.timeZone,domain:t.domain};""!=t.domain&&"All"!=t.domain||(o={time_zone:t.timeZone}),Object(T["a"])("post",e,o,(function(e){if("cls"==t.logSource){var o=e.data.message.AnalysisResults;t.requestCountTotle=o[0].Data[0].Value}else"sls"==t.logSource?t.requestCountTotle=e.data.message[0].count:"ch"==t.logSource&&(t.requestCountTotle=e.data.message[0][0]);t.loading.requestCountTotle=!1}),(function(){t.loading.requestCountTotle=!1}),"no-message")},getRequestIpTotle:function(){var t=this;t.loading.requestIpTotle=!0;var e="/report/cls_flow_request_ip_totle";"sls"==t.logSource&&(e="/report/sls_flow_request_ip_totle"),"ch"==t.logSource&&(e="/report/ch_flow_request_ip_totle");var o={time_zone:t.timeZone,domain:t.domain};""!=t.domain&&"All"!=t.domain||(o={time_zone:t.timeZone}),Object(T["a"])("post",e,o,(function(e){if("cls"==t.logSource){var o=e.data.message.AnalysisResults;t.requestIpTotle=o[0].Data[0].Value}else"sls"==t.logSource?t.requestIpTotle=e.data.message[0].count:"ch"==t.logSource&&(t.requestIpTotle=e.data.message[0][0]);t.loading.requestIpTotle=!1}),(function(){t.loading.requestIpTotle=!1}),"no-message")},getRequestCountTrend:function(){var t=this;t.loading.requestCountTrend=!0;var e="/report/cls_flow_request_count_trend";"sls"==t.logSource&&(e="/report/sls_flow_request_count_trend"),"ch"==t.logSource&&(e="/report/ch_flow_request_count_trend");var o={time_zone:t.timeZone,domain:t.domain};""!=t.domain&&"All"!=t.domain||(o={time_zone:t.timeZone}),Object(T["a"])("post",e,o,(function(e){t.requestCountTrend=e.data.message,t.loading.requestCountTrend=!1,t.initLineChart(t.requestCountTrend,"request-count-trend-flow","攻击流量趋势图")}),(function(){t.loading.requestCountTrend=!1}),"no-message")},getIpCountTrend:function(){var t=this;t.loading.ipCountTrend=!0;var e="/report/cls_flow_ip_count_trend";"sls"==t.logSource&&(e="/report/sls_flow_ip_count_trend"),"ch"==t.logSource&&(e="/report/ch_flow_ip_count_trend");var o={time_zone:t.timeZone,domain:t.domain};""!=t.domain&&"All"!=t.domain||(o={time_zone:t.timeZone}),Object(T["a"])("post",e,o,(function(e){t.loading.ipCountTrend=!1,t.ipCountTrend=e.data.message,t.initLineChart(t.ipCountTrend,"ip-count-trend-flow","攻击IP数量趋势图")}),(function(){t.loading.ipCountTrend=!1}),"no-message")},getAttTypeTop:function(){var t=this;t.loading.attTypeTop=!0;var e="/report/cls_flow_att_type_top10";"sls"==t.logSource&&(e="/report/sls_flow_att_type_top10"),"ch"==t.logSource&&(e="/report/ch_flow_att_type_top10");var o={time_zone:t.timeZone,domain:t.domain};""!=t.domain&&"All"!=t.domain||(o={time_zone:t.timeZone}),Object(T["a"])("post",e,o,(function(e){t.loading.attTypeTop=!1,t.attTypeTop=e.data.message,t.initBarChart(t.attTypeTop,"att-type-top-flow","命中防护-TOP10","waf_policy")}),(function(){t.loading.attTypeTop=!1}),"no-message")},getAttIpTop:function(){var t=this;t.loading.attIpTop=!0;var e="/report/cls_flow_att_ip_top10";"sls"==t.logSource&&(e="/report/sls_flow_att_ip_top10"),"ch"==t.logSource&&(e="/report/ch_flow_att_ip_top10");var o={time_zone:t.timeZone,domain:t.domain};""!=t.domain&&"All"!=t.domain||(o={time_zone:t.timeZone}),Object(T["a"])("post",e,o,(function(e){t.loading.attIpTop=!1,t.attIpTop=e.data.message,t.initBarChart(t.attIpTop,"att-ip-top-flow","攻击IP-TOP10","src_ip")}),(function(){t.loading.attIpTop=!1}),"no-message")},getAttUriTop:function(){var t=this;t.loading.attUriTop=!0;var e="/report/cls_flow_att_uri_top10";"sls"==t.logSource&&(e="/report/sls_flow_att_uri_top10"),"ch"==t.logSource&&(e="/report/ch_flow_att_uri_top10");var o={time_zone:t.timeZone,domain:t.domain};""!=t.domain&&"All"!=t.domain||(o={time_zone:t.timeZone}),Object(T["a"])("post",e,o,(function(e){t.loading.attUriTop=!1,t.attUriTop=e.data.message,t.initBarChart(t.attUriTop,"att-uri-top-flow","攻击URL-TOP10","src_ip")}),(function(){t.loading.attUriTop=!1}),"no-message")},getAttIpCountryTop:function(){var t=this;t.loading.attIpCountryTop=!0;var e="/report/cls_flow_att_ip_country_top10";"sls"==t.logSource&&(e="/report/sls_flow_att_ip_country_top10"),"ch"==t.logSource&&(e="/report/ch_flow_att_ip_country_top10");var o={time_zone:t.timeZone,domain:t.domain};""!=t.domain&&"All"!=t.domain||(o={time_zone:t.timeZone}),Object(T["a"])("post",e,o,(function(e){t.loading.attIpCountryTop=!1,t.attIpCountryTop=e.data.message,t.initBarChart(t.attIpCountryTop,"att-ip-country-top-flow","攻击来源地区-TOP10","src_ip")}),(function(){t.loading.attIpCountryTop=!1}),"no-message")},onChangeDomain:function(t){var e={};e=this.domainList.find((function(e){return e.domain===t})),this.domain=e.domain,this.getData()},onChangeTime:function(t){var e={};e=this.timeList.find((function(e){return e.key===t})),this.timeZone=e.key,this.getData()},initLineChart:function(t,e,o){var n=[],a=[],i=o||"";if("cls"==this.logSource)for(var r=t.AnalysisResults,c=t.ColNames,l=0;l<r.length;l++)for(var u=r[l].Data,s=0;s<u.length;s++)u[s].Key==c[0]&&n.push(u[s].Value),u[s].Key==c[1]&&a.push(u[s].Value);if("sls"==this.logSource)for(var d=t,p=0;p<d.length;p++)n.push(d[p].time),a.push(d[p].count);if("ch"==this.logSource)for(var f=t,g=0;g<f.length;g++)n.push(f[g][0]),a.push(f[g][1]);var m={title:{text:i},color:["#c23531"],tooltip:{trigger:"axis"},xAxis:{type:"category",data:n,axisLabel:{formatter:function(t){return t.length>20?"".concat(t.slice(0,20),"..."):t}}},yAxis:{type:"value"},series:[{data:a,type:"line"}]};this.buildChart(e,m)},initBarChart:function(t,e,o,n){var a=[],i=[],r=o||"";if("cls"==this.logSource)for(var c=t.AnalysisResults,l=t.ColNames,u=0;u<c.length;u++)for(var s=c[u].Data,d=0;d<s.length;d++)s[d].Key==l[0]&&i.push(s[d].Value),s[d].Key==l[1]&&a.push(s[d].Value);else if("sls"==this.logSource)for(var p=t,f=0;f<p.length;f++)i.push(p[f][n]),a.push(p[f].count);else if("ch"==this.logSource)for(var g=t,m=0;m<g.length;m++)i.push(g[m][0]),a.push(g[m][1]);var _={title:{text:r},color:["#c23531","#2f4554","#61a0a8","#d48265","#91c7ae","#749f83","#ca8622","#bda29a","#6e7074","#546570","#c4ccd3"],tooltip:{trigger:"axis",axisPointer:{type:"shadow"}},grid:{left:"3%",right:"4%",bottom:"3%",containLabel:!0},yAxis:{type:"category",data:i,axisLabel:{formatter:function(t){return t.length>20?"".concat(t.slice(0,20),"..."):t}}},xAxis:{type:"value"},series:[{data:a,type:"bar"}]};this.buildChart(e,_)},buildChart:function(t,e){if(document.querySelector("#"+t)){var o=e||[],n=j["a"].init(document.getElementById(t));o&&"object"===Object(O["a"])(o)&&n.setOption(o,!0)}}}};o("663e");v.render=b;e["default"]=v}}]);
//# sourceMappingURL=chunk-edf08d12.e1dc1606.js.map