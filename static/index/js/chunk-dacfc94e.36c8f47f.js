(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-dacfc94e"],{"4eef":function(e,t,a){},"7db0":function(e,t,a){"use strict";var o=a("23e7"),c=a("b727").find,n=a("44d2"),r="find",i=!0;r in[]&&Array(1)[r]((function(){i=!1})),o({target:"Array",proto:!0,forced:i},{find:function(e){return c(this,e,arguments.length>1?arguments[1]:void 0)}}),n(r)},d8bc:function(e,t,a){"use strict";a.r(t);var o=a("7a23"),c=Object(o["createVNode"])("h3",null,"WAF日志查询分析",-1),n=Object(o["createVNode"])("div",{class:"margin-4x"},null,-1),r={class:"domain-search-input"},i={class:"time-select-input"},l={class:"time-select-input"},s=Object(o["createTextVNode"])("查询"),u={class:"demo-block"};function d(e,t){var a=Object(o["resolveComponent"])("el-col"),d=Object(o["resolveComponent"])("el-row"),b=Object(o["resolveComponent"])("el-input"),m=Object(o["resolveComponent"])("el-option"),p=Object(o["resolveComponent"])("el-select"),f=Object(o["resolveComponent"])("el-date-picker"),g=Object(o["resolveComponent"])("el-button"),h=Object(o["resolveComponent"])("el-table-column"),j=Object(o["resolveComponent"])("el-table"),O=Object(o["resolveDirective"])("loading");return Object(o["withDirectives"])((Object(o["openBlock"])(),Object(o["createBlock"])(d,{class:"report-raw-log"},{default:Object(o["withCtx"])((function(){return[Object(o["createVNode"])(a,{span:24},{default:Object(o["withCtx"])((function(){return[Object(o["createVNode"])(d,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(o["withCtx"])((function(){return[Object(o["createVNode"])(a,{span:24},{default:Object(o["withCtx"])((function(){return[Object(o["createVNode"])(d,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(o["withCtx"])((function(){return[Object(o["createVNode"])(a,{span:12},{default:Object(o["withCtx"])((function(){return[c]})),_:1}),Object(o["createVNode"])(a,{span:12,class:"text-align-right"})]})),_:1})]})),_:1})]})),_:1}),n,Object(o["createVNode"])(d,null,{default:Object(o["withCtx"])((function(){return[Object(o["createVNode"])(a,{span:24},{default:Object(o["withCtx"])((function(){return[Object(o["createVNode"])("div",r,[Object(o["createVNode"])(b,{placeholder:"请输入查询语句","prefix-icon":"el-icon-search",modelValue:e.dataSearch,"onUpdate:modelValue":t[1]||(t[1]=function(t){return e.dataSearch=t})},null,8,["modelValue"])]),Object(o["withDirectives"])(Object(o["createVNode"])("div",i,[Object(o["createVNode"])(p,{modelValue:e.timeZone,"onUpdate:modelValue":t[2]||(t[2]=function(t){return e.timeZone=t}),placeholder:"请选择",onChange:e.onChangeTime},{default:Object(o["withCtx"])((function(){return[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(e.timeList,(function(e){return Object(o["openBlock"])(),Object(o["createBlock"])(m,{key:e.key,label:e.value,value:e.key},null,8,["label","value"])})),128))]})),_:1},8,["modelValue","onChange"])],512),[[o["vShow"],"default"!=e.timeZone]]),Object(o["withDirectives"])(Object(o["createVNode"])("div",l,[Object(o["createVNode"])(f,{modelValue:e.pickerTime,"onUpdate:modelValue":t[3]||(t[3]=function(t){return e.pickerTime=t}),type:"datetimerange","range-separator":"To","start-placeholder":"开始时间","end-placeholder":"结束时间"},null,8,["modelValue"])],512),[[o["vShow"],"default"==e.timeZone]]),Object(o["createVNode"])(g,{type:"primary",onClick:t[4]||(t[4]=function(t){return e.onClickSearch()})},{default:Object(o["withCtx"])((function(){return[s]})),_:1})]})),_:1})]})),_:1}),Object(o["createVNode"])("div",u,[Object(o["createVNode"])(j,{data:e.tableData,style:{width:"100%"}},{default:Object(o["withCtx"])((function(){return[Object(o["createVNode"])(h,{prop:"request_id",label:"请求ID"}),Object(o["createVNode"])(h,{prop:"request_time",label:"请求时间"}),Object(o["createVNode"])(h,{prop:"src_ip",label:"源IP"}),Object(o["createVNode"])(h,{prop:"host",label:"域名"}),Object(o["createVNode"])(h,{prop:"uri",label:"访问路径"}),Object(o["createVNode"])(h,{prop:"waf_module",label:"防护模块"}),Object(o["createVNode"])(h,{prop:"waf_extra",label:"防护策略"}),Object(o["createVNode"])(h,{prop:"waf_action",label:"执行动作"})]})),_:1},8,["data"])])]})),_:1})]})),_:1},512)),[[O,e.loadingPage,void 0,{fullscreen:!0,lock:!0}]])}a("7db0");var b=a("362c"),m={mixins:[b["b"]],data:function(){return{loadingPage:!0,dialogNameListItemFormVisible:!1,loading:!1,tableData:[],dataSearch:"",dataFromTime:"",dataToTime:"",timeZone:"7day",pickerTime:[],timeList:[{key:"7day",value:"7天"},{key:"24hour",value:"24小时"},{key:"1hour",value:"1小时"},{key:"default",value:"自定义"}]}},mounted:function(){this.getData()},methods:{getData:function(){var e=this;Object(b["a"])("get","/waf/waf_get_sys_report_conf",{},(function(t){e.logSource=t.data.message.log_source,""==e.logSource?e.$message({duration:0,showClose:!0,message:"报表配置未设置日志数据来源，<a href='/#/sys-report-conf' class='error-message-btn'>请前往配置</a>",type:"warning",dangerouslyUseHTMLString:!0}):e.loadingPage=!1,"ch"==e.logSource&&e.$message({duration:0,showClose:!0,message:"功能开发中",type:"warning",dangerouslyUseHTMLString:!0})}),(function(){e.loadingPage=!1}))},onClickSearch:function(){var e=this,t={},a="/report/cls_get_raw_log";"sls"==e.logSource&&(a="/report/sls_get_raw_log"),"ch"==e.logSource&&(a="/report/ch_get_raw_log"),e.dataSearch?(e.getTime(),e.onChangePicker(),t={from_time:e.dataFromTime,to_time:e.dataToTime,sql_query:e.dataSearch},Object(b["a"])("post",a,t,(function(t){if(e.loadingPage=!1,"cls"==e.logSource)for(var a=t.data.message.Results,o=0;o<a.length;o++){var c=JSON.parse(a[o].LogJson);e.tableData.push(c)}else e.tableData=t.data.message}),(function(){e.loadingPage=!1}),"no-message")):e.$message({showClose:!0,message:"请输入查询语句",type:"error"})},onChangeTime:function(e){var t={};t=this.timeList.find((function(t){return t.key===e})),this.timeZone=t.key},getTime:function(){var e=Date.parse(new Date)/1e3,t="";"7day"==this.timeZone?t=604800:"24h"==this.timeZone?t=86400:"1h"==this.timeZone&&(t=3600),this.dataFromTime=e-t,this.dataToTime=e},onChangePicker:function(){this.pickerTime.length>0&&(this.dataFromTime=this.pickerTime[0].getTime()/1e3,this.dataToTime=this.pickerTime[1].getTime()/1e3)}}};a("fbc0");m.render=d;t["default"]=m},fbc0:function(e,t,a){"use strict";a("4eef")}}]);
//# sourceMappingURL=chunk-dacfc94e.36c8f47f.js.map