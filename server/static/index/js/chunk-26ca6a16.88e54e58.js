(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-26ca6a16"],{"1cbc":function(e,t,a){e.exports=a.p+"static/index/img/yw.0e25ffb1.png"},7005:function(e,t,a){"use strict";a.r(t);var c=a("7a23"),l=a("e880"),s=a.n(l),o=a("9d64"),i=a.n(o),r=a("1cbc"),d=a.n(r);const n=Object(c["createTextVNode"])("运营中心"),b=Object(c["createTextVNode"])("业务数据统计"),m={class:"query-time-container statistics"},j={class:"statistics-container"},O=Object(c["createVNode"])("div",{class:"left-content"},[Object(c["createVNode"])("div",{class:"content"},[Object(c["createVNode"])("p",null,"用户"),Object(c["createVNode"])("img",{src:s.a,alt:"user"})])],-1),g={class:"middle-content"},u={class:"progress-left"},p=Object(c["createVNode"])("div",{class:"progress-item"},[Object(c["createVNode"])("div",{class:"line-box"},[Object(c["createVNode"])("div",{class:"line line-1"}),Object(c["createVNode"])("i",{class:"el-icon-arrow-right arrow-1"})])],-1),v={class:"progress-text"},V={class:"text-box"},N={class:"item"},h=Object(c["createVNode"])("div",{class:"title"},"请求次数",-1),w={class:"detail"},f={class:"item"},_=Object(c["createVNode"])("div",{class:"title"},"请求成功次数",-1),D={class:"detail"},T={class:"item"},C=Object(c["createVNode"])("div",{class:"title"},"请求失败次数",-1),S={class:"detail"},x={class:"item"},k=Object(c["createVNode"])("div",{class:"title"},"请求平均耗时",-1),y={class:"detail"},q={class:"item"},P=Object(c["createVNode"])("div",{class:"title"},"请求耗时中位数",-1),U={class:"detail"},B=Object(c["createVNode"])("div",{class:"content"},[Object(c["createVNode"])("p",null,"WAF"),Object(c["createVNode"])("img",{src:i.a,alt:"logo"})],-1),L={class:"progress-right"},M=Object(c["createVNode"])("div",{class:"progress-item"},[Object(c["createVNode"])("div",{class:"line-box"},[Object(c["createVNode"])("div",{class:"line line-2"}),Object(c["createVNode"])("i",{class:"el-icon-arrow-right arrow-2"})])],-1),A={class:"progress-text"},F={class:"text-box"},H={class:"item"},R=Object(c["createVNode"])("div",{class:"title"},"回源次数",-1),J={class:"detail"},$={class:"item"},W=Object(c["createVNode"])("div",{class:"title"},"回源成功次数",-1),z={class:"detail"},E={class:"item"},G=Object(c["createVNode"])("div",{class:"title"},"回源失败次数",-1),I={class:"detail"},K={class:"item"},Q=Object(c["createVNode"])("div",{class:"title"},"回源平均耗时",-1),X={class:"detail"},Y={class:"item"},Z=Object(c["createVNode"])("div",{class:"title"},"回源耗时中位数",-1),ee={class:"detail"},te=Object(c["createVNode"])("div",{class:"right-content"},[Object(c["createVNode"])("div",{class:"content"},[Object(c["createVNode"])("p",null,"业务服务器"),Object(c["createVNode"])("img",{src:d.a,alt:"server"})])],-1),ae=Object(c["createVNode"])("div",{style:{padding:"15px 0 5px 0","border-top":"1px solid #ebeef5",color:"#4e5969"}},[Object(c["createVNode"])("p",null,"业务服务器负载情况")],-1),ce={class:"demo-block"};function le(e,t,a,l,s,o){const i=Object(c["resolveComponent"])("el-breadcrumb-item"),r=Object(c["resolveComponent"])("el-breadcrumb"),d=Object(c["resolveComponent"])("el-row"),le=Object(c["resolveComponent"])("el-option"),se=Object(c["resolveComponent"])("el-select"),oe=Object(c["resolveComponent"])("el-date-picker"),ie=Object(c["resolveComponent"])("el-button"),re=Object(c["resolveComponent"])("el-col"),de=Object(c["resolveComponent"])("el-table-column"),ne=Object(c["resolveComponent"])("el-table"),be=Object(c["resolveDirective"])("loading");return Object(c["openBlock"])(),Object(c["createBlock"])("div",null,[Object(c["createVNode"])(d,{class:"breadcrumb-style"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(r,{separator:"/"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(i,{to:{path:"/soc-statistics"}},{default:Object(c["withCtx"])(()=>[n]),_:1}),Object(c["createVNode"])(i,null,{default:Object(c["withCtx"])(()=>[b]),_:1})]),_:1})]),_:1}),Object(c["createVNode"])(d,{class:"container-style"},{default:Object(c["withCtx"])(()=>[Object(c["withDirectives"])(Object(c["createVNode"])(re,{span:24},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])("div",m,[Object(c["withDirectives"])(Object(c["createVNode"])(se,{modelValue:s.valueTime,"onUpdate:modelValue":t[1]||(t[1]=e=>s.valueTime=e),placeholder:"Select",onChange:o.onChangeSelectTime},{default:Object(c["withCtx"])(()=>[(Object(c["openBlock"])(!0),Object(c["createBlock"])(c["Fragment"],null,Object(c["renderList"])(s.optionTime,e=>(Object(c["openBlock"])(),Object(c["createBlock"])(le,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue","onChange"]),[[c["vShow"],s.isShowSelectTime]]),Object(c["withDirectives"])(Object(c["createVNode"])("div",null,[Object(c["createVNode"])(oe,{modelValue:s.pickerTime,"onUpdate:modelValue":t[2]||(t[2]=e=>s.pickerTime=e),type:"datetimerange","range-separator":"-","start-placeholder":"开始时间","end-placeholder":"结束时间",onChange:o.changeTimeline},null,8,["modelValue","onChange"])],512),[[c["vShow"],!s.isShowSelectTime]]),Object(c["createVNode"])(ie,{icon:"el-icon-search",onClick:o.onChangeSearch,class:"search-icon-btn"},null,8,["onClick"])]),Object(c["createVNode"])("div",j,[Object(c["createVNode"])(d,null,{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(re,{span:5},{default:Object(c["withCtx"])(()=>[O]),_:1}),Object(c["createVNode"])(re,{span:14},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])("div",g,[Object(c["createVNode"])("div",u,[p,Object(c["createVNode"])("div",v,[Object(c["createVNode"])("div",V,[Object(c["createVNode"])("div",N,[h,Object(c["createVNode"])("div",w,Object(c["toDisplayString"])(s.tableData.total_requests),1)]),Object(c["createVNode"])("div",f,[_,Object(c["createVNode"])("div",D,Object(c["toDisplayString"])(s.tableData.successful_requests),1)]),Object(c["createVNode"])("div",T,[C,Object(c["createVNode"])("div",S,Object(c["toDisplayString"])(s.tableData.failed_requests),1)]),Object(c["createVNode"])("div",x,[k,Object(c["createVNode"])("div",y,Object(c["toDisplayString"])(s.tableData.avg_request_time_ms)+"s",1)]),Object(c["createVNode"])("div",q,[P,Object(c["createVNode"])("div",U,Object(c["toDisplayString"])(s.tableData.median_request_time_ms)+"s",1)])])])]),B,Object(c["createVNode"])("div",L,[M,Object(c["createVNode"])("div",A,[Object(c["createVNode"])("div",F,[Object(c["createVNode"])("div",H,[R,Object(c["createVNode"])("div",J,Object(c["toDisplayString"])(s.tableData.total_upstream_requests),1)]),Object(c["createVNode"])("div",$,[W,Object(c["createVNode"])("div",z,Object(c["toDisplayString"])(s.tableData.successful_upstream_requests),1)]),Object(c["createVNode"])("div",E,[G,Object(c["createVNode"])("div",I,Object(c["toDisplayString"])(s.tableData.failed_upstream_requests),1)]),Object(c["createVNode"])("div",K,[Q,Object(c["createVNode"])("div",X,Object(c["toDisplayString"])(s.tableData.avg_upstream_time_ms)+"s",1)]),Object(c["createVNode"])("div",Y,[Z,Object(c["createVNode"])("div",ee,Object(c["toDisplayString"])(s.tableData.median_upstream_time_ms)+"s",1)])])])])])]),_:1}),Object(c["createVNode"])(re,{span:5},{default:Object(c["withCtx"])(()=>[te]),_:1})]),_:1})]),ae,Object(c["createVNode"])("div",ce,[Object(c["createVNode"])(ne,{data:s.tableDataDetail,style:{width:"100%"}},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(de,{prop:"Host",label:"域名"}),Object(c["createVNode"])(de,{prop:"UpstreamAddr",label:"回源地址"}),Object(c["createVNode"])(de,{prop:"TotalUpstreamRequests",label:"回源次数"}),Object(c["createVNode"])(de,{prop:"SuccessfulUpstreamRequests",label:"回源成功次数"}),Object(c["createVNode"])(de,{prop:"FailedUpstreamRequests",label:"回源失败次数"}),Object(c["createVNode"])(de,{prop:"AvgUpstreamTimeMs",label:"回源平均耗时"}),Object(c["createVNode"])(de,{prop:"MedianUpstreamTimeMs",label:"回源耗时中位数"})]),_:1},8,["data"])])]),_:1},512),[[be,s.loadingPage,void 0,{fullscreen:!0,lock:!0}]])]),_:1})])}var se=a("362c"),oe={mixins:[se["c"]],data(){return{dataSearch:"",loadingPage:!1,loading:!1,tableData:{},tableDataDetail:[],isShowSelectTime:!0,valueTime:"1w",pickerTime:[],optionTime:[{value:"1h",label:"1小时"},{value:"1d",label:"24小时"},{value:"1w",label:"7天"},{value:"1m",label:"30天"},{value:"default",label:"自定义"}]}},computed:{rules(){return{}}},mounted(){this.onChangeSelectTime(),this.getDataConf()},methods:{getDataConf(){var e=this;Object(se["a"])("post","/waf/waf_get_sys_report_conf_conf",{},(function(t){e.loadingPage=!1,e.logSource=t.data.message.report_conf,"false"==e.logSource?e.$message({duration:0,showClose:!0,message:"日志查询功能未配置，<a href='/#/sys-report-conf' class='error-message-btn'>点击前往配置</a>",type:"warning",dangerouslyUseHTMLString:!0}):e.getDataConfLog()}),(function(){e.loadingPage=!1}),"no-message")},getDataConfLog(){var e=this;Object(se["a"])("post","/waf/waf_get_sys_log_conf",{},(function(t){e.loadingPage=!1,e.log_all=t.data.message.log_all,e.log_conf_remote=t.data.message.log_conf_remote,"true"==e.log_all&&"true"==e.log_conf_remote?(e.getData(),e.getDataDetail()):e.$message({duration:0,showClose:!0,message:"日志传输功能未开启全流量日志记录，<a href='/#/sys-log-conf' class='error-message-btn'>点击前往配置</a>",type:"warning",dangerouslyUseHTMLString:!0})}),(function(){e.loadingPage=!1}),"no-message")},getData(){var e=this;Object(se["a"])("post","/soc/soc_query_request_statistics",{from_time:Object(se["b"])(e.pickerTime[0]),to_time:Object(se["b"])(e.pickerTime[1])},(function(t){e.loadingPage=!1,e.tableData=t.data.message}),(function(){e.loadingPage=!1}),"no-message")},getDataDetail(){var e=this;Object(se["a"])("post","/soc/soc_query_request_statistics_detail",{from_time:Object(se["b"])(e.pickerTime[0]),to_time:Object(se["b"])(e.pickerTime[1])},(function(t){e.loadingPage=!1,e.tableDataDetail=t.data.message}),(function(){e.loadingPage=!1}),"no-message")},onChangeSelectTime(){var e=this;"default"==e.valueTime?(e.isShowSelectTime=!1,e.pickerTime=[new Date((new Date).getTime()-864e5),new Date]):(e.isShowSelectTime=!0,"1h"==e.valueTime&&(e.pickerTime=[new Date((new Date).getTime()-36e5),new Date]),"1d"==e.valueTime&&(e.pickerTime=[new Date((new Date).getTime()-864e5),new Date]),"1w"==e.valueTime&&(e.pickerTime=[new Date((new Date).getTime()-6048e5),new Date]),"1m"==e.valueTime&&(e.pickerTime=[new Date((new Date).getTime()-2592e6),new Date]))},changeTimeline(e){var t=this;null==e?(t.isShowSelectTime=!0,t.valueTime="1w"):t.isShowSelectTime=!1},onChangeSearch(){this.onChangeSelectTime(),this.getData(),this.getDataDetail()}}},ie=(a("8315"),a("d959")),re=a.n(ie);const de=re()(oe,[["render",le]]);t["default"]=de},8315:function(e,t,a){"use strict";a("e6e5")},"9d64":function(e,t,a){e.exports=a.p+"static/index/img/logo.87ab72a5.png"},e6e5:function(e,t,a){},e880:function(e,t,a){e.exports=a.p+"static/index/img/kh.66795c6e.png"}}]);
//# sourceMappingURL=chunk-26ca6a16.88e54e58.js.map