(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-30239c38"],{c33b:function(e,t,o){},ca31:function(e,t,o){"use strict";o.r(t);var a=o("7a23");const l={class:"custom-wrap"},i=Object(a["createVNode"])("h3",null,"分析组件防护",-1),n=Object(a["createVNode"])("div",{class:"margin-4x"},null,-1),c=Object(a["createTextVNode"])("优先级调整"),d=Object(a["createTextVNode"])("加载组件"),r={class:"demo-block"},u=Object(a["createVNode"])("p",null,"确定删除吗？",-1),s={style:{"text-align":"right",margin:"0"}},b=Object(a["createTextVNode"])("取消"),p=Object(a["createTextVNode"])("确定 "),g=Object(a["createTextVNode"])("删除"),m=Object(a["createTextVNode"])("取消"),O=Object(a["createTextVNode"])("确定 ");function w(e,t,o,w,j,f){const h=Object(a["resolveComponent"])("el-col"),_=Object(a["resolveComponent"])("el-row"),C=Object(a["resolveComponent"])("el-button"),V=Object(a["resolveComponent"])("el-table-column"),x=Object(a["resolveComponent"])("el-switch"),y=Object(a["resolveComponent"])("el-popover"),v=Object(a["resolveComponent"])("el-table"),k=Object(a["resolveComponent"])("el-option"),N=Object(a["resolveComponent"])("el-select"),D=Object(a["resolveComponent"])("el-form-item"),R=Object(a["resolveComponent"])("el-form"),F=Object(a["resolveComponent"])("el-dialog"),T=Object(a["resolveDirective"])("loading");return Object(a["openBlock"])(),Object(a["createBlock"])("div",l,[Object(a["createVNode"])(_,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(h,{span:24},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(_,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(h,{span:12},{default:Object(a["withCtx"])(()=>[i]),_:1}),Object(a["createVNode"])(h,{span:12,class:"text-align-right"},{default:Object(a["withCtx"])(()=>["single_rule"==j.ruleType?(Object(a["openBlock"])(),Object(a["createBlock"])("a",{key:0,class:"el-button el-button--primary is-plain",href:"/#/protection/"+j.domain+"/"+j.ruleType},"返回",8,["href"])):Object(a["createCommentVNode"])("",!0),"group_rule"==j.ruleType?(Object(a["openBlock"])(),Object(a["createBlock"])("a",{key:1,class:"el-button el-button--primary is-plain",href:"/#/group-protection/"+j.domain},"返回",8,["href"])):Object(a["createCommentVNode"])("",!0)]),_:1})]),_:1})]),_:1})]),_:1}),n,Object(a["withDirectives"])(Object(a["createVNode"])(_,null,{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(h,{span:24},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(_,{class:"text-align-right"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{type:"success",onClick:t[1]||(t[1]=e=>f.onClickChangeOrder())},{default:Object(a["withCtx"])(()=>[c]),_:1}),Object(a["createVNode"])(C,{type:"primary",onClick:t[2]||(t[2]=e=>f.onClickDownloadRule()),loading:j.loadingDownloadRule},{default:Object(a["withCtx"])(()=>[d]),_:1},8,["loading"])]),_:1}),Object(a["createVNode"])("div",r,[Object(a["createVNode"])(v,{data:j.tableData,style:{width:"100%"}},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(V,{prop:"name",label:"组件名称"}),Object(a["createVNode"])(V,{prop:"conf",label:"配置"}),Object(a["createVNode"])(V,{prop:"status",label:"状态"},{default:Object(a["withCtx"])(e=>[Object(a["createVNode"])(x,{modelValue:e.row.status,"onUpdate:modelValue":t=>e.row.status=t,onChange:t=>f.onChangeRuleStatus(e.row),"active-value":"true","inactive-value":"false"},null,8,["modelValue","onUpdate:modelValue","onChange"])]),_:1}),Object(a["createVNode"])(V,{label:"操作",align:"right"},{default:Object(a["withCtx"])(e=>[Object(a["createVNode"])(y,{placement:"top",width:"160",visible:e.row.isVisiblePopover,"onUpdate:visible":t=>e.row.isVisiblePopover=t},{reference:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{type:"text",size:"mini",onClick:t=>e.row.isVisiblePopover=!0},{default:Object(a["withCtx"])(()=>[g]),_:2},1032,["onClick"])]),default:Object(a["withCtx"])(()=>[u,Object(a["createVNode"])("div",s,[Object(a["createVNode"])(C,{size:"mini",type:"text",onClick:t=>e.row.isVisiblePopover=!1},{default:Object(a["withCtx"])(()=>[b]),_:2},1032,["onClick"]),Object(a["createVNode"])(C,{type:"primary",size:"mini",onClick:t=>f.handleDelete(e.row),loading:j.loading},{default:Object(a["withCtx"])(()=>[p]),_:2},1032,["onClick","loading"])])]),_:2},1032,["visible","onUpdate:visible"])]),_:1}),j.isShowOrder?Object(a["createCommentVNode"])("",!0):(Object(a["openBlock"])(),Object(a["createBlock"])(V,{key:0,label:"优先级",align:"right"},{default:Object(a["withCtx"])(e=>[Object(a["createVNode"])(C,{type:"success",class:"icon iconfont iconxiangshang",circle:"",onClick:t=>f.onClickChangeOrderSubmit(e.$index,e.row,"up"),title:"上移",loading:j.orderLoading},null,8,["onClick","loading"]),Object(a["createVNode"])(C,{type:"success",class:"icon iconfont iconxiangxia",circle:"",onClick:t=>f.onClickChangeOrderSubmit(e.$index,e.row,"down"),title:"下移",loading:j.orderLoading},null,8,["onClick","loading"]),Object(a["createVNode"])(C,{type:"success",class:"icon iconfont iconzhiding",circle:"",onClick:t=>f.onClickChangeOrderSubmit(e.$index,e.row,"top"),title:"置顶",loading:j.orderLoading},null,8,["onClick","loading"])]),_:1}))]),_:1},8,["data"])])]),_:1}),Object(a["createVNode"])(F,{modelValue:j.dialogDownloadRuleFormVisible,"onUpdate:modelValue":t[6]||(t[6]=e=>j.dialogDownloadRuleFormVisible=e),title:"加载","close-on-click-modal":!1,width:"520px",onClosed:f.dialogCloseDownloadRule},{footer:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{onClick:t[4]||(t[4]=e=>j.dialogDownloadRuleFormVisible=!1)},{default:Object(a["withCtx"])(()=>[m]),_:1}),Object(a["createVNode"])(C,{type:"primary",onClick:t[5]||(t[5]=e=>f.onClickDownloadRuleSubmit("downloadRuleForm")),loading:j.loading},{default:Object(a["withCtx"])(()=>[O]),_:1},8,["loading"])]),default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(R,{class:"form-download-rule-dialog",model:j.downloadRuleForm,"label-position":"left","label-width":"130px",rules:f.rules,ref:"downloadRuleForm"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(D,{label:"加载组件",key:"1",prop:"uuid"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(N,{modelValue:j.downloadRuleForm.uuid,"onUpdate:modelValue":t[3]||(t[3]=e=>j.downloadRuleForm.uuid=e),placeholder:"请选择或输入模糊搜索",filterable:""},{default:Object(a["withCtx"])(()=>[(Object(a["openBlock"])(!0),Object(a["createBlock"])(a["Fragment"],null,Object(a["renderList"])(j.ruleOptions,e=>(Object(a["openBlock"])(),Object(a["createBlock"])(k,{key:e.uuid,label:e.name,value:e.uuid},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1})]),_:1},8,["model","rules"])]),_:1},8,["modelValue","onClosed"])]),_:1},512),[[T,j.loadingPage,void 0,{fullscreen:!0,lock:!0}]])])}var j=o("362c"),f=o("6c02"),h={mixins:[j["b"]],data(){return{loading:!1,loadingPage:!1,isShowOrder:!0,orderLoading:!1,tableData:[],domain:"",ruleType:"",dialogDownloadRuleFormVisible:!1,loadingDownloadRule:!1,downloadRuleForm:[],ruleOptions:[],dialogLookRuleFormVisible:!1,lookRuleForm:[]}},computed:{rules(){return{uuid:[{required:!0,message:"请选择一个规则",trigger:"change"}]}}},mounted(){const e=Object(f["c"])();this.ruleType=e.params.ruleType,this.domain=e.params.domain,this.getData()},methods:{getData(){var e=this,t="/waf/waf_get_analysis_component_list",o={domain:e.domain};"group_rule"==e.ruleType&&(t="/waf/waf_get_group_analysis_component_list",o={group_id:e.domain}),Object(j["a"])("post",t,o,(function(t){e.loadingPage=!1,e.tableData=t.data.message,e.tableData.forEach(e=>{e.isVisiblePopover=!1})}),(function(){e.loadingPage=!1}),"no-message")},onClickDownloadRule(){var e=this;e.loadingDownloadRule=!0,e.dialogDownloadRuleFormVisible=!0,Object(j["a"])("post","/waf/waf_get_sys_component_protection_list",{},(function(t){e.loadingDownloadRule=!1;var o=t.data.message;e.ruleOptions=e.getDifference(e.tableData,o)}),(function(){e.loadingDownloadRule=!1}),"no-message")},getDifference(e,t){var o=[];return t.forEach(t=>{var a=!0;e.forEach(e=>{e.uuid==t.uuid&&(a=!1)}),a&&o.push(t)}),o},onClickDownloadRuleSubmit(e){var t=this,o="/waf/waf_load_analysis_component",a={uuid:t.downloadRuleForm.uuid,domain:t.domain};"group_rule"==t.ruleType&&(o="/waf/waf_load_group_analysis_component",a={uuid:t.downloadRuleForm.uuid,group_id:t.domain}),this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(j["a"])("post",o,a,(function(e){t.loading=!1,t.dialogDownloadRuleFormVisible=!1,t.getData()}),(function(){t.loading=!1})))})},dialogCloseDownloadRule(){this.downloadRuleForm=[],this.$refs["downloadRuleForm"].resetFields()},handleDelete(e){var t=this;t.loading=!0;var o="/waf/waf_del_analysis_component",a={domain:t.domain,uuid:e.uuid};"group_rule"==t.ruleType&&(o="/waf/waf_del_group_analysis_component",a={group_id:t.domain,uuid:e.uuid}),Object(j["a"])("post",o,a,(function(o){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))},onClickChangeOrder(){var e=this;e.isShowOrder=!e.isShowOrder},onClickChangeOrderSubmit(e,t,o){var a=this,l={uuid:t.uuid};e>0&&("top"==o&&(l.type="top"),"up"==o&&(l.type="exchange",l.exchange_uuid=a.tableData[e-1].uuid)),e<a.tableData.length-1&&"down"==o&&(l.type="exchange",l.exchange_uuid=a.tableData[e+1].uuid);var i="/waf/waf_exchange_analysis_component_priority";"group_rule"==a.ruleType?(i="/waf/waf_exchange_group_analysis_component_priority",l.group_id=a.domain):l.domain=a.domain,"top"!=l.type&&"exchange"!=l.type||(a.orderLoading=!0,Object(j["a"])("post",i,l,(function(e){a.orderLoading=!1,a.getData()}),(function(){a.orderLoading=!1}),"no-message"))},onChangeRuleStatus(e){var t=this,o={domain:t.domain,uuid:e.uuid,status:e.status},a="/waf/waf_edit_analysis_component_conf";"group_rule"==t.ruleType&&(a="/waf/waf_edit_group_analysis_component_conf",o={group_id:t.domain,uuid:e.uuid,status:e.status}),Object(j["a"])("post",a,o,(function(e){t.getData()}),(function(){}),"no-message")}}},_=(o("efd1"),o("d959")),C=o.n(_);const V=C()(h,[["render",w]]);t["default"]=V},efd1:function(e,t,o){"use strict";o("c33b")}}]);
//# sourceMappingURL=chunk-30239c38.fd50a8ae.js.map