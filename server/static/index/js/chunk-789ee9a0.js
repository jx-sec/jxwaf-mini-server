(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-789ee9a0"],{"1e44":function(e,t,o){"use strict";o("f65e")},2667:function(e,t,o){"use strict";o.r(t);o("b0c0");var n=o("7a23"),i={class:"custom-wrap"},l=Object(n["createVNode"])("h3",null,"全局组件管理",-1),a=Object(n["createVNode"])("div",{class:"margin-4x"},null,-1),c=Object(n["createTextVNode"])("优先级调整"),r=Object(n["createTextVNode"])("加载组件"),u={class:"demo-block"},d=Object(n["createVNode"])("p",null,"确定删除吗？",-1),s={style:{"text-align":"right",margin:"0"}},b=Object(n["createTextVNode"])("取消"),f=Object(n["createTextVNode"])("确定 "),g=Object(n["createTextVNode"])("删除"),w=Object(n["createTextVNode"])("取消"),p=Object(n["createTextVNode"])("确定 ");function O(e,t){var o=Object(n["resolveComponent"])("el-col"),O=Object(n["resolveComponent"])("el-row"),j=Object(n["resolveComponent"])("el-button"),m=Object(n["resolveComponent"])("el-table-column"),h=Object(n["resolveComponent"])("el-switch"),C=Object(n["resolveComponent"])("el-popover"),V=Object(n["resolveComponent"])("el-table"),v=Object(n["resolveComponent"])("el-option"),x=Object(n["resolveComponent"])("el-select"),_=Object(n["resolveComponent"])("el-form-item"),k=Object(n["resolveComponent"])("el-form"),N=Object(n["resolveComponent"])("el-dialog"),D=Object(n["resolveDirective"])("loading");return Object(n["openBlock"])(),Object(n["createBlock"])("div",i,[Object(n["createVNode"])(O,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:24},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(O,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[l]})),_:1})]})),_:1})]})),_:1})]})),_:1}),a,Object(n["withDirectives"])(Object(n["createVNode"])(O,null,{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:24},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(O,{class:"text-align-right"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(j,{type:"success",onClick:t[1]||(t[1]=function(t){return e.onClickChangeOrder()})},{default:Object(n["withCtx"])((function(){return[c]})),_:1}),Object(n["createVNode"])(j,{type:"primary",onClick:t[2]||(t[2]=function(t){return e.onClickDownloadRule()}),loading:e.loadingDownloadRule},{default:Object(n["withCtx"])((function(){return[r]})),_:1},8,["loading"])]})),_:1}),Object(n["createVNode"])("div",u,[Object(n["createVNode"])(V,{data:e.tableData,style:{width:"100%"}},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(m,{prop:"name",label:"组件名称"}),Object(n["createVNode"])(m,{prop:"conf",label:"组件配置"}),Object(n["createVNode"])(m,{prop:"status",label:"组件状态"},{default:Object(n["withCtx"])((function(t){return[Object(n["createVNode"])(h,{modelValue:t.row.status,"onUpdate:modelValue":function(e){return t.row.status=e},onChange:function(o){return e.onChangeRuleStatus(t.row)},"active-value":"true","inactive-value":"false"},null,8,["modelValue","onUpdate:modelValue","onChange"])]})),_:1}),Object(n["createVNode"])(m,{label:"操作",align:"right"},{default:Object(n["withCtx"])((function(t){return[Object(n["createVNode"])(C,{placement:"top",width:"160",visible:t.row.isVisiblePopover,"onUpdate:visible":function(e){return t.row.isVisiblePopover=e}},{reference:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(j,{type:"text",size:"mini",onClick:function(e){return t.row.isVisiblePopover=!0}},{default:Object(n["withCtx"])((function(){return[g]})),_:2},1032,["onClick"])]})),default:Object(n["withCtx"])((function(){return[d,Object(n["createVNode"])("div",s,[Object(n["createVNode"])(j,{size:"mini",type:"text",onClick:function(e){return t.row.isVisiblePopover=!1}},{default:Object(n["withCtx"])((function(){return[b]})),_:2},1032,["onClick"]),Object(n["createVNode"])(j,{type:"primary",size:"mini",onClick:function(o){return e.handleDelete(t.row)},loading:e.loading},{default:Object(n["withCtx"])((function(){return[f]})),_:2},1032,["onClick","loading"])])]})),_:2},1032,["visible","onUpdate:visible"])]})),_:1}),e.isShowOrder?Object(n["createCommentVNode"])("",!0):(Object(n["openBlock"])(),Object(n["createBlock"])(m,{key:0,label:"优先级",align:"right"},{default:Object(n["withCtx"])((function(t){return[Object(n["createVNode"])(j,{type:"success",class:"icon iconfont iconxiangshang",circle:"",onClick:function(o){return e.onClickChangeOrderSubmit(t.$index,t.row,"up")},title:"上移",loading:e.orderLoading},null,8,["onClick","loading"]),Object(n["createVNode"])(j,{type:"success",class:"icon iconfont iconxiangxia",circle:"",onClick:function(o){return e.onClickChangeOrderSubmit(t.$index,t.row,"down")},title:"下移",loading:e.orderLoading},null,8,["onClick","loading"]),Object(n["createVNode"])(j,{type:"success",class:"icon iconfont iconzhiding",circle:"",onClick:function(o){return e.onClickChangeOrderSubmit(t.$index,t.row,"top")},title:"置顶",loading:e.orderLoading},null,8,["onClick","loading"])]})),_:1}))]})),_:1},8,["data"])])]})),_:1}),Object(n["createVNode"])(N,{modelValue:e.dialogDownloadRuleFormVisible,"onUpdate:modelValue":t[6]||(t[6]=function(t){return e.dialogDownloadRuleFormVisible=t}),title:"加载","close-on-click-modal":!1,width:"520px",onClosed:e.dialogCloseDownloadRule},{footer:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(j,{onClick:t[4]||(t[4]=function(t){return e.dialogDownloadRuleFormVisible=!1})},{default:Object(n["withCtx"])((function(){return[w]})),_:1}),Object(n["createVNode"])(j,{type:"primary",onClick:t[5]||(t[5]=function(t){return e.onClickDownloadRuleSubmit("downloadRuleForm")}),loading:e.loading},{default:Object(n["withCtx"])((function(){return[p]})),_:1},8,["loading"])]})),default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(k,{class:"form-download-rule-dialog",model:e.downloadRuleForm,"label-position":"left","label-width":"130px",rules:e.rules,ref:"downloadRuleForm"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(_,{label:"加载组件",key:"1",prop:"uuid"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(x,{modelValue:e.downloadRuleForm.uuid,"onUpdate:modelValue":t[3]||(t[3]=function(t){return e.downloadRuleForm.uuid=t}),placeholder:"请选择或输入模糊搜索",filterable:""},{default:Object(n["withCtx"])((function(){return[(Object(n["openBlock"])(!0),Object(n["createBlock"])(n["Fragment"],null,Object(n["renderList"])(e.ruleOptions,(function(e){return Object(n["openBlock"])(),Object(n["createBlock"])(v,{key:e.uuid,label:e.name,value:e.uuid},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})]})),_:1},8,["model","rules"])]})),_:1},8,["modelValue","onClosed"])]})),_:1},512),[[D,e.loadingPage,void 0,{fullscreen:!0,lock:!0}]])])}o("159b");var j=o("362c"),m={mixins:[j["b"]],data:function(){return{loading:!1,loadingPage:!1,isShowOrder:!0,orderLoading:!1,tableData:[],dialogDownloadRuleFormVisible:!1,loadingDownloadRule:!1,downloadRuleForm:[],ruleOptions:[],jsontest:""}},computed:{rules:function(){return{uuid:[{required:!0,message:"请选择一个规则",trigger:"change"}]}}},mounted:function(){this.getData();var e={name:"JSON中国",url:"http://www.json.org.cn",page:88,isNonProfit:!0,address:{street:"浙大路38号.",city:"浙江杭州",country:"中国"},links:[{name:"Google",url:"http://www.google.com"},{name:"Baidu",url:"http://www.baidu.com"},{name:"SoSo",url:"http://www.SoSo.com"}]};this.jsontest=JSON.stringify(e,null,2),console.log(this.jsontest)},methods:{getData:function(){var e=this,t="/waf/waf_get_global_component_protection_list",o={};Object(j["a"])("post",t,o,(function(t){e.loadingPage=!1,e.tableData=t.data.message,e.tableData.forEach((function(e){e.isVisiblePopover=!1}))}),(function(){e.loadingPage=!1}),"no-message")},onClickDownloadRule:function(){var e=this;e.loadingDownloadRule=!0,e.dialogDownloadRuleFormVisible=!0,Object(j["a"])("post","/waf/waf_get_sys_component_protection_list",{},(function(t){e.loadingDownloadRule=!1;var o=t.data.message;e.ruleOptions=e.getDifference(e.tableData,o)}),(function(){e.loadingDownloadRule=!1}),"no-message")},getDifference:function(e,t){var o=[];return t.forEach((function(t){var n=!0;e.forEach((function(e){e.uuid==t.uuid&&(n=!1)})),n&&o.push(t)})),o},onClickDownloadRuleSubmit:function(e){var t=this,o="/waf/waf_load_global_component_protection",n={uuid:t.downloadRuleForm.uuid};this.$refs[e].validate((function(e){e&&(t.loading=!0,Object(j["a"])("post",o,n,(function(e){t.loading=!1,t.dialogDownloadRuleFormVisible=!1,t.getData()}),(function(){t.loading=!1})))}))},dialogCloseDownloadRule:function(){this.downloadRuleForm=[],this.$refs["downloadRuleForm"].resetFields()},handleDelete:function(e){var t=this;t.loading=!0;var o="/waf/waf_del_global_component_protection",n={uuid:e.uuid};Object(j["a"])("post",o,n,(function(o){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))},onClickChangeOrder:function(){var e=this;e.isShowOrder=!e.isShowOrder},onClickChangeOrderSubmit:function(e,t,o){var n=this,i={uuid:t.uuid};e>0&&("top"==o&&(i.type="top"),"up"==o&&(i.type="exchange",i.exchange_uuid=n.tableData[e-1].uuid)),e<n.tableData.length-1&&"down"==o&&(i.type="exchange",i.exchange_uuid=n.tableData[e+1].uuid);var l="/waf/waf_edit_global_component_protection_conf";"top"!=i.type&&"exchange"!=i.type||(n.orderLoading=!0,Object(j["a"])("post",l,i,(function(e){n.orderLoading=!1,n.getData()}),(function(){n.orderLoading=!1}),"no-message"))},onChangeRuleStatus:function(e){var t=this,o={uuid:e.uuid,status:e.status},n="/waf/waf_edit_global_component_protection_status";Object(j["a"])("post",n,o,(function(e){t.getData()}),(function(){}),"no-message")}}};o("1e44");m.render=O;t["default"]=m},f65e:function(e,t,o){}}]);
//# sourceMappingURL=chunk-789ee9a0.js.map