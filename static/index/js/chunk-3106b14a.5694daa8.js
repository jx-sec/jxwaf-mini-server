(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-3106b14a"],{"57b8":function(e,t,a){"use strict";a("8c59")},"8c59":function(e,t,a){},"8c85":function(e,t,a){"use strict";a.r(t);var o=a("7a23");const c={class:"custom-wrap"},l=Object(o["createTextVNode"])("防护管理"),i=Object(o["createTextVNode"])("基础组件"),n={class:"data-search-input"},r=Object(o["createTextVNode"])("优先级调整"),d=Object(o["createTextVNode"])("新建组件"),s={class:"demo-block"},b=Object(o["createTextVNode"])("编辑"),u=Object(o["createVNode"])("p",null,"确定删除吗？",-1),m={style:{"text-align":"right",margin:"0"}},p=Object(o["createTextVNode"])("取消"),O=Object(o["createTextVNode"])("确定 "),g=Object(o["createTextVNode"])("删除"),h=Object(o["createTextVNode"])("取消"),j=Object(o["createTextVNode"])("确定 ");function C(e,t,a,C,f,V){const w=Object(o["resolveComponent"])("el-breadcrumb-item"),x=Object(o["resolveComponent"])("el-breadcrumb"),_=Object(o["resolveComponent"])("el-row"),N=Object(o["resolveComponent"])("el-input"),k=Object(o["resolveComponent"])("el-button"),v=Object(o["resolveComponent"])("el-table-column"),y=Object(o["resolveComponent"])("el-switch"),S=Object(o["resolveComponent"])("el-popover"),F=Object(o["resolveComponent"])("el-table"),P=Object(o["resolveComponent"])("el-col"),D=Object(o["resolveComponent"])("el-form-item"),T=Object(o["resolveComponent"])("el-form"),U=Object(o["resolveComponent"])("el-dialog"),J=Object(o["resolveDirective"])("loading");return Object(o["openBlock"])(),Object(o["createBlock"])("div",c,[Object(o["createVNode"])(_,{class:"breadcrumb-style"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(x,{separator:"/"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(w,{to:{path:"/"}},{default:Object(o["withCtx"])(()=>[l]),_:1}),Object(o["createVNode"])(w,null,{default:Object(o["withCtx"])(()=>[i]),_:1})]),_:1})]),_:1}),Object(o["createVNode"])(_,{class:"container-style"},{default:Object(o["withCtx"])(()=>[Object(o["withDirectives"])(Object(o["createVNode"])(P,{span:24},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(_,{class:"text-align-right"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",n,[Object(o["createVNode"])(N,{placeholder:"请输入名单名称进行搜索","prefix-icon":"el-icon-search",modelValue:f.dataSearch,"onUpdate:modelValue":t[1]||(t[1]=e=>f.dataSearch=e)},null,8,["modelValue"]),Object(o["createVNode"])(k,{icon:"el-icon-search",onClick:V.onChangeSearch,class:"search-icon-btn"},null,8,["onClick"])]),Object(o["createVNode"])(k,{type:"success",onClick:t[2]||(t[2]=e=>V.onClickChangeOrder())},{default:Object(o["withCtx"])(()=>[r]),_:1}),Object(o["createVNode"])(k,{type:"primary",onClick:t[3]||(t[3]=e=>V.onClickCreate())},{default:Object(o["withCtx"])(()=>[d]),_:1})]),_:1}),Object(o["createVNode"])("div",s,[Object(o["createVNode"])(F,{data:f.tableData.filter(e=>!f.dataSearch||e.name.toLowerCase().includes(f.dataSearch.toLowerCase())),style:{width:"100%"}},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(v,{prop:"name",label:"组件名称"}),Object(o["createVNode"])(v,{prop:"detail",label:"组件描述"}),Object(o["createVNode"])(v,{prop:"conf",label:"配置"}),Object(o["createVNode"])(v,{prop:"status",label:"状态"},{default:Object(o["withCtx"])(e=>[Object(o["createVNode"])(y,{modelValue:e.row.status,"onUpdate:modelValue":t=>e.row.status=t,onChange:t=>V.onChangeRuleStatus(e.row),"active-value":"true","inactive-value":"false"},null,8,["modelValue","onUpdate:modelValue","onChange"])]),_:1}),Object(o["createVNode"])(v,{label:"操作",align:"right"},{default:Object(o["withCtx"])(e=>[Object(o["createVNode"])(k,{size:"mini",onClick:t=>V.handleEdit(e.row),class:"button-block",type:"text"},{default:Object(o["withCtx"])(()=>[b]),_:2},1032,["onClick"]),Object(o["createVNode"])(S,{placement:"top",width:"160",visible:e.row.isVisiblePopover,"onUpdate:visible":t=>e.row.isVisiblePopover=t},{reference:Object(o["withCtx"])(()=>[Object(o["createVNode"])(k,{type:"text",size:"mini",onClick:t=>e.row.isVisiblePopover=!0},{default:Object(o["withCtx"])(()=>[g]),_:2},1032,["onClick"])]),default:Object(o["withCtx"])(()=>[u,Object(o["createVNode"])("div",m,[Object(o["createVNode"])(k,{size:"mini",type:"text",onClick:t=>e.row.isVisiblePopover=!1},{default:Object(o["withCtx"])(()=>[p]),_:2},1032,["onClick"]),Object(o["createVNode"])(k,{type:"primary",size:"mini",onClick:t=>V.handleDelete(e.row),loading:f.loading},{default:Object(o["withCtx"])(()=>[O]),_:2},1032,["onClick","loading"])])]),_:2},1032,["visible","onUpdate:visible"])]),_:1}),f.isShowOrder?Object(o["createCommentVNode"])("",!0):(Object(o["openBlock"])(),Object(o["createBlock"])(v,{key:0,label:"优先级",align:"right"},{default:Object(o["withCtx"])(e=>[Object(o["createVNode"])(k,{type:"success",class:"icon iconfont iconxiangshang",circle:"",onClick:t=>V.onClickChangeOrderSubmit(e.$index,e.row,"up"),title:"上移",loading:f.orderLoading},null,8,["onClick","loading"]),Object(o["createVNode"])(k,{type:"success",class:"icon iconfont iconxiangxia",circle:"",onClick:t=>V.onClickChangeOrderSubmit(e.$index,e.row,"down"),title:"下移",loading:f.orderLoading},null,8,["onClick","loading"]),Object(o["createVNode"])(k,{type:"success",class:"icon iconfont iconzhiding",circle:"",onClick:t=>V.onClickChangeOrderSubmit(e.$index,e.row,"top"),title:"置顶",loading:f.orderLoading},null,8,["onClick","loading"])]),_:1}))]),_:1},8,["data"])])]),_:1},512),[[J,f.loadingPage,void 0,{fullscreen:!0,lock:!0}]]),Object(o["createVNode"])(U,{modelValue:f.dialogCreateFormVisible,"onUpdate:modelValue":t[11]||(t[11]=e=>f.dialogCreateFormVisible=e),title:f.title,"close-on-click-modal":!1,width:"520px",onClosed:V.dialogCloseCreate},{footer:Object(o["withCtx"])(()=>[Object(o["createVNode"])(k,{onClick:t[9]||(t[9]=e=>f.dialogCreateFormVisible=!1)},{default:Object(o["withCtx"])(()=>[h]),_:1}),Object(o["createVNode"])(k,{type:"primary",onClick:t[10]||(t[10]=e=>V.onClickCreateSubmit("createForm")),loading:f.loading},{default:Object(o["withCtx"])(()=>[j]),_:1},8,["loading"])]),default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(T,{class:"form-download-rule-dialog",model:f.createForm,"label-position":"left","label-width":"130px",rules:V.rules,ref:"createForm"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(D,{label:"组件名称",key:"1",prop:"name"},{default:Object(o["withCtx"])(()=>["new"==f.type?(Object(o["openBlock"])(),Object(o["createBlock"])(N,{key:0,modelValue:f.createForm.name,"onUpdate:modelValue":t[4]||(t[4]=e=>f.createForm.name=e),placeholder:"Please input"},null,8,["modelValue"])):(Object(o["openBlock"])(),Object(o["createBlock"])(N,{key:1,modelValue:f.createForm.name,"onUpdate:modelValue":t[5]||(t[5]=e=>f.createForm.name=e),placeholder:"Please input",disabled:""},null,8,["modelValue"]))]),_:1}),Object(o["createVNode"])(D,{label:"组件描述",key:"2"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(N,{modelValue:f.createForm.detail,"onUpdate:modelValue":t[6]||(t[6]=e=>f.createForm.detail=e),placeholder:"Please input"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(D,{label:"CODE",key:"3",prop:"code"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(N,{modelValue:f.createForm.code,"onUpdate:modelValue":t[7]||(t[7]=e=>f.createForm.code=e),rows:5,type:"textarea",placeholder:"Please input"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(D,{label:"默认配置",key:"4",class:"is-required"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(N,{modelValue:f.create_conf,"onUpdate:modelValue":t[8]||(t[8]=e=>f.create_conf=e),rows:5,type:"textarea",placeholder:"Please input"},null,8,["modelValue"])]),_:1})]),_:1},8,["model","rules"])]),_:1},8,["modelValue","title","onClosed"])]),_:1})])}var f=a("362c"),V={mixins:[f["c"]],data(){return{loading:!1,loadingPage:!1,isShowOrder:!0,orderLoading:!1,tableData:[],createForm:{detail:""},conf:{},create_conf:"",title:"新建组件",type:"new",dialogCreateFormVisible:!1,dataSearch:""}},computed:{rules(){return{name:[{required:!0,message:"请输入组件名称",trigger:"blur"}],code:[{required:!0,message:"请输入code",trigger:"blur"}]}}},mounted(){this.getData()},methods:{getData(){var e=this,t="/waf/waf_get_base_component_list",a={};Object(f["a"])("post",t,a,(function(t){e.loadingPage=!1,e.tableData=t.data.message,e.tableData.forEach(e=>{e.isVisiblePopover=!1})}),(function(){e.loadingPage=!1}),"no-message")},handleDelete(e){var t=this;t.loading=!0;var a="/waf/waf_del_base_component",o={name:e.name};Object(f["a"])("post",a,o,(function(a){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))},onClickChangeOrder(){var e=this;e.isShowOrder=!e.isShowOrder},onClickChangeOrderSubmit(e,t,a){var o=this,c={name:t.name};e>0&&("top"==a&&(c.type="top"),"up"==a&&(c.type="exchange",c.exchange_name=o.tableData[e-1].name)),e<o.tableData.length-1&&"down"==a&&(c.type="exchange",c.exchange_name=o.tableData[e+1].name);var l="/waf/waf_exchange_base_component_priority";"top"!=c.type&&"exchange"!=c.type||(o.orderLoading=!0,Object(f["a"])("post",l,c,(function(e){o.orderLoading=!1,o.getData()}),(function(){o.orderLoading=!1}),"no-message"))},onChangeRuleStatus(e){var t=this,a={name:e.name,status:e.status},o="/waf/waf_edit_base_component_status";Object(f["a"])("post",o,a,(function(e){t.getData()}),(function(){}),"no-message")},handleEdit(e){this.dialogCreateFormVisible=!0,this.type="edit",this.title="编辑组件";var t=this;t.loadingPage=!0;var a="/waf/waf_get_base_component",o={name:e.name};Object(f["a"])("post",a,o,(function(e){t.loadingPage=!1,t.createForm=e.data.message}),(function(){t.loadingPage=!1}),"no-message");var c=JSON.parse(e.conf);this.create_conf=JSON.stringify(c,null,4)},onClickCreate(){this.dialogCreateFormVisible=!0,this.type="new",this.title="新建组件",this.create_conf=""},dialogCloseCreate(){this.createForm={detail:""},this.create_conf="",this.$refs["createForm"].resetFields()},onClickCreateSubmit(e){var t=this,a="",o={},c="/waf/waf_edit_base_component";"new"==t.type&&(c="/waf/waf_create_base_component");try{a=JSON.stringify(JSON.parse(t.create_conf)),o=JSON.parse(t.create_conf),t.create_conf=JSON.stringify(o,null,4)}catch(l){return t.$message({showClose:!0,message:"请输入正确JSON格式",type:"error"}),!1}t.createForm.conf=a,this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(f["a"])("post",c,t.createForm,(function(e){t.loading=!1,t.dialogCreateFormVisible=!1,t.getData()}),(function(){t.loading=!1})))})},onChangeSearch(){var e=this;e.loadingPage=!0,setTimeout((function(){e.loadingPage=!1}),300)}}},w=(a("57b8"),a("d959")),x=a.n(w);const _=x()(V,[["render",C]]);t["default"]=_}}]);
//# sourceMappingURL=chunk-3106b14a.5694daa8.js.map