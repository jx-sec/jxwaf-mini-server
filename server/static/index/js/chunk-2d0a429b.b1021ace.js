(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d0a429b"],{"04ef":function(e,t,a){"use strict";a.r(t);var o=a("7a23");const l=Object(o["createTextVNode"])("防护管理"),c=Object(o["createTextVNode"])("分析组件"),i={class:"data-search-input"},n=Object(o["createTextVNode"])("优先级调整"),r=Object(o["createTextVNode"])("新建组件"),d={class:"demo-block"},s=Object(o["createTextVNode"])("编辑"),b=Object(o["createVNode"])("p",null,"确定删除吗？",-1),u={style:{"text-align":"right",margin:"0"}},m=Object(o["createTextVNode"])("取消"),O=Object(o["createTextVNode"])("确定 "),p=Object(o["createTextVNode"])("删除"),g=Object(o["createTextVNode"])("取消"),h=Object(o["createTextVNode"])("确定 ");function j(e,t,a,j,C,f){const V=Object(o["resolveComponent"])("el-breadcrumb-item"),w=Object(o["resolveComponent"])("el-breadcrumb"),x=Object(o["resolveComponent"])("el-row"),_=Object(o["resolveComponent"])("el-input"),N=Object(o["resolveComponent"])("el-button"),k=Object(o["resolveComponent"])("el-table-column"),v=Object(o["resolveComponent"])("el-switch"),y=Object(o["resolveComponent"])("el-popover"),S=Object(o["resolveComponent"])("el-table"),F=Object(o["resolveComponent"])("el-col"),P=Object(o["resolveComponent"])("el-form-item"),D=Object(o["resolveComponent"])("el-form"),T=Object(o["resolveComponent"])("el-dialog"),U=Object(o["resolveDirective"])("loading");return Object(o["openBlock"])(),Object(o["createBlock"])("div",null,[Object(o["createVNode"])(x,{class:"breadcrumb-style"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(w,{separator:"/"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(V,{to:{path:"/"}},{default:Object(o["withCtx"])(()=>[l]),_:1}),Object(o["createVNode"])(V,null,{default:Object(o["withCtx"])(()=>[c]),_:1})]),_:1})]),_:1}),Object(o["createVNode"])(x,{class:"container-style"},{default:Object(o["withCtx"])(()=>[Object(o["withDirectives"])(Object(o["createVNode"])(F,{span:24},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(x,{class:"text-align-right"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",i,[Object(o["createVNode"])(_,{placeholder:"请输入名称进行搜索","prefix-icon":"el-icon-search",modelValue:C.dataSearch,"onUpdate:modelValue":t[1]||(t[1]=e=>C.dataSearch=e)},null,8,["modelValue"]),Object(o["createVNode"])(N,{icon:"el-icon-search",onClick:f.onChangeSearch,class:"search-icon-btn"},null,8,["onClick"])]),Object(o["createVNode"])(N,{type:"success",onClick:t[2]||(t[2]=e=>f.onClickChangeOrder())},{default:Object(o["withCtx"])(()=>[n]),_:1}),Object(o["createVNode"])(N,{type:"primary",onClick:t[3]||(t[3]=e=>f.onClickCreate())},{default:Object(o["withCtx"])(()=>[r]),_:1})]),_:1}),Object(o["createVNode"])("div",d,[Object(o["createVNode"])(S,{data:C.tableData.filter(e=>!C.dataSearch||e.name.toLowerCase().includes(C.dataSearch.toLowerCase())),style:{width:"100%"}},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(k,{prop:"name",label:"组件名称"}),Object(o["createVNode"])(k,{prop:"detail",label:"组件描述"}),Object(o["createVNode"])(k,{prop:"conf",label:"配置"}),Object(o["createVNode"])(k,{prop:"status",label:"状态"},{default:Object(o["withCtx"])(e=>[Object(o["createVNode"])(v,{modelValue:e.row.status,"onUpdate:modelValue":t=>e.row.status=t,onChange:t=>f.onChangeRuleStatus(e.row),"active-value":"true","inactive-value":"false"},null,8,["modelValue","onUpdate:modelValue","onChange"])]),_:1}),Object(o["createVNode"])(k,{label:"操作",align:"right"},{default:Object(o["withCtx"])(e=>[Object(o["createVNode"])(N,{size:"mini",onClick:t=>f.handleEdit(e.row),class:"button-block",type:"text"},{default:Object(o["withCtx"])(()=>[s]),_:2},1032,["onClick"]),Object(o["createVNode"])(y,{placement:"top",width:"160",visible:e.row.isVisiblePopover,"onUpdate:visible":t=>e.row.isVisiblePopover=t},{reference:Object(o["withCtx"])(()=>[Object(o["createVNode"])(N,{type:"text",size:"mini",onClick:t=>e.row.isVisiblePopover=!0},{default:Object(o["withCtx"])(()=>[p]),_:2},1032,["onClick"])]),default:Object(o["withCtx"])(()=>[b,Object(o["createVNode"])("div",u,[Object(o["createVNode"])(N,{size:"mini",type:"text",onClick:t=>e.row.isVisiblePopover=!1},{default:Object(o["withCtx"])(()=>[m]),_:2},1032,["onClick"]),Object(o["createVNode"])(N,{type:"primary",size:"mini",onClick:t=>f.handleDelete(e.row),loading:C.loading},{default:Object(o["withCtx"])(()=>[O]),_:2},1032,["onClick","loading"])])]),_:2},1032,["visible","onUpdate:visible"])]),_:1}),C.isShowOrder?Object(o["createCommentVNode"])("",!0):(Object(o["openBlock"])(),Object(o["createBlock"])(k,{key:0,label:"优先级",align:"right"},{default:Object(o["withCtx"])(e=>[Object(o["createVNode"])(N,{type:"success",class:"icon iconfont iconxiangshang",circle:"",onClick:t=>f.onClickChangeOrderSubmit(e.$index,e.row,"up"),title:"上移",loading:C.orderLoading},null,8,["onClick","loading"]),Object(o["createVNode"])(N,{type:"success",class:"icon iconfont iconxiangxia",circle:"",onClick:t=>f.onClickChangeOrderSubmit(e.$index,e.row,"down"),title:"下移",loading:C.orderLoading},null,8,["onClick","loading"]),Object(o["createVNode"])(N,{type:"success",class:"icon iconfont iconzhiding",circle:"",onClick:t=>f.onClickChangeOrderSubmit(e.$index,e.row,"top"),title:"置顶",loading:C.orderLoading},null,8,["onClick","loading"])]),_:1}))]),_:1},8,["data"])])]),_:1},512),[[U,C.loadingPage,void 0,{fullscreen:!0,lock:!0}]])]),_:1}),Object(o["createVNode"])(T,{modelValue:C.dialogCreateFormVisible,"onUpdate:modelValue":t[11]||(t[11]=e=>C.dialogCreateFormVisible=e),title:C.title,"close-on-click-modal":!1,width:"520px",onClosed:f.dialogCloseCreate},{footer:Object(o["withCtx"])(()=>[Object(o["createVNode"])(N,{onClick:t[9]||(t[9]=e=>C.dialogCreateFormVisible=!1)},{default:Object(o["withCtx"])(()=>[g]),_:1}),Object(o["createVNode"])(N,{type:"primary",onClick:t[10]||(t[10]=e=>f.onClickCreateSubmit("createForm")),loading:C.loading},{default:Object(o["withCtx"])(()=>[h]),_:1},8,["loading"])]),default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(D,{class:"form-download-rule-dialog",model:C.createForm,"label-position":"left","label-width":"130px",rules:f.rules,ref:"createForm"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(P,{label:"组件名称",key:"1",prop:"name"},{default:Object(o["withCtx"])(()=>["new"==C.type?(Object(o["openBlock"])(),Object(o["createBlock"])(_,{key:0,modelValue:C.createForm.name,"onUpdate:modelValue":t[4]||(t[4]=e=>C.createForm.name=e),placeholder:"Please input"},null,8,["modelValue"])):(Object(o["openBlock"])(),Object(o["createBlock"])(_,{key:1,modelValue:C.createForm.name,"onUpdate:modelValue":t[5]||(t[5]=e=>C.createForm.name=e),placeholder:"Please input",disabled:""},null,8,["modelValue"]))]),_:1}),Object(o["createVNode"])(P,{label:"组件描述",key:"2"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(_,{modelValue:C.createForm.detail,"onUpdate:modelValue":t[6]||(t[6]=e=>C.createForm.detail=e),placeholder:"Please input"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(P,{label:"CODE",key:"4",prop:"code"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(_,{modelValue:C.createForm.code,"onUpdate:modelValue":t[7]||(t[7]=e=>C.createForm.code=e),rows:5,type:"textarea",placeholder:"Please input"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(P,{label:"默认配置",key:"3",class:"is-required"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(_,{modelValue:C.create_conf,"onUpdate:modelValue":t[8]||(t[8]=e=>C.create_conf=e),rows:5,type:"textarea",placeholder:"Please input"},null,8,["modelValue"])]),_:1})]),_:1},8,["model","rules"])]),_:1},8,["modelValue","title","onClosed"])])}var C=a("362c"),f={mixins:[C["d"]],data(){return{dataSearch:"",loadingPage:!1,loading:!1,tableData:[],createForm:{detail:""},conf:{},create_conf:"",title:"新建组件",type:"new",dialogCreateFormVisible:!1,isShowOrder:!0,orderLoading:!1}},computed:{rules(){return{name:[{required:!0,message:"请输入组件名称",trigger:"blur"}],code:[{required:!0,message:"请输入code",trigger:"blur"}]}}},mounted(){this.getData()},methods:{getData(){var e=this;Object(C["a"])("get","/waf/waf_get_analysis_component_list",{},(function(t){e.loadingPage=!1,e.tableData=t.data.message,e.tableData.forEach(e=>{e.isVisiblePopover=!1})}),(function(){e.loadingPage=!1}))},handleDelete(e){var t=this;t.loading=!0,Object(C["a"])("post","/waf/waf_del_analysis_component",{name:e.name},(function(a){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))},handleEdit(e){this.dialogCreateFormVisible=!0,this.type="edit",this.title="编辑组件";var t=this;t.loadingPage=!0;var a="/waf/waf_get_analysis_component",o={name:e.name};Object(C["a"])("post",a,o,(function(e){t.loadingPage=!1,t.createForm=e.data.message}),(function(){t.loadingPage=!1}),"no-message");var l=JSON.parse(e.conf);this.create_conf=JSON.stringify(l,null,4)},onClickCreate(){this.dialogCreateFormVisible=!0,this.type="new",this.title="新建组件",this.create_conf=""},dialogCloseCreate(){this.createForm={detail:""},this.create_conf="",this.$refs["createForm"].resetFields()},onClickCreateSubmit(e){var t=this,a="",o={},l="/waf/waf_edit_analysis_component";"new"==t.type&&(l="/waf/waf_create_analysis_component");try{a=JSON.stringify(JSON.parse(t.create_conf)),o=JSON.parse(t.create_conf),t.create_conf=JSON.stringify(o,null,4)}catch(c){return t.$message({showClose:!0,message:"请输入正确JSON格式",type:"error"}),!1}t.createForm.conf=a,this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(C["a"])("post",l,t.createForm,(function(e){t.loading=!1,t.dialogCreateFormVisible=!1,t.getData()}),(function(){t.loading=!1})))})},onClickChangeOrder(){var e=this;e.isShowOrder=!e.isShowOrder},onClickChangeOrderSubmit(e,t,a){var o=this,l={name:t.name};e>0&&("top"==a&&(l.type="top"),"up"==a&&(l.type="exchange",l.exchange_name=o.tableData[e-1].name)),e<o.tableData.length-1&&"down"==a&&(l.type="exchange",l.exchange_name=o.tableData[e+1].name);var c="/waf/waf_exchange_analysis_component_priority";"top"!=l.type&&"exchange"!=l.type||(o.orderLoading=!0,Object(C["a"])("post",c,l,(function(e){o.orderLoading=!1,o.getData()}),(function(){o.orderLoading=!1}),"no-message"))},onChangeRuleStatus(e){var t=this,a={name:e.name,status:e.status},o="/waf/waf_edit_analysis_component_status";Object(C["a"])("post",o,a,(function(e){t.getData()}),(function(){}),"no-message")},onChangeSearch(){var e=this;e.loadingPage=!0,setTimeout((function(){e.loadingPage=!1}),300)}}},V=a("d959"),w=a.n(V);const x=w()(f,[["render",j]]);t["default"]=x}}]);
//# sourceMappingURL=chunk-2d0a429b.b1021ace.js.map