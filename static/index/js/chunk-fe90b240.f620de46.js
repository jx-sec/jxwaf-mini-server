(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-fe90b240"],{"1dde":function(e,t,o){var n=o("d039"),i=o("b622"),c=o("2d00"),r=i("species");e.exports=function(e){return c>=51||!n((function(){var t=[],o=t.constructor={};return o[r]=function(){return{foo:1}},1!==t[e](Boolean).foo}))}},2532:function(e,t,o){"use strict";var n=o("23e7"),i=o("5a34"),c=o("1d80"),r=o("577e"),a=o("ab13");n({target:"String",proto:!0,forced:!a("includes")},{includes:function(e){return!!~r(c(this)).indexOf(r(i(e)),arguments.length>1?arguments[1]:void 0)}})},2922:function(e,t,o){"use strict";o.r(t);o("4de4"),o("caad"),o("2532");var n=o("7a23"),i=Object(n["createVNode"])("h3",null,"防护组件管理",-1),c=Object(n["createVNode"])("div",{class:"margin-4x"},null,-1),r={class:"ssl-search-input"},a={class:"demo-block"},l=Object(n["createTextVNode"])("编辑"),u=Object(n["createVNode"])("p",null,"确定删除吗？",-1),d={style:{"text-align":"right",margin:"0"}},s=Object(n["createTextVNode"])("取消"),f=Object(n["createTextVNode"])("确定 "),b=Object(n["createTextVNode"])("删除"),p=Object(n["createTextVNode"])("取消"),O=Object(n["createTextVNode"])("确定 ");function g(e,t){var o=Object(n["resolveComponent"])("el-col"),g=Object(n["resolveComponent"])("el-row"),j=Object(n["resolveComponent"])("el-input"),m=Object(n["resolveComponent"])("el-table-column"),h=Object(n["resolveComponent"])("el-button"),C=Object(n["resolveComponent"])("el-popover"),V=Object(n["resolveComponent"])("el-table"),w=Object(n["resolveComponent"])("el-form-item"),v=Object(n["resolveComponent"])("el-form"),x=Object(n["resolveComponent"])("el-dialog"),N=Object(n["resolveDirective"])("loading");return Object(n["withDirectives"])((Object(n["openBlock"])(),Object(n["createBlock"])(g,null,{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:24},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(g,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[i]})),_:1}),Object(n["createVNode"])(o,{span:12,class:"text-align-right"})]})),_:1}),c,Object(n["createVNode"])(g,null,{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:24},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(g,{class:"text-align-right"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])("div",r,[Object(n["createVNode"])(j,{placeholder:"请输入名称进行搜索","prefix-icon":"el-icon-search",modelValue:e.dataSearch,"onUpdate:modelValue":t[1]||(t[1]=function(t){return e.dataSearch=t})},null,8,["modelValue"])])]})),_:1}),Object(n["createVNode"])("div",a,[Object(n["createVNode"])(V,{data:e.tableData.filter((function(t){return!e.dataSearch||t.ssl.toLowerCase().includes(e.dataSearch.toLowerCase())})),style:{width:"100%"}},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(m,{prop:"name",label:"组件名称"}),Object(n["createVNode"])(m,{prop:"detail",label:"组件详情"}),Object(n["createVNode"])(m,{label:"关联网站"},{default:Object(n["withCtx"])((function(e){return[Object(n["createVNode"])("p",null," 网站："+Object(n["toDisplayString"])(e.row.waf_domain_count),1),Object(n["createVNode"])("p",null," 网站分组："+Object(n["toDisplayString"])(e.row.waf_group_domain_count),1)]})),_:1}),Object(n["createVNode"])(m,{prop:"demo_conf",label:"默认配置"}),Object(n["createVNode"])(m,{label:"操作",align:"right"},{default:Object(n["withCtx"])((function(t){return[Object(n["createVNode"])(h,{size:"mini",onClick:function(o){return e.handleEdit(t.row)},class:"button-block",type:"text"},{default:Object(n["withCtx"])((function(){return[l]})),_:2},1032,["onClick"]),Object(n["createVNode"])(C,{placement:"top",width:"160",visible:t.row.isVisiblePopover,"onUpdate:visible":function(e){return t.row.isVisiblePopover=e}},{reference:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(h,{type:"text",size:"mini",onClick:function(e){return t.row.isVisiblePopover=!0}},{default:Object(n["withCtx"])((function(){return[b]})),_:2},1032,["onClick"])]})),default:Object(n["withCtx"])((function(){return[u,Object(n["createVNode"])("div",d,[Object(n["createVNode"])(h,{size:"mini",type:"text",onClick:function(e){return t.row.isVisiblePopover=!1}},{default:Object(n["withCtx"])((function(){return[s]})),_:2},1032,["onClick"]),Object(n["createVNode"])(h,{type:"primary",size:"mini",onClick:function(o){return e.handleDelete(t.row)},loading:e.loading},{default:Object(n["withCtx"])((function(){return[f]})),_:2},1032,["onClick","loading"])])]})),_:2},1032,["visible","onUpdate:visible"])]})),_:1})]})),_:1},8,["data"])])]})),_:1})]})),_:1})]})),_:1}),Object(n["createVNode"])(x,{modelValue:e.dialogConfigFormVisible,"onUpdate:modelValue":t[5]||(t[5]=function(t){return e.dialogConfigFormVisible=t}),title:"配置","close-on-click-modal":!1,width:"520px",onClosed:e.dialogCloseConfig},{footer:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(h,{onClick:t[3]||(t[3]=function(t){return e.dialogConfigFormVisible=!1})},{default:Object(n["withCtx"])((function(){return[p]})),_:1}),Object(n["createVNode"])(h,{type:"primary",onClick:t[4]||(t[4]=function(t){return e.onClickConfigSubmit("configForm")}),loading:e.loading},{default:Object(n["withCtx"])((function(){return[O]})),_:1},8,["loading"])]})),default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(v,{class:"form-download-rule-dialog",model:e.configForm,"label-position":"left","label-width":"130px",rules:e.rules,ref:"configForm"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(w,{label:"配置",key:"1"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(j,{modelValue:e.conf,"onUpdate:modelValue":t[2]||(t[2]=function(t){return e.conf=t}),rows:10,type:"textarea",placeholder:"Please input"},null,8,["modelValue"])]})),_:1})]})),_:1},8,["model","rules"])]})),_:1},8,["modelValue","onClosed"])]})),_:1},512)),[[N,e.loadingPage,void 0,{fullscreen:!0,lock:!0}]])}o("159b"),o("b0c0");var j=o("362c"),m={mixins:[j["b"]],data:function(){return{dataSearch:"",loadingPage:!1,loading:!1,tableData:[],configForm:{},conf:{},dialogConfigFormVisible:!1}},computed:{rules:function(){return{}}},mounted:function(){this.getData()},methods:{getData:function(){var e=this;Object(j["a"])("get","/waf/waf_get_sys_component_protection_list",{},(function(t){e.loadingPage=!1,e.tableData=t.data.message,e.tableData.forEach((function(e){e.isVisiblePopover=!1}))}),(function(){e.loadingPage=!1}))},handleEdit:function(e){this.dialogConfigFormVisible=!0,this.configForm=e;var t=JSON.parse(e.demo_conf);this.conf=JSON.stringify(t,null,4)},dialogCloseConfig:function(){this.$refs["configForm"].resetFields()},onClickConfigSubmit:function(e){var t=this,o="",n={};try{o=JSON.stringify(JSON.parse(t.conf)),n=JSON.parse(t.conf),t.conf=JSON.stringify(n,null,4)}catch(i){return t.$message({showClose:!0,message:"请输入正确JSON格式",type:"error"}),!1}t.configForm.demo_conf=o,this.$refs[e].validate((function(e){e&&(t.loading=!0,Object(j["a"])("post","/waf/waf_edit_sys_component_protection",t.configForm,(function(e){t.loading=!1,t.dialogConfigFormVisible=!1,t.getData()}),(function(){t.loading=!1})))}))},handleDelete:function(e){var t=this;t.loading=!0,Object(j["a"])("post","/waf/waf_delete_sys_component_protection",{name:e.name,uuid:e.uuid},(function(o){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))}}};o("d4a6");m.render=g;t["default"]=m},"4de4":function(e,t,o){"use strict";var n=o("23e7"),i=o("b727").filter,c=o("1dde"),r=c("filter");n({target:"Array",proto:!0,forced:!r},{filter:function(e){return i(this,e,arguments.length>1?arguments[1]:void 0)}})},"5a34":function(e,t,o){var n=o("44e7");e.exports=function(e){if(n(e))throw TypeError("The method doesn't accept regular expressions");return e}},ab13:function(e,t,o){var n=o("b622"),i=n("match");e.exports=function(e){var t=/./;try{"/./"[e](t)}catch(o){try{return t[i]=!1,"/./"[e](t)}catch(n){}}return!1}},caad:function(e,t,o){"use strict";var n=o("23e7"),i=o("4d64").includes,c=o("44d2");n({target:"Array",proto:!0},{includes:function(e){return i(this,e,arguments.length>1?arguments[1]:void 0)}}),c("includes")},d4a6:function(e,t,o){"use strict";o("e4b8")},e4b8:function(e,t,o){}}]);
//# sourceMappingURL=chunk-fe90b240.f620de46.js.map