(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-e0d66ec0"],{2922:function(e,t,o){"use strict";o.r(t);var a=o("7a23");const l=Object(a["createVNode"])("h3",null,"防护组件管理",-1),i=Object(a["createVNode"])("div",{class:"margin-4x"},null,-1),c={class:"ssl-search-input"},n={class:"demo-block"},r=Object(a["createTextVNode"])("编辑"),d=Object(a["createVNode"])("p",null,"确定删除吗？",-1),s={style:{"text-align":"right",margin:"0"}},b=Object(a["createTextVNode"])("取消"),f=Object(a["createTextVNode"])("确定 "),O=Object(a["createTextVNode"])("删除"),u=Object(a["createTextVNode"])("取消"),j=Object(a["createTextVNode"])("确定 ");function p(e,t,o,p,g,m){const C=Object(a["resolveComponent"])("el-col"),h=Object(a["resolveComponent"])("el-row"),V=Object(a["resolveComponent"])("el-input"),w=Object(a["resolveComponent"])("el-table-column"),N=Object(a["resolveComponent"])("el-button"),x=Object(a["resolveComponent"])("el-popover"),_=Object(a["resolveComponent"])("el-table"),v=Object(a["resolveComponent"])("el-form-item"),y=Object(a["resolveComponent"])("el-form"),k=Object(a["resolveComponent"])("el-dialog"),S=Object(a["resolveDirective"])("loading");return Object(a["withDirectives"])((Object(a["openBlock"])(),Object(a["createBlock"])(h,null,{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{span:24},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(h,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{span:12},{default:Object(a["withCtx"])(()=>[l]),_:1}),Object(a["createVNode"])(C,{span:12,class:"text-align-right"})]),_:1}),i,Object(a["createVNode"])(h,null,{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{span:24},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(h,{class:"text-align-right"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])("div",c,[Object(a["createVNode"])(V,{placeholder:"请输入名称进行搜索","prefix-icon":"el-icon-search",modelValue:g.dataSearch,"onUpdate:modelValue":t[1]||(t[1]=e=>g.dataSearch=e)},null,8,["modelValue"])])]),_:1}),Object(a["createVNode"])("div",n,[Object(a["createVNode"])(_,{data:g.tableData.filter(e=>!g.dataSearch||e.ssl.toLowerCase().includes(g.dataSearch.toLowerCase())),style:{width:"100%"}},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(w,{prop:"name",label:"组件名称"}),Object(a["createVNode"])(w,{prop:"detail",label:"组件详情"}),Object(a["createVNode"])(w,{label:"关联网站"},{default:Object(a["withCtx"])(e=>[Object(a["createVNode"])("p",null," 网站："+Object(a["toDisplayString"])(e.row.waf_domain_count),1),Object(a["createVNode"])("p",null," 网站分组："+Object(a["toDisplayString"])(e.row.waf_group_domain_count),1)]),_:1}),Object(a["createVNode"])(w,{prop:"demo_conf",label:"默认配置"}),Object(a["createVNode"])(w,{label:"操作",align:"right"},{default:Object(a["withCtx"])(e=>[Object(a["createVNode"])(N,{size:"mini",onClick:t=>m.handleEdit(e.row),class:"button-block",type:"text"},{default:Object(a["withCtx"])(()=>[r]),_:2},1032,["onClick"]),Object(a["createVNode"])(x,{placement:"top",width:"160",visible:e.row.isVisiblePopover,"onUpdate:visible":t=>e.row.isVisiblePopover=t},{reference:Object(a["withCtx"])(()=>[Object(a["createVNode"])(N,{type:"text",size:"mini",onClick:t=>e.row.isVisiblePopover=!0},{default:Object(a["withCtx"])(()=>[O]),_:2},1032,["onClick"])]),default:Object(a["withCtx"])(()=>[d,Object(a["createVNode"])("div",s,[Object(a["createVNode"])(N,{size:"mini",type:"text",onClick:t=>e.row.isVisiblePopover=!1},{default:Object(a["withCtx"])(()=>[b]),_:2},1032,["onClick"]),Object(a["createVNode"])(N,{type:"primary",size:"mini",onClick:t=>m.handleDelete(e.row),loading:g.loading},{default:Object(a["withCtx"])(()=>[f]),_:2},1032,["onClick","loading"])])]),_:2},1032,["visible","onUpdate:visible"])]),_:1})]),_:1},8,["data"])])]),_:1})]),_:1})]),_:1}),Object(a["createVNode"])(k,{modelValue:g.dialogConfigFormVisible,"onUpdate:modelValue":t[5]||(t[5]=e=>g.dialogConfigFormVisible=e),title:"配置","close-on-click-modal":!1,width:"520px",onClosed:m.dialogCloseConfig},{footer:Object(a["withCtx"])(()=>[Object(a["createVNode"])(N,{onClick:t[3]||(t[3]=e=>g.dialogConfigFormVisible=!1)},{default:Object(a["withCtx"])(()=>[u]),_:1}),Object(a["createVNode"])(N,{type:"primary",onClick:t[4]||(t[4]=e=>m.onClickConfigSubmit("configForm")),loading:g.loading},{default:Object(a["withCtx"])(()=>[j]),_:1},8,["loading"])]),default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(y,{class:"form-download-rule-dialog",model:g.configForm,"label-position":"left","label-width":"130px",rules:m.rules,ref:"configForm"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(v,{label:"配置",key:"1"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(V,{modelValue:g.conf,"onUpdate:modelValue":t[2]||(t[2]=e=>g.conf=e),rows:10,type:"textarea",placeholder:"Please input"},null,8,["modelValue"])]),_:1})]),_:1},8,["model","rules"])]),_:1},8,["modelValue","onClosed"])]),_:1},512)),[[S,g.loadingPage,void 0,{fullscreen:!0,lock:!0}]])}var g=o("362c"),m={mixins:[g["b"]],data(){return{dataSearch:"",loadingPage:!1,loading:!1,tableData:[],configForm:{},conf:{},dialogConfigFormVisible:!1}},computed:{rules(){return{}}},mounted(){this.getData()},methods:{getData(){var e=this;Object(g["a"])("get","/waf/waf_get_sys_component_protection_list",{},(function(t){e.loadingPage=!1,e.tableData=t.data.message,e.tableData.forEach(e=>{e.isVisiblePopover=!1})}),(function(){e.loadingPage=!1}))},handleEdit(e){this.dialogConfigFormVisible=!0,this.configForm=e;var t=JSON.parse(e.demo_conf);this.conf=JSON.stringify(t,null,4)},dialogCloseConfig(){this.$refs["configForm"].resetFields()},onClickConfigSubmit(e){var t=this,o="",a={};try{o=JSON.stringify(JSON.parse(t.conf)),a=JSON.parse(t.conf),t.conf=JSON.stringify(a,null,4)}catch(l){return t.$message({showClose:!0,message:"请输入正确JSON格式",type:"error"}),!1}t.configForm.demo_conf=o,this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(g["a"])("post","/waf/waf_edit_sys_component_protection",t.configForm,(function(e){t.loading=!1,t.dialogConfigFormVisible=!1,t.getData()}),(function(){t.loading=!1})))})},handleDelete(e){var t=this;t.loading=!0,Object(g["a"])("post","/waf/waf_delete_sys_component_protection",{name:e.name,uuid:e.uuid},(function(o){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))}}},C=(o("71eb"),o("d959")),h=o.n(C);const V=h()(m,[["render",p]]);t["default"]=V},"71eb":function(e,t,o){"use strict";o("c2f0")},c2f0:function(e,t,o){}}]);
//# sourceMappingURL=chunk-e0d66ec0.4cf696a4.js.map