(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-4cc0c7dd"],{"264d":function(e,t,o){},a25a:function(e,t,o){"use strict";o.r(t);var c=o("7a23");const l={class:"group-search-input"},r=Object(c["createTextVNode"])("新建网站分组"),a={class:"demo-block"},i=Object(c["createTextVNode"])(" Web防护引擎： "),n={key:0},d=Object(c["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),b=Object(c["createTextVNode"])("已开启 "),s={key:1},p=Object(c["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),u=Object(c["createTextVNode"])("未开启 "),j=Object(c["createTextVNode"])(" Web规则防护： "),O={key:0},g=Object(c["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),m=Object(c["createTextVNode"])("已开启 "),V={key:1},N=Object(c["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),w=Object(c["createTextVNode"])("未开启 "),_=Object(c["createTextVNode"])(" 流量防护引擎： "),k={key:0},h=Object(c["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),C=Object(c["createTextVNode"])("已开启 "),f={key:1},x=Object(c["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),v=Object(c["createTextVNode"])("未开启 "),T=Object(c["createTextVNode"])(" 流量规则防护： "),y={key:0},B=Object(c["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),F=Object(c["createTextVNode"])("已开启 "),D={key:1},P=Object(c["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),G=Object(c["createTextVNode"])("未开启 "),z=Object(c["createTextVNode"])(" 名单防护： "),S={key:0},U=Object(c["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),E=Object(c["createTextVNode"])("已开启 "),J={key:1},L=Object(c["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),W=Object(c["createTextVNode"])("未开启 "),$=Object(c["createTextVNode"])(" 组件防护： "),q={key:0},A=Object(c["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),H=Object(c["createTextVNode"])("已开启 "),I={key:1},K=Object(c["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),M=Object(c["createTextVNode"])("未开启 "),Q=Object(c["createTextVNode"])("网站管理"),R=Object(c["createTextVNode"])("防护配置 "),X=Object(c["createTextVNode"])("编辑分组 "),Y=Object(c["createVNode"])("p",null,"确定删除吗？",-1),Z={style:{"text-align":"right",margin:"0"}},ee=Object(c["createTextVNode"])("取消"),te=Object(c["createTextVNode"])("确定 "),oe=Object(c["createTextVNode"])("删除"),ce=Object(c["createVNode"])("p",{class:"form-info-color"}," （请输入以字母开头，仅支持下划线“_”及中横线“-”两种特殊字符） ",-1),le=Object(c["createTextVNode"])("取消"),re=Object(c["createTextVNode"])("确定");function ae(e,t,o,ae,ie,ne){const de=Object(c["resolveComponent"])("el-input"),be=Object(c["resolveComponent"])("el-button"),se=Object(c["resolveComponent"])("el-row"),pe=Object(c["resolveComponent"])("el-table-column"),ue=Object(c["resolveComponent"])("el-popover"),je=Object(c["resolveComponent"])("el-table"),Oe=Object(c["resolveComponent"])("el-col"),ge=Object(c["resolveComponent"])("el-form-item"),me=Object(c["resolveComponent"])("el-form"),Ve=Object(c["resolveComponent"])("el-dialog"),Ne=Object(c["resolveDirective"])("loading");return Object(c["withDirectives"])((Object(c["openBlock"])(),Object(c["createBlock"])(se,null,{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(Oe,{span:24},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(se,{class:"text-align-right"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])("div",l,[Object(c["createVNode"])(de,{placeholder:"输入分组名称进行搜索","prefix-icon":"el-icon-search",modelValue:ie.groupSearch,"onUpdate:modelValue":t[1]||(t[1]=e=>ie.groupSearch=e)},null,8,["modelValue"])]),Object(c["createVNode"])(be,{type:"primary",onClick:t[2]||(t[2]=e=>ne.onClickCreategroup())},{default:Object(c["withCtx"])(()=>[r]),_:1})]),_:1}),Object(c["createVNode"])("div",a,[Object(c["createVNode"])(je,{data:ie.tableData.filter(e=>!ie.groupSearch||e.group.toLowerCase().includes(ie.groupSearch.toLowerCase())),style:{width:"100%"}},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(pe,{prop:"group_name",label:"分组名称"}),Object(c["createVNode"])(pe,{prop:"group_detail",label:"描述"}),Object(c["createVNode"])(pe,{prop:"protection",label:"防护配置"},{default:Object(c["withCtx"])(e=>[Object(c["createVNode"])("p",null,[i,"true"==e.row.web_engine_protection?(Object(c["openBlock"])(),Object(c["createBlock"])("span",n,[d,b])):Object(c["createCommentVNode"])("",!0),"false"==e.row.web_engine_protection?(Object(c["openBlock"])(),Object(c["createBlock"])("span",s,[p,u])):Object(c["createCommentVNode"])("",!0)]),Object(c["createVNode"])("p",null,[j,"true"==e.row.web_rule_protection?(Object(c["openBlock"])(),Object(c["createBlock"])("span",O,[g,m])):Object(c["createCommentVNode"])("",!0),"false"==e.row.web_rule_protection?(Object(c["openBlock"])(),Object(c["createBlock"])("span",V,[N,w])):Object(c["createCommentVNode"])("",!0)]),Object(c["createVNode"])("p",null,[_,"true"==e.row.flow_engine_protection?(Object(c["openBlock"])(),Object(c["createBlock"])("span",k,[h,C])):Object(c["createCommentVNode"])("",!0),"false"==e.row.flow_engine_protection?(Object(c["openBlock"])(),Object(c["createBlock"])("span",f,[x,v])):Object(c["createCommentVNode"])("",!0)]),Object(c["createVNode"])("p",null,[T,"true"==e.row.flow_rule_protection?(Object(c["openBlock"])(),Object(c["createBlock"])("span",y,[B,F])):Object(c["createCommentVNode"])("",!0),"false"==e.row.flow_rule_protection?(Object(c["openBlock"])(),Object(c["createBlock"])("span",D,[P,G])):Object(c["createCommentVNode"])("",!0)]),Object(c["createVNode"])("p",null,[z,"true"==e.row.name_list?(Object(c["openBlock"])(),Object(c["createBlock"])("span",S,[U,E])):Object(c["createCommentVNode"])("",!0),"false"==e.row.name_list?(Object(c["openBlock"])(),Object(c["createBlock"])("span",J,[L,W])):Object(c["createCommentVNode"])("",!0)]),Object(c["createVNode"])("p",null,[$,"true"==e.row.name_list?(Object(c["openBlock"])(),Object(c["createBlock"])("span",q,[A,H])):Object(c["createCommentVNode"])("",!0),"false"==e.row.name_list?(Object(c["openBlock"])(),Object(c["createBlock"])("span",I,[K,M])):Object(c["createCommentVNode"])("",!0)])]),_:1}),Object(c["createVNode"])(pe,{prop:"domain_count",label:"网站数量"}),Object(c["createVNode"])(pe,{label:"操作",align:"right"},{default:Object(c["withCtx"])(e=>[Object(c["createVNode"])(be,{size:"mini",onClick:t=>ne.handleDomain(e.row),class:"button-block",type:"text"},{default:Object(c["withCtx"])(()=>[Q]),_:2},1032,["onClick"]),Object(c["createVNode"])(be,{size:"mini",onClick:t=>ne.handleProtection(e.row),class:"button-block",type:"text"},{default:Object(c["withCtx"])(()=>[R]),_:2},1032,["onClick"]),Object(c["createVNode"])(be,{size:"mini",onClick:t=>ne.handleEditGroup(e.row),class:"button-block",type:"text"},{default:Object(c["withCtx"])(()=>[X]),_:2},1032,["onClick"]),Object(c["createVNode"])(ue,{placement:"top",width:"160",visible:e.row.isVisiblePopover,"onUpdate:visible":t=>e.row.isVisiblePopover=t},{reference:Object(c["withCtx"])(()=>[Object(c["createVNode"])(be,{type:"text",size:"mini",onClick:t=>e.row.isVisiblePopover=!0},{default:Object(c["withCtx"])(()=>[oe]),_:2},1032,["onClick"])]),default:Object(c["withCtx"])(()=>[Y,Object(c["createVNode"])("div",Z,[Object(c["createVNode"])(be,{size:"mini",type:"text",onClick:t=>e.row.isVisiblePopover=!1},{default:Object(c["withCtx"])(()=>[ee]),_:2},1032,["onClick"]),Object(c["createVNode"])(be,{type:"primary",size:"mini",onClick:t=>ne.handleDelete(e.row),loading:ie.loading},{default:Object(c["withCtx"])(()=>[te]),_:2},1032,["onClick","loading"])])]),_:2},1032,["visible","onUpdate:visible"])]),_:1})]),_:1},8,["data"])])]),_:1}),Object(c["createVNode"])(Ve,{title:ie.groupTitle,modelValue:ie.dialogGroupFormVisible,"onUpdate:modelValue":t[7]||(t[7]=e=>ie.dialogGroupFormVisible=e),width:"520px","close-on-click-modal":!1,onClose:ne.dialogClose},{footer:Object(c["withCtx"])(()=>[Object(c["createVNode"])(be,{onClick:t[5]||(t[5]=e=>ie.dialogGroupFormVisible=!1)},{default:Object(c["withCtx"])(()=>[le]),_:1}),Object(c["createVNode"])(be,{type:"primary",onClick:t[6]||(t[6]=e=>ne.onClickgroupSubmit("groupForm")),loading:ie.loading},{default:Object(c["withCtx"])(()=>[re]),_:1},8,["loading"])]),default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(me,{model:ie.groupForm,size:"mini","label-position":"left","label-width":"120px",rules:ne.rules,ref:"groupForm",class:"form-tag-dialog"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(ge,{label:"分组名称",prop:"group_name",key:"1"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(de,{modelValue:ie.groupForm.group_name,"onUpdate:modelValue":t[3]||(t[3]=e=>ie.groupForm.group_name=e),placeholder:"请输入字母或数字，如group_1"},null,8,["modelValue"]),ce]),_:1}),Object(c["createVNode"])(ge,{label:"分组描述",key:"2"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(de,{modelValue:ie.groupForm.group_detail,"onUpdate:modelValue":t[4]||(t[4]=e=>ie.groupForm.group_detail=e),placeholder:"请输入分组描述",rows:2,type:"textarea"},null,8,["modelValue"])]),_:1})]),_:1},8,["model","rules"])]),_:1},8,["title","modelValue","onClose"])]),_:1},512)),[[Ne,ie.loadingPage,void 0,{fullscreen:!0,lock:!0}]])}var ie=o("362c"),ne={mixins:[ie["b"]],data(){return{groupTitle:"新建分组",groupType:"new",groupSearch:"",loadingPage:!1,dialogGroupFormVisible:!1,loading:!1,groupForm:{group_name:"",group_detail:""},tableData:[]}},computed:{rules(){return{group_name:[{required:!0,message:"请输入以字母开头的字符串，仅支持“_”及“-”两种特殊字符",trigger:["blur","change"]},{validator:ie["h"],trigger:["blur","change"]}]}}},mounted(){this.getData()},methods:{getData(){var e=this;Object(ie["a"])("get","/waf/waf_get_group_list",{},(function(t){e.loadingPage=!1,e.tableData=t.data.message,e.tableData.forEach(e=>{e.isVisiblePopover=!1})}),(function(){e.loadingPage=!1}))},dialogClose(){this.groupForm={group_name:"",group_detail:""},this.$refs["groupForm"].resetFields()},onClickgroupSubmit(e){var t=this,o="/waf/waf_create_group";"edit"==t.groupType&&(o="/waf/waf_edit_group"),this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(ie["a"])("post",o,t.groupForm,(function(e){t.loading=!1,t.dialogGroupFormVisible=!1,t.getData()}),(function(){t.loading=!1})))})},onClickCreategroup(){var e=this;e.groupTitle="新建分组",e.groupType="new",e.dialogGroupFormVisible=!0},handleProtection(e){window.location.href="/#/group-protection/"+e.group_id},handleDomain(e){window.location.href="/#/group-domain/"+e.group_id},handleEditGroup(e){var t=this;Object(ie["a"])("post","/waf/waf_get_group",{group_id:e.group_id},(function(o){e.loading=!1,t.groupForm=o.data.message,t.groupTitle="编辑分组",t.groupType="edit",t.dialogGroupFormVisible=!0}),(function(){e.loading=!1}),"no-message")},handleDelete(e){var t=this;t.loading=!0,Object(ie["a"])("post","/waf/waf_del_group",{group_id:e.group_id,group_name:e.group_name},(function(o){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))}}},de=(o("a8ca"),o("d959")),be=o.n(de);const se=be()(ne,[["render",ae]]);t["default"]=se},a8ca:function(e,t,o){"use strict";o("264d")}}]);
//# sourceMappingURL=chunk-4cc0c7dd.a4ccacef.js.map