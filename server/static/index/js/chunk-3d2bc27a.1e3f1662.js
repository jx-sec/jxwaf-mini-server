(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-3d2bc27a"],{"1f27":function(e,t,a){"use strict";a("e3b0")},"4e98":function(e,t,a){"use strict";a.r(t);var o=a("7a23");const c=Object(o["createVNode"])("h3",null,"响应替换配置",-1),l={class:"domain-search-input"},d=Object(o["createTextVNode"])("新增"),i={class:"demo-block"},r={key:0},n=Object(o["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),s=Object(o["createTextVNode"])("已开启 "),b={key:1},m=Object(o["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),p=Object(o["createTextVNode"])("已关闭 "),u={key:0},_=Object(o["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),j=Object(o["createTextVNode"])("已开启 "),O={key:1},h=Object(o["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),V=Object(o["createTextVNode"])("已关闭 "),y=Object(o["createTextVNode"])("编辑"),f=Object(o["createVNode"])("p",null,"确定删除吗？",-1),C={style:{"text-align":"right",margin:"0"}},N=Object(o["createTextVNode"])("取消"),g=Object(o["createTextVNode"])("确定 "),w=Object(o["createTextVNode"])("删除"),k={key:0},v=Object(o["createVNode"])("div",{class:"match-title"},[Object(o["createVNode"])("p",null,"Header头"),Object(o["createVNode"])("p",null,"正则匹配"),Object(o["createVNode"])("p",null,"替换内容")],-1),x={class:"match-key-item"},F={class:"match-key-item"},T={class:"match-key-item"},B=Object(o["createTextVNode"])("删除"),U=Object(o["createTextVNode"])("新增"),M={key:1},I=Object(o["createTextVNode"])("取消"),D=Object(o["createTextVNode"])("确定");function S(e,t,a,S,P,z){const E=Object(o["resolveComponent"])("el-col"),J=Object(o["resolveComponent"])("el-row"),L=Object(o["resolveComponent"])("el-divider"),$=Object(o["resolveComponent"])("el-input"),q=Object(o["resolveComponent"])("el-button"),H=Object(o["resolveComponent"])("el-table-column"),A=Object(o["resolveComponent"])("el-popover"),G=Object(o["resolveComponent"])("el-table"),K=Object(o["resolveComponent"])("el-form-item"),Q=Object(o["resolveComponent"])("el-switch"),R=Object(o["resolveComponent"])("el-form"),W=Object(o["resolveComponent"])("el-dialog");return Object(o["openBlock"])(),Object(o["createBlock"])(J,null,{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(E,{span:24},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(J,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(E,{span:24},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(J,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(E,{span:12},{default:Object(o["withCtx"])(()=>[c]),_:1})]),_:1})]),_:1})]),_:1}),Object(o["createVNode"])(L),Object(o["createVNode"])(J,{class:"text-align-right"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",l,[Object(o["createVNode"])($,{placeholder:"请输入名称进行搜索","prefix-icon":"el-icon-search",modelValue:P.domainSearch,"onUpdate:modelValue":t[1]||(t[1]=e=>P.domainSearch=e)},null,8,["modelValue"])]),Object(o["createVNode"])(q,{type:"primary",onClick:t[2]||(t[2]=e=>z.onClickCreateIdentity())},{default:Object(o["withCtx"])(()=>[d]),_:1})]),_:1}),Object(o["createVNode"])("div",i,[Object(o["createVNode"])(G,{data:P.tableData.filter(e=>!P.domainSearch||e.name.toLowerCase().includes(P.domainSearch.toLowerCase())),style:{width:"100%"}},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(H,{prop:"name",label:"名称"}),Object(o["createVNode"])(H,{prop:"detail",label:"详情"}),Object(o["createVNode"])(H,{prop:"status",label:"响应头替换"},{default:Object(o["withCtx"])(e=>["true"==e.row.response_header_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",r,[n,s])):Object(o["createCommentVNode"])("",!0),"false"==e.row.response_header_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",b,[m,p])):Object(o["createCommentVNode"])("",!0)]),_:1}),Object(o["createVNode"])(H,{prop:"status",label:"响应体替换"},{default:Object(o["withCtx"])(e=>["true"==e.row.response_data_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",u,[_,j])):Object(o["createCommentVNode"])("",!0),"false"==e.row.response_data_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",O,[h,V])):Object(o["createCommentVNode"])("",!0)]),_:1}),Object(o["createVNode"])(H,{label:"操作",align:"right"},{default:Object(o["withCtx"])(e=>[Object(o["createVNode"])(q,{size:"mini",onClick:t=>z.handleEdit(e.row),class:"button-block",type:"text",loading:e.row.loading},{default:Object(o["withCtx"])(()=>[y]),_:2},1032,["onClick","loading"]),Object(o["createVNode"])(A,{placement:"top",width:"160",visible:e.row.isVisiblePopover,"onUpdate:visible":t=>e.row.isVisiblePopover=t},{reference:Object(o["withCtx"])(()=>[Object(o["createVNode"])(q,{type:"text",size:"mini",onClick:t=>e.row.isVisiblePopover=!0},{default:Object(o["withCtx"])(()=>[w]),_:2},1032,["onClick"])]),default:Object(o["withCtx"])(()=>[f,Object(o["createVNode"])("div",C,[Object(o["createVNode"])(q,{size:"mini",type:"text",onClick:t=>e.row.isVisiblePopover=!1},{default:Object(o["withCtx"])(()=>[N]),_:2},1032,["onClick"]),Object(o["createVNode"])(q,{type:"primary",size:"mini",onClick:t=>z.handleDelete(e.row),loading:P.loading},{default:Object(o["withCtx"])(()=>[g]),_:2},1032,["onClick","loading"])])]),_:2},1032,["visible","onUpdate:visible"])]),_:1})]),_:1},8,["data"])])]),_:1}),Object(o["createVNode"])(W,{title:P.domainTitle,modelValue:P.dialogIdentityFormVisible,"onUpdate:modelValue":t[13]||(t[13]=e=>P.dialogIdentityFormVisible=e),width:"820px","close-on-click-modal":!1,onClosed:z.dialogClose},{footer:Object(o["withCtx"])(()=>[Object(o["createVNode"])(q,{onClick:t[11]||(t[11]=e=>P.dialogIdentityFormVisible=!1)},{default:Object(o["withCtx"])(()=>[I]),_:1}),Object(o["createVNode"])(q,{type:"primary",onClick:t[12]||(t[12]=e=>z.onClickIdentitySubmit("identityForm")),loading:P.loading},{default:Object(o["withCtx"])(()=>[D]),_:1},8,["loading"])]),default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(R,{class:"form-tag-dialog identity-edit-form ",model:P.identityForm,size:"mini","label-position":"left","label-width":"130px",rules:z.rules,ref:"identityForm"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(K,{label:"名称",prop:"name",key:"1"},{default:Object(o["withCtx"])(()=>["new"==P.domainType?(Object(o["openBlock"])(),Object(o["createBlock"])($,{key:0,modelValue:P.identityForm.name,"onUpdate:modelValue":t[3]||(t[3]=e=>P.identityForm.name=e),placeholder:"请输入字母开头，只包含字母、数字、下划线“_”、中横线“-”"},null,8,["modelValue"])):Object(o["createCommentVNode"])("",!0),"edit"==P.domainType?(Object(o["openBlock"])(),Object(o["createBlock"])($,{key:1,modelValue:P.identityForm.name,"onUpdate:modelValue":t[4]||(t[4]=e=>P.identityForm.name=e),disabled:"disabled"},null,8,["modelValue"])):Object(o["createCommentVNode"])("",!0)]),_:1}),Object(o["createVNode"])(K,{label:"详情",key:"2"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:P.identityForm.detail,"onUpdate:modelValue":t[5]||(t[5]=e=>P.identityForm.detail=e),placeholder:"请输入详情"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(K,{label:"响应头替换",key:"9"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(Q,{modelValue:P.identityForm.response_header_status,"onUpdate:modelValue":t[6]||(t[6]=e=>P.identityForm.response_header_status=e),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),_:1}),"true"==P.identityForm.response_header_status?(Object(o["openBlock"])(),Object(o["createBlock"])("div",k,[Object(o["createVNode"])(K,{label:"响应头替换配置",key:"10"},{default:Object(o["withCtx"])(()=>[v,(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(P.ruleConfigMatchs,(t,a)=>(Object(o["openBlock"])(),Object(o["createBlock"])("div",{class:"match-box",key:"matchs"+a},[Object(o["createVNode"])("div",x,[Object(o["createVNode"])($,{modelValue:t.key,"onUpdate:modelValue":e=>t.key=e},null,8,["modelValue","onUpdate:modelValue"])]),Object(o["createVNode"])("div",F,[Object(o["createVNode"])($,{modelValue:t.match,"onUpdate:modelValue":e=>t.match=e},null,8,["modelValue","onUpdate:modelValue"])]),Object(o["createVNode"])("div",T,[Object(o["createVNode"])($,{modelValue:t.data,"onUpdate:modelValue":e=>t.data=e},null,8,["modelValue","onUpdate:modelValue"])]),Object(o["createVNode"])(q,{onClick:Object(o["withModifiers"])(a=>z.removeConfigMatchs(t,e.bigIndex),["prevent"])},{default:Object(o["withCtx"])(()=>[B]),_:2},1032,["onClick"])]))),128)),Object(o["createVNode"])(q,{onClick:t[7]||(t[7]=t=>z.addConfigMatchs(e.bigIndex)),plain:"",type:"primary",class:"button-new"},{default:Object(o["withCtx"])(()=>[U]),_:1})]),_:1})])):Object(o["createCommentVNode"])("",!0),Object(o["createVNode"])(K,{label:"响应体替换",key:"6"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(Q,{modelValue:P.identityForm.response_data_status,"onUpdate:modelValue":t[8]||(t[8]=e=>P.identityForm.response_data_status=e),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),_:1}),"true"==P.identityForm.response_data_status?(Object(o["openBlock"])(),Object(o["createBlock"])("div",M,[Object(o["createVNode"])(K,{label:"响应体匹配正则",key:"7"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:P.identityForm.response_data_replace_match,"onUpdate:modelValue":t[9]||(t[9]=e=>P.identityForm.response_data_replace_match=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(K,{label:"响应体替换内容",key:"8"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:P.identityForm.response_data_replace_data,"onUpdate:modelValue":t[10]||(t[10]=e=>P.identityForm.response_data_replace_data=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1})])):Object(o["createCommentVNode"])("",!0)]),_:1},8,["model","rules"])]),_:1},8,["title","modelValue","onClosed"])]),_:1})}var P=a("362c"),z={mixins:[P["b"]],data(){return{domainTitle:"新增",domainType:"new",domainSearch:"",dialogIdentityFormVisible:!1,loading:!1,identityForm:{name:"",detail:"",response_header_status:"false",response_header_replace_data:"",response_data_status:"false",response_data_replace_match:"",response_data_replace_data:""},tableData:[],ruleConfigMatchs:[{key:"",match:"",data:""}]}},computed:{rules(){return{name:[{required:!0,message:"请输入字母开头，只包含字母、数字、下划线“_”、中横线“-”",trigger:["blur","change"]},{validator:P["g"],trigger:["blur","change"]}]}}},mounted(){this.getData()},methods:{getData(){var e=this;Object(P["a"])("get","/waf/waf_get_sys_response_replace_list",{},(function(t){e.tableData=t.data.message,e.tableData.forEach(e=>{e.isVisiblePopover=!1})}),(function(){}))},dialogClose(){this.identityForm={name:"",detail:"",response_header_status:"false",response_header_replace_data:"",response_data_status:"false",response_data_replace_match:"",response_data_replace_data:""},this.ruleConfigMatchs=[{key:"",match:"",data:""}],this.$refs["identityForm"].resetFields()},onClickIdentitySubmit(e){var t=this,a="/waf/waf_create_sys_response_replace";"edit"==t.domainType&&(a="/waf/waf_edit_sys_response_replace");var o="";if("true"==t.identityForm.response_header_status){if(0==t.ruleConfigMatchs.length)return t.$message({message:"请对自定义header头进行配置",type:"error"}),!1;for(var c in t.ruleConfigMatchs){var l=t.ruleConfigMatchs[c];o=0==c?o+'"'+l.key+'":{"replace_match":"'+l.match+'","replace_data":"'+l.data+'"}':o+',"'+l.key+'":{"replace_match":"'+l.match+'","replace_data":"'+l.data+'"}'}o="{"+o+"}"}t.identityForm.response_header_replace_data=o,this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(P["a"])("post",a,t.identityForm,(function(e){t.loading=!1,t.dialogIdentityFormVisible=!1,t.getData()}),(function(){t.loading=!1})))})},onClickCreateIdentity(){var e=this;e.domainTitle="新增",e.domainType="new",e.dialogIdentityFormVisible=!0},handleEdit(e){var t=this;e.loading=!0,Object(P["a"])("post","/waf/waf_get_sys_response_replace",{name:e.name},(function(a){e.loading=!1;var o=a.data.message;if(t.identityForm.name=o.name,t.identityForm.detail=o.detail,t.identityForm.response_header_status=o.response_header_status,t.identityForm.response_header_replace_data=o.response_header_replace_data,t.identityForm.response_data_status=o.response_data_status,t.identityForm.response_data_replace_match=o.response_data_replace_match,t.identityForm.response_data_replace_data=o.response_data_replace_data,"true"==t.identityForm.response_header_status){var c=JSON.parse(t.identityForm.response_header_replace_data),l=[];for(var d in c){var i=c[d].replace_match,r=c[d].replace_data;l.push({key:d,match:i,data:r})}t.ruleConfigMatchs=l}t.domainTitle="编辑",t.domainType="edit",t.dialogIdentityFormVisible=!0}),(function(){e.loading=!1}),"no-message")},handleDelete(e){var t=this;t.loading=!0,Object(P["a"])("post","/waf/waf_del_sys_response_replace",{name:e.name},(function(a){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))},removeConfigMatchs(e){var t=this.ruleConfigMatchs.indexOf(e);t>0&&this.ruleConfigMatchs.splice(t,1)},addConfigMatchs(){this.ruleConfigMatchs.push({key:"",match:"",data:""})}}},E=(a("1f27"),a("d959")),J=a.n(E);const L=J()(z,[["render",S]]);t["default"]=L},e3b0:function(e,t,a){}}]);
//# sourceMappingURL=chunk-3d2bc27a.1e3f1662.js.map