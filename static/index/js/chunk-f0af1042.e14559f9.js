(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-f0af1042"],{"087d4":function(e,t,a){"use strict";a("fbca")},7604:function(e,t,a){"use strict";a.r(t);var o=a("7a23");const c=Object(o["createVNode"])("h3",null,"请求替换配置",-1),l={class:"domain-search-input"},d=Object(o["createTextVNode"])("新增"),i={class:"demo-block"},r={key:0},n=Object(o["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),s=Object(o["createTextVNode"])("已开启 "),b={key:1},m=Object(o["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),u=Object(o["createTextVNode"])("已关闭 "),p={key:0},j=Object(o["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),O=Object(o["createTextVNode"])("已开启 "),V={key:1},_=Object(o["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),h=Object(o["createTextVNode"])("已关闭 "),y={key:0},f=Object(o["createVNode"])("i",{class:"el-icon-circle-check icon-success"},null,-1),g=Object(o["createTextVNode"])("已开启 "),C={key:1},N=Object(o["createVNode"])("i",{class:"el-icon-circle-close icon-error"},null,-1),k=Object(o["createTextVNode"])("已关闭 "),w=Object(o["createTextVNode"])("编辑"),v=Object(o["createVNode"])("p",null,"确定删除吗？",-1),x={style:{"text-align":"right",margin:"0"}},F=Object(o["createTextVNode"])("取消"),T=Object(o["createTextVNode"])("确定 "),B=Object(o["createTextVNode"])("删除"),U={key:0},M={key:1},I=Object(o["createVNode"])("div",{class:"match-title"},[Object(o["createVNode"])("p",null,"Header头"),Object(o["createVNode"])("p",null,"正则匹配"),Object(o["createVNode"])("p",null,"替换内容")],-1),D={class:"match-key-item"},P={class:"match-key-item"},S={class:"match-key-item"},E=Object(o["createTextVNode"])("删除"),q=Object(o["createTextVNode"])("新增"),z={key:2},G=Object(o["createTextVNode"])("取消"),H=Object(o["createTextVNode"])("确定");function J(e,t,a,J,L,$){const A=Object(o["resolveComponent"])("el-col"),K=Object(o["resolveComponent"])("el-row"),Q=Object(o["resolveComponent"])("el-divider"),R=Object(o["resolveComponent"])("el-input"),W=Object(o["resolveComponent"])("el-button"),X=Object(o["resolveComponent"])("el-table-column"),Y=Object(o["resolveComponent"])("el-popover"),Z=Object(o["resolveComponent"])("el-table"),ee=Object(o["resolveComponent"])("el-form-item"),te=Object(o["resolveComponent"])("el-switch"),ae=Object(o["resolveComponent"])("el-form"),oe=Object(o["resolveComponent"])("el-dialog");return Object(o["openBlock"])(),Object(o["createBlock"])(K,null,{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(A,{span:24},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(K,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(A,{span:24},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(K,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(A,{span:12},{default:Object(o["withCtx"])(()=>[c]),_:1})]),_:1})]),_:1})]),_:1}),Object(o["createVNode"])(Q),Object(o["createVNode"])(K,{class:"text-align-right"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",l,[Object(o["createVNode"])(R,{placeholder:"请输入名称进行搜索","prefix-icon":"el-icon-search",modelValue:L.domainSearch,"onUpdate:modelValue":t[1]||(t[1]=e=>L.domainSearch=e)},null,8,["modelValue"])]),Object(o["createVNode"])(W,{type:"primary",onClick:t[2]||(t[2]=e=>$.onClickCreateIdentity())},{default:Object(o["withCtx"])(()=>[d]),_:1})]),_:1}),Object(o["createVNode"])("div",i,[Object(o["createVNode"])(Z,{data:L.tableData.filter(e=>!L.domainSearch||e.name.toLowerCase().includes(L.domainSearch.toLowerCase())),style:{width:"100%"}},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(X,{prop:"name",label:"名称"}),Object(o["createVNode"])(X,{prop:"detail",label:"详情"}),Object(o["createVNode"])(X,{prop:"status",label:"GET请求内容替换"},{default:Object(o["withCtx"])(e=>["true"==e.row.get_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",r,[n,s])):Object(o["createCommentVNode"])("",!0),"false"==e.row.get_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",b,[m,u])):Object(o["createCommentVNode"])("",!0)]),_:1}),Object(o["createVNode"])(X,{prop:"status",label:"Header请求内容替换"},{default:Object(o["withCtx"])(e=>["true"==e.row.header_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",p,[j,O])):Object(o["createCommentVNode"])("",!0),"false"==e.row.header_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",V,[_,h])):Object(o["createCommentVNode"])("",!0)]),_:1}),Object(o["createVNode"])(X,{prop:"status",label:"Post请求内容替换"},{default:Object(o["withCtx"])(e=>["true"==e.row.post_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",y,[f,g])):Object(o["createCommentVNode"])("",!0),"false"==e.row.post_status?(Object(o["openBlock"])(),Object(o["createBlock"])("span",C,[N,k])):Object(o["createCommentVNode"])("",!0)]),_:1}),Object(o["createVNode"])(X,{label:"操作",align:"right"},{default:Object(o["withCtx"])(e=>[Object(o["createVNode"])(W,{size:"mini",onClick:t=>$.handleEdit(e.row),class:"button-block",type:"text",loading:e.row.loading},{default:Object(o["withCtx"])(()=>[w]),_:2},1032,["onClick","loading"]),Object(o["createVNode"])(Y,{placement:"top",width:"160",visible:e.row.isVisiblePopover,"onUpdate:visible":t=>e.row.isVisiblePopover=t},{reference:Object(o["withCtx"])(()=>[Object(o["createVNode"])(W,{type:"text",size:"mini",onClick:t=>e.row.isVisiblePopover=!0},{default:Object(o["withCtx"])(()=>[B]),_:2},1032,["onClick"])]),default:Object(o["withCtx"])(()=>[v,Object(o["createVNode"])("div",x,[Object(o["createVNode"])(W,{size:"mini",type:"text",onClick:t=>e.row.isVisiblePopover=!1},{default:Object(o["withCtx"])(()=>[F]),_:2},1032,["onClick"]),Object(o["createVNode"])(W,{type:"primary",size:"mini",onClick:t=>$.handleDelete(e.row),loading:L.loading},{default:Object(o["withCtx"])(()=>[T]),_:2},1032,["onClick","loading"])])]),_:2},1032,["visible","onUpdate:visible"])]),_:1})]),_:1},8,["data"])])]),_:1}),Object(o["createVNode"])(oe,{title:L.domainTitle,modelValue:L.dialogIdentityFormVisible,"onUpdate:modelValue":t[16]||(t[16]=e=>L.dialogIdentityFormVisible=e),width:"820px","close-on-click-modal":!1,onClosed:$.dialogClose},{footer:Object(o["withCtx"])(()=>[Object(o["createVNode"])(W,{onClick:t[14]||(t[14]=e=>L.dialogIdentityFormVisible=!1)},{default:Object(o["withCtx"])(()=>[G]),_:1}),Object(o["createVNode"])(W,{type:"primary",onClick:t[15]||(t[15]=e=>$.onClickIdentitySubmit("identityForm")),loading:L.loading},{default:Object(o["withCtx"])(()=>[H]),_:1},8,["loading"])]),default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(ae,{class:"form-tag-dialog identity-edit-form ",model:L.identityForm,size:"mini","label-position":"left","label-width":"130px",rules:$.rules,ref:"identityForm"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(ee,{label:"名称",prop:"name",key:"1"},{default:Object(o["withCtx"])(()=>["new"==L.domainType?(Object(o["openBlock"])(),Object(o["createBlock"])(R,{key:0,modelValue:L.identityForm.name,"onUpdate:modelValue":t[3]||(t[3]=e=>L.identityForm.name=e),placeholder:"请输入字母开头，只包含字母、数字、下划线“_”、中横线“-”"},null,8,["modelValue"])):Object(o["createCommentVNode"])("",!0),"edit"==L.domainType?(Object(o["openBlock"])(),Object(o["createBlock"])(R,{key:1,modelValue:L.identityForm.name,"onUpdate:modelValue":t[4]||(t[4]=e=>L.identityForm.name=e),disabled:"disabled"},null,8,["modelValue"])):Object(o["createCommentVNode"])("",!0)]),_:1}),Object(o["createVNode"])(ee,{label:"详情",key:"2"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(R,{modelValue:L.identityForm.detail,"onUpdate:modelValue":t[5]||(t[5]=e=>L.identityForm.detail=e),placeholder:"请输入详情"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(ee,{label:"GET请求内容替换",key:"3"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(te,{modelValue:L.identityForm.get_status,"onUpdate:modelValue":t[6]||(t[6]=e=>L.identityForm.get_status=e),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),_:1}),"true"==L.identityForm.get_status?(Object(o["openBlock"])(),Object(o["createBlock"])("div",U,[Object(o["createVNode"])(ee,{label:"GET内容匹配正则",key:"4"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(R,{modelValue:L.identityForm.get_replace_match,"onUpdate:modelValue":t[7]||(t[7]=e=>L.identityForm.get_replace_match=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(ee,{label:"GET替换内容",key:"5"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(R,{modelValue:L.identityForm.get_replace_data,"onUpdate:modelValue":t[8]||(t[8]=e=>L.identityForm.get_replace_data=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1})])):Object(o["createCommentVNode"])("",!0),Object(o["createVNode"])(ee,{label:"Header内容替换",key:"9"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(te,{modelValue:L.identityForm.header_status,"onUpdate:modelValue":t[9]||(t[9]=e=>L.identityForm.header_status=e),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),_:1}),"true"==L.identityForm.header_status?(Object(o["openBlock"])(),Object(o["createBlock"])("div",M,[Object(o["createVNode"])(ee,{label:"Header替换配置",key:"10"},{default:Object(o["withCtx"])(()=>[I,(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(L.ruleConfigMatchs,(t,a)=>(Object(o["openBlock"])(),Object(o["createBlock"])("div",{class:"match-box",key:"matchs"+a},[Object(o["createVNode"])("div",D,[Object(o["createVNode"])(R,{modelValue:t.key,"onUpdate:modelValue":e=>t.key=e},null,8,["modelValue","onUpdate:modelValue"])]),Object(o["createVNode"])("div",P,[Object(o["createVNode"])(R,{modelValue:t.match,"onUpdate:modelValue":e=>t.match=e},null,8,["modelValue","onUpdate:modelValue"])]),Object(o["createVNode"])("div",S,[Object(o["createVNode"])(R,{modelValue:t.data,"onUpdate:modelValue":e=>t.data=e},null,8,["modelValue","onUpdate:modelValue"])]),Object(o["createVNode"])(W,{onClick:Object(o["withModifiers"])(a=>$.removeConfigMatchs(t,e.bigIndex),["prevent"])},{default:Object(o["withCtx"])(()=>[E]),_:2},1032,["onClick"])]))),128)),Object(o["createVNode"])(W,{onClick:t[10]||(t[10]=t=>$.addConfigMatchs(e.bigIndex)),plain:"",type:"primary",class:"button-new"},{default:Object(o["withCtx"])(()=>[q]),_:1})]),_:1})])):Object(o["createCommentVNode"])("",!0),Object(o["createVNode"])(ee,{label:"Post请求内容替换",key:"6"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(te,{modelValue:L.identityForm.post_status,"onUpdate:modelValue":t[11]||(t[11]=e=>L.identityForm.post_status=e),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),_:1}),"true"==L.identityForm.post_status?(Object(o["openBlock"])(),Object(o["createBlock"])("div",z,[Object(o["createVNode"])(ee,{label:"Post内容匹配正则",key:"7"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(R,{modelValue:L.identityForm.post_replace_match,"onUpdate:modelValue":t[12]||(t[12]=e=>L.identityForm.post_replace_match=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(ee,{label:"Post替换内容",key:"8"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(R,{modelValue:L.identityForm.post_replace_data,"onUpdate:modelValue":t[13]||(t[13]=e=>L.identityForm.post_replace_data=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1})])):Object(o["createCommentVNode"])("",!0)]),_:1},8,["model","rules"])]),_:1},8,["title","modelValue","onClosed"])]),_:1})}var L=a("362c"),$={mixins:[L["b"]],data(){return{domainTitle:"新增",domainType:"new",domainSearch:"",dialogIdentityFormVisible:!1,loading:!1,identityForm:{name:"",detail:"",get_status:"false",get_replace_match:"",get_replace_data:"",header_status:"false",header_replace_data:"",post_status:"false",post_replace_match:"",post_replace_data:""},tableData:[],ruleConfigMatchs:[{key:"",match:"",data:""}]}},computed:{rules(){return{name:[{required:!0,message:"请输入字母开头，只包含字母、数字、下划线“_”、中横线“-”",trigger:["blur","change"]},{validator:L["h"],trigger:["blur","change"]}]}}},mounted(){this.getData()},methods:{getData(){var e=this;Object(L["a"])("get","/waf/waf_get_sys_request_replace_list",{},(function(t){e.tableData=t.data.message,e.tableData.forEach(e=>{e.isVisiblePopover=!1})}),(function(){}))},dialogClose(){this.identityForm={name:"",detail:"",get_status:"false",get_replace_match:"",get_replace_data:"",header_status:"false",header_replace_data:"",post_status:"false",post_replace_match:"",post_replace_data:""},this.ruleConfigMatchs=[{key:"",match:"",data:""}],this.$refs["identityForm"].resetFields()},onClickIdentitySubmit(e){var t=this,a="/waf/waf_create_sys_request_replace";"edit"==t.domainType&&(a="/waf/waf_edit_sys_request_replace");var o="";if("true"==t.identityForm.get_status){if(0==t.ruleConfigMatchs.length)return t.$message({message:"请对自定义header头进行配置",type:"error"}),!1;for(var c in t.ruleConfigMatchs){var l=t.ruleConfigMatchs[c];o=0==c?o+'"'+l.key+'":{"replace_match":"'+l.match+'","replace_data":"'+l.data+'"}':o+',"'+l.key+'":{"replace_match":"'+l.match+'","replace_data":"'+l.data+'"}'}o="{"+o+"}"}t.identityForm.header_replace_data=o,this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(L["a"])("post",a,t.identityForm,(function(e){t.loading=!1,t.dialogIdentityFormVisible=!1,t.getData()}),(function(){t.loading=!1})))})},onClickCreateIdentity(){var e=this;e.domainTitle="新增",e.domainType="new",e.dialogIdentityFormVisible=!0},handleEdit(e){var t=this;e.loading=!0,Object(L["a"])("post","/waf/waf_get_sys_request_replace",{name:e.name},(function(a){e.loading=!1;var o=a.data.message;if(t.identityForm.name=o.name,t.identityForm.detail=o.detail,t.identityForm.get_status=o.get_status,t.identityForm.get_replace_match=o.get_replace_match,t.identityForm.get_replace_data=o.get_replace_data,t.identityForm.header_status=o.header_status,t.identityForm.header_replace_data=o.header_replace_data,t.identityForm.post_status=o.post_status,t.identityForm.post_replace_match=o.post_replace_match,t.identityForm.post_replace_data=o.post_replace_data,"true"==t.identityForm.header_status){var c=JSON.parse(t.identityForm.header_replace_data),l=[];for(var d in c){var i=c[d].replace_match,r=c[d].replace_data;l.push({key:d,match:i,data:r})}t.ruleConfigMatchs=l}t.domainTitle="编辑",t.domainType="edit",t.dialogIdentityFormVisible=!0}),(function(){e.loading=!1}),"no-message")},handleDelete(e){var t=this;t.loading=!0,Object(L["a"])("post","/waf/waf_del_sys_request_replace",{name:e.name},(function(a){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))},removeConfigMatchs(e){var t=this.ruleConfigMatchs.indexOf(e);t>0&&this.ruleConfigMatchs.splice(t,1)},addConfigMatchs(){this.ruleConfigMatchs.push({key:"",match:"",data:""})}}},A=(a("087d4"),a("d959")),K=a.n(A);const Q=K()($,[["render",J]]);t["default"]=Q},fbca:function(e,t,a){}}]);
//# sourceMappingURL=chunk-f0af1042.e14559f9.js.map