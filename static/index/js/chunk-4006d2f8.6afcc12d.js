(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-4006d2f8"],{"68f2":function(e,l,a){"use strict";a.r(l);var t=a("7a23");const c={class:"custom-edit-wrap"},o=Object(t["createTextVNode"])("防护管理"),r=Object(t["createTextVNode"])("名单防护"),s=Object(t["createTextVNode"])("新增"),i=Object(t["createTextVNode"])("编辑"),n=Object(t["createTextVNode"])("无限制"),_=Object(t["createTextVNode"])("自定义"),u={class:"match-box-content"},d={class:"match_key_cascader"},b={class:"match_key_input"},m=Object(t["createTextVNode"])("删除"),h=Object(t["createTextVNode"])("新增"),p=Object(t["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),f=Object(t["createVNode"])("a",{class:"el-button el-button--primary is-plain",href:"/#/name-list"},"返回",-1),v=Object(t["createTextVNode"])("保存 ");function j(e,l,a,j,O,k){const g=Object(t["resolveComponent"])("el-breadcrumb-item"),y=Object(t["resolveComponent"])("el-breadcrumb"),w=Object(t["resolveComponent"])("el-row"),x=Object(t["resolveComponent"])("el-input"),N=Object(t["resolveComponent"])("el-form-item"),V=Object(t["resolveComponent"])("el-radio"),C=Object(t["resolveComponent"])("el-cascader"),q=Object(t["resolveComponent"])("el-button"),L=Object(t["resolveComponent"])("el-option"),M=Object(t["resolveComponent"])("el-select"),F=Object(t["resolveComponent"])("el-form"),S=Object(t["resolveComponent"])("el-col"),B=Object(t["resolveDirective"])("loading");return Object(t["openBlock"])(),Object(t["createBlock"])("div",c,[Object(t["createVNode"])(w,{class:"breadcrumb-style"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(y,{separator:"/"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(g,{to:{path:"/"}},{default:Object(t["withCtx"])(()=>[o]),_:1}),Object(t["createVNode"])(g,{to:{path:"/name-list"}},{default:Object(t["withCtx"])(()=>[r]),_:1}),"new"==O.uuid?(Object(t["openBlock"])(),Object(t["createBlock"])(g,{key:0},{default:Object(t["withCtx"])(()=>[s]),_:1})):(Object(t["openBlock"])(),Object(t["createBlock"])(g,{key:1},{default:Object(t["withCtx"])(()=>[i]),_:1}))]),_:1})]),_:1}),Object(t["createVNode"])(w,{class:"container-style"},{default:Object(t["withCtx"])(()=>[Object(t["withDirectives"])(Object(t["createVNode"])(S,{span:24},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(F,{class:"custom-edit-form name-and-dict",model:O.sysNameListForm,rules:k.rules,ref:"sysNameListForm","label-width":"180px"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])("div",null,[Object(t["createVNode"])(N,{label:"名单名称",prop:"name_list_name"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(x,{modelValue:O.sysNameListForm.name_list_name,"onUpdate:modelValue":l[1]||(l[1]=e=>O.sysNameListForm.name_list_name=e),placeholder:"请输入字母开头，字母或数字组合，仅支持_-两种符号"},null,8,["modelValue"])]),_:1}),Object(t["createVNode"])(N,{label:"名单描述"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(x,{modelValue:O.sysNameListForm.name_list_detail,"onUpdate:modelValue":l[2]||(l[2]=e=>O.sysNameListForm.name_list_detail=e)},null,8,["modelValue"])]),_:1}),Object(t["createVNode"])(N,{label:"过期时间（秒）"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(V,{modelValue:O.sysNameListForm.name_list_expire,"onUpdate:modelValue":l[3]||(l[3]=e=>O.sysNameListForm.name_list_expire=e),label:"false"},{default:Object(t["withCtx"])(()=>[n]),_:1},8,["modelValue"]),Object(t["createVNode"])(V,{modelValue:O.sysNameListForm.name_list_expire,"onUpdate:modelValue":l[4]||(l[4]=e=>O.sysNameListForm.name_list_expire=e),label:"ture"},{default:Object(t["withCtx"])(()=>[_]),_:1},8,["modelValue"])]),_:1}),"ture"==O.sysNameListForm.name_list_expire?(Object(t["openBlock"])(),Object(t["createBlock"])(N,{key:0,prop:"name_list_expire_time"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(x,{modelValue:O.sysNameListForm.name_list_expire_time,"onUpdate:modelValue":l[5]||(l[5]=e=>O.sysNameListForm.name_list_expire_time=e),placeholder:"请输入大于0的数字"},null,8,["modelValue"])]),_:1})):Object(t["createCommentVNode"])("",!0),Object(t["createVNode"])(N,{label:"匹配参数"},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(O.ruleSmallMatchs,(l,a)=>(Object(t["openBlock"])(),Object(t["createBlock"])("div",{class:"match-box",key:a},[Object(t["createVNode"])("div",u,[Object(t["createVNode"])("div",d,[Object(t["createVNode"])(C,{separator:":",modelValue:l.rule_match_key_list,"onUpdate:modelValue":e=>l.rule_match_key_list=e,options:O.optionsMatchKey,props:O.propsMatchKey,onChange:a=>k.onChangeRuleMatchs(a,l,e.bigIndex),clearable:""},null,8,["modelValue","onUpdate:modelValue","options","props","onChange"])]),Object(t["withDirectives"])(Object(t["createVNode"])("div",b,[Object(t["createVNode"])(x,{modelValue:l.rule_match_key,"onUpdate:modelValue":e=>l.rule_match_key=e,clearable:"",onChange:a=>k.onChangeRuleInput(a,l,e.bigIndex)},null,8,["modelValue","onUpdate:modelValue","onChange"])],512),[[t["vShow"],l.showInput]])]),Object(t["createVNode"])(q,{onClick:Object(t["withModifiers"])(a=>k.removeRuleMatchs(l,e.bigIndex),["prevent"])},{default:Object(t["withCtx"])(()=>[m]),_:2},1032,["onClick"])]))),128)),Object(t["createVNode"])(q,{onClick:l[6]||(l[6]=l=>k.addRuleMatchs(e.bigIndex)),plain:"",type:"primary",class:"button-new"},{default:Object(t["withCtx"])(()=>[h]),_:1})]),_:1}),Object(t["createVNode"])(N,{label:"执行动作",prop:"name_list_action"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(M,{modelValue:O.sysNameListForm.name_list_action,"onUpdate:modelValue":l[7]||(l[7]=e=>O.sysNameListForm.name_list_action=e),placeholder:"请选择",onChange:l[8]||(l[8]=e=>k.onChangeRuleAction())},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(O.ruleAction,e=>(Object(t["openBlock"])(),Object(t["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==O.sysNameListForm.name_list_action?(Object(t["openBlock"])(),Object(t["createBlock"])(N,{key:1},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(M,{modelValue:O.sysNameListForm.action_value,"onUpdate:modelValue":l[9]||(l[9]=e=>O.sysNameListForm.action_value=e),placeholder:"请选择"},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(O.optionsBotCheck,e=>(Object(t["openBlock"])(),Object(t["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),p]),_:1})):Object(t["createCommentVNode"])("",!0)])]),_:1},8,["model","rules"]),Object(t["createVNode"])(w,{type:"flex",class:"margin-border",justify:"space-between"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(S,{span:12},{default:Object(t["withCtx"])(()=>[f]),_:1}),Object(t["createVNode"])(S,{span:12,class:"text-align-right"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(q,{type:"primary",onClick:l[10]||(l[10]=e=>k.onClickWebRuleProSubmit("sysNameListForm")),loading:O.loading},{default:Object(t["withCtx"])(()=>[v]),_:1},8,["loading"])]),_:1})]),_:1})]),_:1},512),[[B,O.loadingPage,void 0,{fullscreen:!0,lock:!0}]])]),_:1})])}var O=a("362c"),k=a("6c02"),g={mixins:[O["c"]],data(){return{loading:!1,loadingPage:!1,uuid:"",sysNameListForm:{name_list_name:"",name_list_detail:"",name_list_rule:"",name_list_action:"",name_list_expire:"false",name_list_expire_time:"",action_value:""},type:"edit",optionsMatchKey:[{value:"waf_log",label:"waf_log",children:[{value:"cookie",label:"cookie",leaf:!0},{value:"post_data",label:"post_data",leaf:!0},{value:"query_string",label:"query_string",leaf:!0},{value:"host",label:"host",leaf:!0},{value:"uri",label:"uri",leaf:!0},{value:"src_ip",label:"src_ip",leaf:!0},{value:"req_raw_data",label:"req_raw_data",leaf:!0},{value:"res_raw_data",label:"res_raw_data",leaf:!0},{value:"waf_description",label:"waf_description",leaf:!0},{value:"content_length",label:"content_length",leaf:!0},{value:"ret_code",label:"ret_code",leaf:!0},{value:"ssl_ciphers",label:"ssl_ciphers",leaf:!0},{value:"ssl_protocol",label:"ssl_protocol",leaf:!0},{value:"request_time",label:"request_time",leaf:!0},{value:"user_agent",label:"user_agent",leaf:!0},{value:"waf_action",label:"waf_action",leaf:!0},{value:"waf_app",label:"waf_app",leaf:!0},{value:"x5_action",label:"x5_action",leaf:!0},{value:"x5_policy_id",label:"x5_policy_id",leaf:!0},{value:"x5_test",label:"x5_test",leaf:!0},{value:"x_forward_for",label:"x_forward_for",leaf:!0},{value:"waf_service",label:"waf_service",leaf:!0},{value:"set_cookie",label:"set_cookie",leaf:!0},{value:"rqs_content_type",label:"rqs_content_type",leaf:!0},{value:"rsp_content_type",label:"rsp_content_type",leaf:!0},{value:"request_datetime",label:"request_datetime",leaf:!0},{value:"region",label:"region",leaf:!0},{value:"referer",label:"referer",leaf:!0},{value:"method",label:"method",leaf:!0},{value:"jump_location",label:"jump_location",leaf:!0},{value:"https",label:"https",leaf:!0},{value:"eagleeye_traceid",label:"eagleeye_traceid",leaf:!0},{value:"dst_ip",label:"dst_ip",leaf:!0}]},{value:"query_string",label:"query_string",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"json_post",label:"json_post",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"post",label:"post",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"cookie",label:"cookie",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"self_learn_result",label:"self_learn_result",children:[{value:"new_uri_check",label:"new_uri_check",leaf:!0},{value:"query_string_token_check",label:"query_string_token_check",leaf:!0},{value:"post_data_token_check",label:"post_data_token_check",leaf:!0},{value:"ioc_domain_collect_check",label:"ioc_domain_collect_check",leaf:!0},{value:"ioc_ip_collect_check",label:"ioc_ip_collect_check",leaf:!0},{value:"sql_query_string_token_check",label:"sql_query_string_token_check",leaf:!0},{value:"sql_post_data_token_check",label:"sql_post_data_token_check",leaf:!0},{value:"bash_rce_query_string_token_check",label:"bash_rce_query_string_token_check",leaf:!0},{value:"bash_rce_post_data_token_check",label:"bash_rce_post_data_token_check",leaf:!0}]},{value:"self_learn",label:"self_learn",children:[{value:"query_string_token",label:"query_string_token",leaf:!0},{value:"post_data_token",label:"post_data_token",leaf:!0},{value:"ioc_domain_collect",label:"ioc_domain_collect",leaf:!0},{value:"ioc_ip_collect",label:"ioc_ip_collect",leaf:!0},{value:"sql_query_string_token",label:"sql_query_string_token",leaf:!0},{value:"sql_post_data_token",label:"sql_post_data_token",leaf:!0},{value:"bash_rce_query_string_token",label:"bash_rce_query_string_token",leaf:!0},{value:"bash_rce_post_data_token",label:"bash_rce_post_data_token",leaf:!0}]},{value:"waf_description",label:"waf_description",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"ctx",label:"ctx",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"string",label:"string",children:[{value:"default",label:"自定义",leaf:!0}]}],propsMatchKey:{expandTrigger:"hover",lazy:!0,lazyLoad(e,l){}},ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],ruleAction:[{value:"block",label:"阻断请求"},{value:"reject_response",label:"拒绝响应"},{value:"watch",label:"观察模式"},{value:"bot_check",label:"人机识别"}],optionsBotCheck:[{value:"standard",label:"标准"},{value:"slipper",label:"滑块"},{value:"image",label:"图片验证码"}]}},computed:{rules(){return{name_list_name:[{required:!0,message:"请输入规则名称",trigger:["blur","change"]},{validator:O["i"],trigger:["blur","change"]}],name_list_expire_time:[{required:!0,message:"请输入大于0的数字",trigger:["blur","change"]},{validator:O["h"],trigger:["blur","change"]}],name_list_action:[{required:!0,message:"请选择执行动作",trigger:"change"}]}}},mounted(){var e=this;const l=Object(k["c"])();e.uuid=l.params.uuid,"new"==e.uuid?(e.type="new",e.loadingPage=!1):(e.type="edit",e.loadingPage=!1,e.getData())},methods:{getData(){var e=this,l="/waf/waf_get_name_list",a={name_list_name:e.uuid};Object(O["a"])("post",l,a,(function(l){e.loadingPage=!1,e.sysNameListForm=l.data.message;var a=JSON.parse(e.sysNameListForm.name_list_rule),t=[],c=["query_string","json_post","post","cookie","waf_description","ctx","string"];for(var o in a){var r=a[o],s=r.key,i=r.value,n="false";c.indexOf(s)>-1&&(n="true"),t.push({rule_match_key_list:[s,i],rule_match_key:s+":"+i,showInput:n})}e.ruleSmallMatchs=t}),(function(){e.loadingPage=!1}),"no-message")},onClickWebRuleProSubmit(e){var l=this,a=[];if(0==l.ruleSmallMatchs.length)return l.$message({message:"请选择匹配参数",type:"error"}),!1;if(""==l.ruleSmallMatchs[0].rule_match_key)return l.$message({message:"请选择匹配参数",type:"error"}),!1;for(var t in l.ruleSmallMatchs){var c=l.ruleSmallMatchs[t],o="",r=[],s="",i="";c.rule_match_key&&(r=c.rule_match_key.split(":")),r.length>0&&(s=r[0],i=c.rule_match_key.replace(new RegExp(s+":"),""),o='{"key":"'+s+'" , "value":"'+i+'"}'),a.push(JSON.parse(o))}"false"==l.sysNameListForm.name_list_expire&&(l.sysNameListForm.name_list_expire_time=0);var n="/waf/waf_edit_name_list";"new"==l.type&&(n="/waf/waf_create_name_list"),l.sysNameListForm.name_list_rule=JSON.stringify(a),this.$refs[e].validate(e=>{e&&(l.loading=!0,Object(O["a"])("post",n,l.sysNameListForm,(function(e){l.loading=!1,window.location.href="/#/name-list/"}),(function(){l.loading=!1})))})},onChangeRuleAction(){var e=this;e.action_value=""},removeRuleMatchs(e){var l=this.ruleSmallMatchs.indexOf(e);-1!==l&&this.ruleSmallMatchs.splice(l,1)},addRuleMatchs(){this.ruleSmallMatchs.push({rule_match_key:"",showInput:!1})},onChangeRuleMatchs(e,l,a){if(e&&e.length>0){var t=this.ruleSmallMatchs.indexOf(l);"default"==e[1]?(this.ruleSmallMatchs[t].showInput=!0,this.ruleSmallMatchs[t].rule_match_key=e[0]+":"):this.ruleSmallMatchs[t].rule_match_key=e[0]+":"+e[1]}},onChangeRuleInput(e,l,a){var t=this.ruleSmallMatchs.indexOf(l);""==e?(this.ruleSmallMatchs[t].showInput=!1,this.ruleSmallMatchs[t].rule_match_key="",this.ruleSmallMatchs[t].rule_match_key_list=[]):this.ruleSmallMatchs[t].rule_match_key=e}}},y=(a("e4e2"),a("d959")),w=a.n(y);const x=w()(g,[["render",j]]);l["default"]=x},e2c9:function(e,l,a){},e4e2:function(e,l,a){"use strict";a("e2c9")}}]);
//# sourceMappingURL=chunk-4006d2f8.6afcc12d.js.map