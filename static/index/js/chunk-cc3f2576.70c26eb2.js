(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-cc3f2576"],{"20c3":function(e,a,t){"use strict";t.r(a);var l=t("7a23");const c={class:"custom-edit-wrap"},r=Object(l["createTextVNode"])("网站防护"),o=Object(l["createTextVNode"])("防护配置"),s=Object(l["createTextVNode"])("Web防护规则"),u=Object(l["createTextVNode"])("新增"),n=Object(l["createTextVNode"])("编辑"),i={class:"match-box-content"},d={class:"match_key_cascader"},b={class:"match_key_input"},h=Object(l["createTextVNode"])("删除"),m=Object(l["createTextVNode"])("新增"),p={class:"match-box-content"},_={class:"match_key_cascader"},g=Object(l["createTextVNode"])("删除"),O=Object(l["createTextVNode"])("新增"),v={class:"card-item-bottom"},j=Object(l["createTextVNode"])("删除"),f={class:"card-footer"},k=Object(l["createTextVNode"])("新增"),w=Object(l["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),M=Object(l["createTextVNode"])("保存 ");function V(e,a,t,V,y,C){const B=Object(l["resolveComponent"])("el-breadcrumb-item"),x=Object(l["resolveComponent"])("el-breadcrumb"),N=Object(l["resolveComponent"])("el-row"),R=Object(l["resolveComponent"])("el-input"),F=Object(l["resolveComponent"])("el-form-item"),S=Object(l["resolveComponent"])("el-cascader"),P=Object(l["resolveComponent"])("el-button"),L=Object(l["resolveComponent"])("el-option"),U=Object(l["resolveComponent"])("el-select"),D=Object(l["resolveComponent"])("el-card"),T=Object(l["resolveComponent"])("el-form"),I=Object(l["resolveComponent"])("el-col"),q=Object(l["resolveDirective"])("loading");return Object(l["openBlock"])(),Object(l["createBlock"])("div",c,[Object(l["createVNode"])(N,{class:"breadcrumb-style"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(x,{separator:"/"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(B,{to:{path:"/"}},{default:Object(l["withCtx"])(()=>[r]),_:1}),Object(l["createVNode"])(B,{to:{path:"/protection/"+y.domain}},{default:Object(l["withCtx"])(()=>[o]),_:1},8,["to"]),Object(l["createVNode"])(B,{to:{path:"/web-rule-protection/"+y.domain}},{default:Object(l["withCtx"])(()=>[s]),_:1},8,["to"]),"new"==y.uuid?(Object(l["openBlock"])(),Object(l["createBlock"])(B,{key:0},{default:Object(l["withCtx"])(()=>[u]),_:1})):(Object(l["openBlock"])(),Object(l["createBlock"])(B,{key:1},{default:Object(l["withCtx"])(()=>[n]),_:1}))]),_:1})]),_:1}),Object(l["createVNode"])(N,{class:"container-style"},{default:Object(l["withCtx"])(()=>[Object(l["withDirectives"])(Object(l["createVNode"])(I,{span:24},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(T,{class:"custom-edit-form",model:y.webRuleManageForm,rules:C.rules,ref:"webRuleManageForm","label-width":"180px"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])("div",null,[Object(l["createVNode"])(F,{label:"规则名称",prop:"rule_name"},{default:Object(l["withCtx"])(()=>["new"==y.uuid?(Object(l["openBlock"])(),Object(l["createBlock"])(R,{key:0,modelValue:y.webRuleManageForm.rule_name,"onUpdate:modelValue":a[1]||(a[1]=e=>y.webRuleManageForm.rule_name=e),placeholder:"请输入字母开头，字母或数字组合，仅支持_-两种符号"},null,8,["modelValue"])):(Object(l["openBlock"])(),Object(l["createBlock"])(R,{key:1,modelValue:y.webRuleManageForm.rule_name,"onUpdate:modelValue":a[2]||(a[2]=e=>y.webRuleManageForm.rule_name=e),disabled:""},null,8,["modelValue"]))]),_:1}),Object(l["createVNode"])(F,{label:"规则详情"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(R,{modelValue:y.webRuleManageForm.rule_detail,"onUpdate:modelValue":a[3]||(a[3]=e=>y.webRuleManageForm.rule_detail=e)},null,8,["modelValue"])]),_:1}),Object(l["createVNode"])(D,{class:"box-card-rule"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(y.ruleBigMatchs,(e,a)=>(Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"card-item",key:a},[Object(l["createVNode"])(F,{label:"匹配参数"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.ruleSmallMatchs,(e,t)=>(Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"match-box",key:t},[Object(l["createVNode"])("div",i,[Object(l["createVNode"])("div",d,[Object(l["createVNode"])(S,{separator:":",modelValue:e.rule_match_key_list,"onUpdate:modelValue":a=>e.rule_match_key_list=a,options:y.optionsMatchKey,props:y.propsMatchKey,onChange:t=>C.onChangeRuleMatchs(t,e,a),clearable:""},null,8,["modelValue","onUpdate:modelValue","options","props","onChange"])]),Object(l["withDirectives"])(Object(l["createVNode"])("div",b,[Object(l["createVNode"])(R,{modelValue:e.rule_match_key,"onUpdate:modelValue":a=>e.rule_match_key=a,clearable:"",onChange:t=>C.onChangeRuleInput(t,e,a)},null,8,["modelValue","onUpdate:modelValue","onChange"])],512),[[l["vShow"],e.showInput]])]),Object(l["createVNode"])(P,{onClick:Object(l["withModifiers"])(t=>C.removeRuleMatchs(e,a),["prevent"])},{default:Object(l["withCtx"])(()=>[h]),_:2},1032,["onClick"])]))),128)),Object(l["createVNode"])(P,{onClick:e=>C.addRuleMatchs(a),plain:"",type:"primary"},{default:Object(l["withCtx"])(()=>[m]),_:2},1032,["onClick"])]),_:2},1024),Object(l["createVNode"])(F,{label:"参数处理"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.argsPrepocessList,(e,t)=>(Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"match-box",key:t},[Object(l["createVNode"])("div",p,[Object(l["createVNode"])("div",_,[Object(l["createVNode"])(U,{modelValue:e.args_prepocess_value,"onUpdate:modelValue":a=>e.args_prepocess_value=a,placeholder:"Select"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(y.optionsArgs,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:2},1032,["modelValue","onUpdate:modelValue"])])]),Object(l["createVNode"])(P,{onClick:Object(l["withModifiers"])(t=>C.removeArgsPrepocess(e,a),["prevent"])},{default:Object(l["withCtx"])(()=>[g]),_:2},1032,["onClick"])]))),128)),Object(l["createVNode"])(P,{onClick:e=>C.addArgsPrepocess(a),plain:"",type:"primary"},{default:Object(l["withCtx"])(()=>[O]),_:2},1032,["onClick"])]),_:2},1024),Object(l["createVNode"])(F,{label:"匹配方式"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(U,{modelValue:e.match_operator,"onUpdate:modelValue":a=>e.match_operator=a,placeholder:"请选择"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(y.optionsOperator,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:2},1032,["modelValue","onUpdate:modelValue"])]),_:2},1024),Object(l["createVNode"])(F,{label:"匹配内容"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(R,{modelValue:e.match_value,"onUpdate:modelValue":a=>e.match_value=a},null,8,["modelValue","onUpdate:modelValue"])]),_:2},1024),Object(l["createVNode"])("div",v,[Object(l["createVNode"])(P,{type:"danger",plain:"",onClick:Object(l["withModifiers"])(a=>C.removeRuleBigMatchs(e),["prevent"])},{default:Object(l["withCtx"])(()=>[j]),_:2},1032,["onClick"])])]))),128)),Object(l["createVNode"])("div",f,[Object(l["createVNode"])(P,{class:"button",type:"primary",onClick:a[4]||(a[4]=a=>C.addRuleBigMatchs(e.bigIndex))},{default:Object(l["withCtx"])(()=>[k]),_:1})])]),_:1}),Object(l["createVNode"])(F,{label:"执行动作",prop:"rule_action"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(U,{modelValue:y.webRuleManageForm.rule_action,"onUpdate:modelValue":a[5]||(a[5]=e=>y.webRuleManageForm.rule_action=e),placeholder:"请选择",onChange:a[6]||(a[6]=e=>C.onChangeRuleAction())},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(y.ruleAction,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==y.webRuleManageForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(F,{key:0},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(U,{modelValue:y.action_value,"onUpdate:modelValue":a[7]||(a[7]=e=>y.action_value=e),placeholder:"请选择"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(y.optionsBotCheck,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),w]),_:1})):Object(l["createCommentVNode"])("",!0)])]),_:1},8,["model","rules"]),Object(l["createVNode"])(N,{type:"flex",class:"margin-border",justify:"space-between"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(I,{span:12},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])("a",{class:"el-button el-button--primary is-plain",href:"/#/web-rule-protection/"+y.domain},"返回",8,["href"])]),_:1}),Object(l["createVNode"])(I,{span:12,class:"text-align-right"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(P,{type:"primary",onClick:a[8]||(a[8]=e=>C.onClickWebRuleProSubmit("webRuleManageForm")),loading:y.loading},{default:Object(l["withCtx"])(()=>[M]),_:1},8,["loading"])]),_:1})]),_:1})]),_:1},512),[[q,y.loadingPage,void 0,{fullscreen:!0,lock:!0}]])]),_:1})])}var y=t("362c"),C=t("6c02"),B={mixins:[y["c"]],data(){return{loading:!1,loadingPage:!1,domain:"",uuid:"new",webRuleManageForm:{rule_detail:"",action_value:""},type:"edit",optionsMatchKey:[{value:"http_args",label:"http_args",children:[{value:"path",label:"path",leaf:!0},{value:"query_string",label:"query_string",leaf:!0},{value:"method",label:"method",leaf:!0},{value:"src_ip",label:"src_ip",leaf:!0},{value:"raw_body",label:"raw_body",leaf:!0},{value:"version",label:"version",leaf:!0},{value:"scheme",label:"scheme",leaf:!0},{value:"raw_header",label:"raw_header",leaf:!0}]},{value:"header_args",label:"header_args",children:[{value:"host",label:"host",leaf:!0},{value:"cookie",label:"cookie",leaf:!0},{value:"referer",label:"referer",leaf:!0},{value:"user_agent",label:"user_agent",leaf:!0},{value:"default",label:"自定义",leaf:!0}]},{value:"cookie_args",label:"cookie_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"uri_args",label:"uri_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"post_args",label:"post_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"json_post_args",label:"json_post_args",children:[{value:"default",label:"自定义",leaf:!0}]}],ruleBigMatchs:[{ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",argsPrepocessList:[{args_prepocess_value:""}]}],operator:"",optionsOperator:[{value:"rx",label:"正则匹配"},{value:"str_prefix",label:"前缀匹配"},{value:"str_suffix",label:"后缀匹配"},{value:"str_contain",label:"包含"},{value:"str_ncontain",label:"不包含"},{value:"str_eq",label:"等于"},{value:"str_neq",label:"不等于"},{value:"gt",label:"数字大于"},{value:"lt",label:"数字小于"},{value:"eq",label:"数字等于"},{value:"neq",label:"数字不等于"}],optionsArgs:[{value:"none",label:"不处理",key:"none"},{value:"lowerCase",label:"小写处理",key:"lowerCase"},{value:"base64Decode",label:"BASE64解码",key:"base64Decode"},{value:"length",label:"长度计算",key:"length"},{value:"uriDecode",label:"URL解码",key:"uriDecode"},{value:"uniDecode",label:"UNICODE解码",key:"uniDecode"},{value:"hexDecode",label:"十六进制解码",key:"hexDecode"},{value:"type",label:"获取数据类型",key:"type"}],ruleAction:[{value:"block",label:"阻断请求"},{value:"watch",label:"观察模式"}],optionsBotCheck:[{value:"standard",label:"标准"},{value:"slipper",label:"滑块"},{value:"image",label:"图片验证码"}],optionsDict:[],optionsNameList:[],custom_response:[],request_replace:[],response_replace:[],traffic_forward:[],action_value:"",propsMatchKey:{expandTrigger:"hover"}}},computed:{rules(){return{rule_name:[{required:!0,message:"请输入规则名称",trigger:["blur","change"]},{validator:y["h"],trigger:["blur","change"]}],action_value:[{required:!0,message:"请选择匹配方式",trigger:"change"}],match_value:[{required:!0,message:"请输入匹配内容",trigger:["blur","change"]}],rule_action:[{required:!0,message:"请选择执行动作",trigger:"change"}]}}},mounted(){var e=this;const a=Object(C["c"])();e.uuid=a.params.uuid,e.domain=a.params.domain,e.loadingPage=!1,"new"!=e.uuid&&e.getData()},methods:{getData(){var e=this,a="/waf/waf_get_web_rule_protection",t={domain:e.domain,rule_name:e.uuid};Object(y["a"])("post",a,t,(function(a){e.loadingPage=!1,e.webRuleManageForm=a.data.message,e.webRuleManageForm.rule_name=e.uuid;var t=JSON.parse(e.webRuleManageForm.rule_matchs),l=[];for(var c in t){var r=[],o=[],s=["header_args","cookie_args","uri_args","post_args","json_post_args"];for(var u in t[c].match_args){var n=t[c].match_args[u],i=n.key,d=n.value,b="false";s.indexOf(i)>-1&&(b="true"),"shared_dict"==i?e.optionsDict.forEach(e=>{e.shared_dict_uuid==d&&r.push({rule_match_key_list:[i,e.shared_dict_uuid],rule_match_key:i+":"+e.shared_dict_name,showInput:b})}):r.push({rule_match_key_list:[i,d],rule_match_key:i+":"+d,showInput:b})}for(var h in t[c].args_prepocess)o.push({args_prepocess_value:t[c].args_prepocess[h]});l.push({ruleSmallMatchs:r,argsPrepocessList:o,match_operator:t[c].match_operator,match_value:t[c].match_value})}e.ruleBigMatchs=l,e.action_value=e.webRuleManageForm.action_value}),(function(){e.loadingPage=!1}),"no-message")},onChangeRuleAction(){var e=this;e.action_value=""},onClickWebRuleProSubmit(e){var a=this,t=[];if(0==a.ruleBigMatchs.length)return a.$message({showClose:!0,message:"请输入详细规则",type:"error"}),!1;for(var l in a.ruleBigMatchs){var c=[],r=[];if(0==a.ruleBigMatchs[l].ruleSmallMatchs.length)return a.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;for(var o in a.ruleBigMatchs[l].ruleSmallMatchs){var s=a.ruleBigMatchs[l].ruleSmallMatchs[o];if(""==s.rule_match_key)return a.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;var u="",n=[],i="",d="";s.rule_match_key&&(n=s.rule_match_key.split(":")),n.length>0&&(i=n[0],d=s.rule_match_key.replace(new RegExp(i+":"),""),u='{"key":"'+i+'" , "value":"'+d+'"}'),"shared_dict"==i&&(u='{"key":"'+i+'" , "value":"'+s.rule_match_key_list[1]+'"}'),c.push(JSON.parse(u))}if(0==a.ruleBigMatchs[l].argsPrepocessList.length)return a.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;for(var b in a.ruleBigMatchs[l].argsPrepocessList){if(""==a.ruleBigMatchs[l].argsPrepocessList[b].args_prepocess_value)return a.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;r.push(a.ruleBigMatchs[l].argsPrepocessList[b].args_prepocess_value)}if(""==a.ruleBigMatchs[l].match_operator)return a.$message({showClose:!0,message:"请选择匹配方式",type:"error"}),!1;if(""==a.ruleBigMatchs[l].match_value)return a.$message({showClose:!0,message:"请输入匹配内容",type:"error"}),!1;t.push({match_args:c,args_prepocess:r,match_operator:a.ruleBigMatchs[l].match_operator,match_value:a.ruleBigMatchs[l].match_value})}if("bot_check"==a.webRuleManageForm.rule_action&&""==a.action_value)return a.$message({message:"请选择人机识别方式",type:"error"}),!1;a.webRuleManageForm.domain=a.domain,a.webRuleManageForm.action_value=a.action_value;var h="/waf/waf_edit_web_rule_protection";"new"==a.uuid?h="/waf/waf_create_web_rule_protection":a.webRuleManageForm.rule_name=a.uuid,a.webRuleManageForm.rule_matchs=JSON.stringify(t),this.$refs[e].validate(e=>{e&&(a.loading=!0,Object(y["a"])("post",h,a.webRuleManageForm,(function(e){a.loading=!1,window.location.href="/#/web-rule-protection/"+a.domain}),(function(){a.loading=!1})))})},removeArgsPrepocess(e,a){var t=this.ruleBigMatchs[a].argsPrepocessList.indexOf(e);-1!=t&&this.ruleBigMatchs[a].argsPrepocessList.splice(t,1)},addArgsPrepocess(e){this.ruleBigMatchs[e].argsPrepocessList.push({args_prepocess_value:""})},addRuleMatchs(e){this.ruleBigMatchs[e].ruleSmallMatchs.push({rule_match_key:"",rule_match_key_list:[],showInput:!1})},removeRuleMatchs(e,a){var t=this.ruleBigMatchs[a].ruleSmallMatchs.indexOf(e);-1!=t&&this.ruleBigMatchs[a].ruleSmallMatchs.splice(t,1)},removeRuleBigMatchs(e){var a=this.ruleBigMatchs.indexOf(e);-1!=a&&this.ruleBigMatchs.splice(a,1)},addRuleBigMatchs(e){this.ruleBigMatchs.push({ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",argsPrepocessList:[{args_prepocess_value:""}]})},onChangeRuleMatchs(e,a,t){var l=this.ruleBigMatchs[t].ruleSmallMatchs.indexOf(a);"default"==e[1]?(this.ruleBigMatchs[t].ruleSmallMatchs[l].showInput=!0,this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key=e[0]+":"):this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key=e[0]+":"+e[1]},onChangeRuleInput(e,a,t){var l=this.ruleBigMatchs[t].ruleSmallMatchs.indexOf(a);""==e?(this.ruleBigMatchs[t].ruleSmallMatchs[l].showInput=!1,this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key="",this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key_list=[]):this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key=e}}},x=(t("46c6"),t("d959")),N=t.n(x);const R=N()(B,[["render",V]]);a["default"]=R},"46c6":function(e,a,t){"use strict";t("4bf5")},"4bf5":function(e,a,t){}}]);
//# sourceMappingURL=chunk-cc3f2576.70c26eb2.js.map