(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2f29cf4f"],{"7ce0":function(e,a,l){"use strict";l.r(a);var t=l("7a23");const r={class:"custom-edit-wrap"},c=Object(t["createTextVNode"])("网站防护"),o=Object(t["createTextVNode"])("防护配置"),s=Object(t["createTextVNode"])("流量白名单规则"),u=Object(t["createTextVNode"])("新增"),i=Object(t["createTextVNode"])("编辑"),n={class:"match-box-content"},d={class:"match_key_cascader"},h={class:"match_key_input"},b=Object(t["createTextVNode"])("删除"),m=Object(t["createTextVNode"])("新增"),_={class:"match-box-content"},p={class:"match_key_cascader"},g=Object(t["createTextVNode"])("删除"),O=Object(t["createTextVNode"])("新增"),v={class:"card-item-bottom"},j=Object(t["createTextVNode"])("删除"),f={class:"card-footer"},w=Object(t["createTextVNode"])("新增"),k=Object(t["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),M=Object(t["createTextVNode"])("保存 ");function V(e,a,l,V,y,C){const B=Object(t["resolveComponent"])("el-breadcrumb-item"),x=Object(t["resolveComponent"])("el-breadcrumb"),N=Object(t["resolveComponent"])("el-row"),R=Object(t["resolveComponent"])("el-input"),F=Object(t["resolveComponent"])("el-form-item"),S=Object(t["resolveComponent"])("el-cascader"),P=Object(t["resolveComponent"])("el-button"),L=Object(t["resolveComponent"])("el-option"),U=Object(t["resolveComponent"])("el-select"),D=Object(t["resolveComponent"])("el-card"),T=Object(t["resolveComponent"])("el-form"),I=Object(t["resolveComponent"])("el-col"),q=Object(t["resolveDirective"])("loading");return Object(t["openBlock"])(),Object(t["createBlock"])("div",r,[Object(t["createVNode"])(N,{class:"breadcrumb-style"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(x,{separator:"/"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(B,{to:{path:"/"}},{default:Object(t["withCtx"])(()=>[c]),_:1}),Object(t["createVNode"])(B,{to:{path:"/protection/"+y.domain}},{default:Object(t["withCtx"])(()=>[o]),_:1},8,["to"]),Object(t["createVNode"])(B,{to:{path:"/flow-white-rule/"+y.domain}},{default:Object(t["withCtx"])(()=>[s]),_:1},8,["to"]),"new"==y.uuid?(Object(t["openBlock"])(),Object(t["createBlock"])(B,{key:0},{default:Object(t["withCtx"])(()=>[u]),_:1})):(Object(t["openBlock"])(),Object(t["createBlock"])(B,{key:1},{default:Object(t["withCtx"])(()=>[i]),_:1}))]),_:1})]),_:1}),Object(t["createVNode"])(N,{class:"container-style"},{default:Object(t["withCtx"])(()=>[Object(t["withDirectives"])(Object(t["createVNode"])(I,{span:24},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(T,{class:"custom-edit-form",model:y.flowRuleManageForm,rules:C.rules,ref:"flowRuleManageForm","label-width":"180px"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])("div",null,[Object(t["createVNode"])(F,{label:"规则名称",prop:"rule_name"},{default:Object(t["withCtx"])(()=>["new"==y.uuid?(Object(t["openBlock"])(),Object(t["createBlock"])(R,{key:0,modelValue:y.flowRuleManageForm.rule_name,"onUpdate:modelValue":a[1]||(a[1]=e=>y.flowRuleManageForm.rule_name=e),placeholder:"请输入字母开头，字母或数字组合，仅支持_-两种符号"},null,8,["modelValue"])):(Object(t["openBlock"])(),Object(t["createBlock"])(R,{key:1,modelValue:y.flowRuleManageForm.rule_name,"onUpdate:modelValue":a[2]||(a[2]=e=>y.flowRuleManageForm.rule_name=e),disabled:""},null,8,["modelValue"]))]),_:1}),Object(t["createVNode"])(F,{label:"规则详情"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(R,{modelValue:y.flowRuleManageForm.rule_detail,"onUpdate:modelValue":a[3]||(a[3]=e=>y.flowRuleManageForm.rule_detail=e)},null,8,["modelValue"])]),_:1}),Object(t["createVNode"])(D,{class:"box-card-rule"},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(y.ruleBigMatchs,(e,a)=>(Object(t["openBlock"])(),Object(t["createBlock"])("div",{class:"card-item",key:a},[Object(t["createVNode"])(F,{label:"匹配参数"},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(e.ruleSmallMatchs,(e,l)=>(Object(t["openBlock"])(),Object(t["createBlock"])("div",{class:"match-box",key:l},[Object(t["createVNode"])("div",n,[Object(t["createVNode"])("div",d,[Object(t["createVNode"])(S,{separator:":",modelValue:e.rule_match_key_list,"onUpdate:modelValue":a=>e.rule_match_key_list=a,options:y.optionsMatchKey,props:y.propsMatchKey,onChange:l=>C.onChangeRuleMatchs(l,e,a),clearable:""},null,8,["modelValue","onUpdate:modelValue","options","props","onChange"])]),Object(t["withDirectives"])(Object(t["createVNode"])("div",h,[Object(t["createVNode"])(R,{modelValue:e.rule_match_key,"onUpdate:modelValue":a=>e.rule_match_key=a,clearable:"",onChange:l=>C.onChangeRuleInput(l,e,a)},null,8,["modelValue","onUpdate:modelValue","onChange"])],512),[[t["vShow"],e.showInput]])]),Object(t["createVNode"])(P,{onClick:Object(t["withModifiers"])(l=>C.removeRuleMatchs(e,a),["prevent"])},{default:Object(t["withCtx"])(()=>[b]),_:2},1032,["onClick"])]))),128)),Object(t["createVNode"])(P,{onClick:e=>C.addRuleMatchs(a),plain:"",type:"primary"},{default:Object(t["withCtx"])(()=>[m]),_:2},1032,["onClick"])]),_:2},1024),Object(t["createVNode"])(F,{label:"参数处理"},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(e.argsPrepocessList,(e,l)=>(Object(t["openBlock"])(),Object(t["createBlock"])("div",{class:"match-box",key:l},[Object(t["createVNode"])("div",_,[Object(t["createVNode"])("div",p,[Object(t["createVNode"])(U,{modelValue:e.args_prepocess_value,"onUpdate:modelValue":a=>e.args_prepocess_value=a,placeholder:"Select"},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(y.optionsArgs,e=>(Object(t["openBlock"])(),Object(t["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:2},1032,["modelValue","onUpdate:modelValue"])])]),Object(t["createVNode"])(P,{onClick:Object(t["withModifiers"])(l=>C.removeArgsPrepocess(e,a),["prevent"])},{default:Object(t["withCtx"])(()=>[g]),_:2},1032,["onClick"])]))),128)),Object(t["createVNode"])(P,{onClick:e=>C.addArgsPrepocess(a),plain:"",type:"primary"},{default:Object(t["withCtx"])(()=>[O]),_:2},1032,["onClick"])]),_:2},1024),Object(t["createVNode"])(F,{label:"匹配方式"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(U,{modelValue:e.match_operator,"onUpdate:modelValue":a=>e.match_operator=a,placeholder:"请选择"},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(y.optionsOperator,e=>(Object(t["openBlock"])(),Object(t["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:2},1032,["modelValue","onUpdate:modelValue"])]),_:2},1024),Object(t["createVNode"])(F,{label:"匹配内容"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(R,{modelValue:e.match_value,"onUpdate:modelValue":a=>e.match_value=a},null,8,["modelValue","onUpdate:modelValue"])]),_:2},1024),Object(t["createVNode"])("div",v,[Object(t["createVNode"])(P,{type:"danger",plain:"",onClick:Object(t["withModifiers"])(a=>C.removeRuleBigMatchs(e),["prevent"])},{default:Object(t["withCtx"])(()=>[j]),_:2},1032,["onClick"])])]))),128)),Object(t["createVNode"])("div",f,[Object(t["createVNode"])(P,{class:"button",type:"primary",onClick:a[4]||(a[4]=a=>C.addRuleBigMatchs(e.bigIndex))},{default:Object(t["withCtx"])(()=>[w]),_:1})])]),_:1}),Object(t["createVNode"])(F,{label:"执行动作",prop:"rule_action"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(U,{modelValue:y.flowRuleManageForm.rule_action,"onUpdate:modelValue":a[5]||(a[5]=e=>y.flowRuleManageForm.rule_action=e),placeholder:"请选择",onChange:a[6]||(a[6]=e=>C.onChangeRuleAction())},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(y.ruleAction,e=>(Object(t["openBlock"])(),Object(t["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==y.flowRuleManageForm.rule_action?(Object(t["openBlock"])(),Object(t["createBlock"])(F,{key:0},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(U,{modelValue:y.action_value,"onUpdate:modelValue":a[7]||(a[7]=e=>y.action_value=e),placeholder:"请选择"},{default:Object(t["withCtx"])(()=>[(Object(t["openBlock"])(!0),Object(t["createBlock"])(t["Fragment"],null,Object(t["renderList"])(y.optionsBotCheck,e=>(Object(t["openBlock"])(),Object(t["createBlock"])(L,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),k]),_:1})):Object(t["createCommentVNode"])("",!0)])]),_:1},8,["model","rules"]),Object(t["createVNode"])(N,{type:"flex",class:"margin-border",justify:"space-between"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(I,{span:12},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])("a",{class:"el-button el-button--primary is-plain",href:"/#/flow-white-rule/"+y.domain},"返回",8,["href"])]),_:1}),Object(t["createVNode"])(I,{span:12,class:"text-align-right"},{default:Object(t["withCtx"])(()=>[Object(t["createVNode"])(P,{type:"primary",onClick:a[8]||(a[8]=e=>C.onClickflowRuleProSubmit("flowRuleManageForm")),loading:y.loading},{default:Object(t["withCtx"])(()=>[M]),_:1},8,["loading"])]),_:1})]),_:1})]),_:1},512),[[q,y.loadingPage,void 0,{fullscreen:!0,lock:!0}]])]),_:1})])}var y=l("362c"),C=l("6c02"),B={mixins:[y["c"]],data(){return{loading:!1,loadingPage:!1,uuid:"new",domain:"",flowRuleManageForm:{rule_detail:"",action_value:""},optionsMatchKey:[{value:"http_args",label:"http_args",children:[{value:"path",label:"path",leaf:!0},{value:"query_string",label:"query_string",leaf:!0},{value:"method",label:"method",leaf:!0},{value:"src_ip",label:"src_ip",leaf:!0},{value:"raw_body",label:"raw_body",leaf:!0},{value:"version",label:"version",leaf:!0},{value:"scheme",label:"scheme",leaf:!0},{value:"raw_header",label:"raw_header",leaf:!0}]},{value:"header_args",label:"header_args",children:[{value:"host",label:"host",leaf:!0},{value:"cookie",label:"cookie",leaf:!0},{value:"referer",label:"referer",leaf:!0},{value:"user_agent",label:"user_agent",leaf:!0},{value:"default",label:"自定义",leaf:!0}]},{value:"cookie_args",label:"cookie_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"uri_args",label:"uri_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"post_args",label:"post_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"json_post_args",label:"json_post_args",children:[{value:"default",label:"自定义",leaf:!0}]}],ruleBigMatchs:[{ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",argsPrepocessList:[{args_prepocess_value:""}]}],operator:"",optionsOperator:[{value:"rx",label:"正则匹配"},{value:"str_prefix",label:"前缀匹配"},{value:"str_suffix",label:"后缀匹配"},{value:"str_contain",label:"包含"},{value:"str_ncontain",label:"不包含"},{value:"str_eq",label:"等于"},{value:"str_neq",label:"不等于"},{value:"gt",label:"数字大于"},{value:"lt",label:"数字小于"},{value:"eq",label:"数字等于"},{value:"neq",label:"数字不等于"}],optionsArgs:[{value:"none",label:"不处理",key:"none"},{value:"lowerCase",label:"小写处理",key:"lowerCase"},{value:"base64Decode",label:"BASE64解码",key:"base64Decode"},{value:"length",label:"长度计算",key:"length"},{value:"uriDecode",label:"URL解码",key:"uriDecode"},{value:"uniDecode",label:"UNICODE解码",key:"uniDecode"},{value:"hexDecode",label:"十六进制解码",key:"hexDecode"},{value:"type",label:"获取数据类型",key:"type"}],ruleAction:[{value:"block",label:"阻断请求"},{value:"reject_response",label:"拒绝响应"},{value:"watch",label:"观察模式"},{value:"bot_check",label:"人机识别"}],optionsBotCheck:[{value:"standard",label:"标准"},{value:"slipper",label:"滑块"},{value:"image",label:"图片验证码"}],optionsDict:[],optionsNameList:[],custom_response:[],request_replace:[],response_replace:[],traffic_forward:[],action_value:"",propsMatchKey:{expandTrigger:"hover"}}},computed:{rules(){return{rule_name:[{required:!0,message:"请输入规则名称",trigger:["blur","change"]},{validator:y["i"],trigger:["blur","change"]}],action_value:[{required:!0,message:"请选择匹配方式",trigger:"change"}],match_value:[{required:!0,message:"请输入匹配内容",trigger:["blur","change"]}],rule_action:[{required:!0,message:"请选择执行动作",trigger:"change"}]}}},mounted(){var e=this;const a=Object(C["c"])();e.uuid=a.params.uuid,e.domain=a.params.domain,e.loadingPage=!1,"new"!=e.uuid&&e.getData()},methods:{getData(){var e=this,a="/waf/waf_get_flow_white_rule",l={domain:e.domain,rule_name:e.uuid};Object(y["a"])("post",a,l,(function(a){e.loadingPage=!1,e.flowRuleManageForm=a.data.message,e.flowRuleManageForm.rule_name=e.uuid;var l=JSON.parse(e.flowRuleManageForm.rule_matchs),t=[];for(var r in l){var c=[],o=[],s=["header_args","cookie_args","uri_args","post_args","json_post_args"];for(var u in l[r].match_args){var i=l[r].match_args[u],n=i.key,d=i.value,h="false";s.indexOf(n)>-1&&(h="true"),"shared_dict"==n?e.optionsDict.forEach(e=>{e.shared_dict_uuid==d&&c.push({rule_match_key_list:[n,e.shared_dict_uuid],rule_match_key:n+":"+e.shared_dict_name,showInput:h})}):c.push({rule_match_key_list:[n,d],rule_match_key:n+":"+d,showInput:h})}for(var b in l[r].args_prepocess)o.push({args_prepocess_value:l[r].args_prepocess[b]});t.push({ruleSmallMatchs:c,argsPrepocessList:o,match_operator:l[r].match_operator,match_value:l[r].match_value})}e.ruleBigMatchs=t,e.action_value=e.flowRuleManageForm.action_value}),(function(){e.loadingPage=!1}),"no-message")},onChangeRuleAction(){var e=this;e.action_value=""},onClickflowRuleProSubmit(e){var a=this,l=[];if(0==a.ruleBigMatchs.length)return a.$message({showClose:!0,message:"请输入详细规则",type:"error"}),!1;for(var t in a.ruleBigMatchs){var r=[],c=[];if(0==a.ruleBigMatchs[t].ruleSmallMatchs.length)return a.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;for(var o in a.ruleBigMatchs[t].ruleSmallMatchs){var s=a.ruleBigMatchs[t].ruleSmallMatchs[o];if(""==s.rule_match_key)return a.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;var u="",i=[],n="",d="";s.rule_match_key&&(i=s.rule_match_key.split(":")),i.length>0&&(n=i[0],d=s.rule_match_key.replace(new RegExp(n+":"),""),u='{"key":"'+n+'" , "value":"'+d+'"}'),"shared_dict"==n&&(u='{"key":"'+n+'" , "value":"'+s.rule_match_key_list[1]+'"}'),r.push(JSON.parse(u))}if(0==a.ruleBigMatchs[t].argsPrepocessList.length)return a.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;for(var h in a.ruleBigMatchs[t].argsPrepocessList){if(""==a.ruleBigMatchs[t].argsPrepocessList[h].args_prepocess_value)return a.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;c.push(a.ruleBigMatchs[t].argsPrepocessList[h].args_prepocess_value)}if(""==a.ruleBigMatchs[t].match_operator)return a.$message({showClose:!0,message:"请选择匹配方式",type:"error"}),!1;if(""==a.ruleBigMatchs[t].match_value)return a.$message({showClose:!0,message:"请输入匹配内容",type:"error"}),!1;l.push({match_args:r,args_prepocess:c,match_operator:a.ruleBigMatchs[t].match_operator,match_value:a.ruleBigMatchs[t].match_value})}if("bot_check"==a.flowRuleManageForm.rule_action&&""==a.action_value)return a.$message({message:"请选择人机识别方式",type:"error"}),!1;a.flowRuleManageForm.domain=a.domain,a.flowRuleManageForm.action_value=a.action_value;var b="/waf/waf_edit_flow_white_rule";"new"==a.uuid?b="/waf/waf_create_flow_white_rule":a.flowRuleManageForm.rule_name=a.uuid,a.flowRuleManageForm.rule_matchs=JSON.stringify(l),this.$refs[e].validate(e=>{e&&(a.loading=!0,Object(y["a"])("post",b,a.flowRuleManageForm,(function(e){a.loading=!1,window.location.href="/#/flow-white-rule/"+a.domain}),(function(){a.loading=!1})))})},removeArgsPrepocess(e,a){var l=this.ruleBigMatchs[a].argsPrepocessList.indexOf(e);-1!=l&&this.ruleBigMatchs[a].argsPrepocessList.splice(l,1)},addArgsPrepocess(e){this.ruleBigMatchs[e].argsPrepocessList.push({args_prepocess_value:""})},addRuleMatchs(e){this.ruleBigMatchs[e].ruleSmallMatchs.push({rule_match_key:"",rule_match_key_list:[],showInput:!1})},removeRuleMatchs(e,a){var l=this.ruleBigMatchs[a].ruleSmallMatchs.indexOf(e);-1!=l&&this.ruleBigMatchs[a].ruleSmallMatchs.splice(l,1)},removeRuleBigMatchs(e){var a=this.ruleBigMatchs.indexOf(e);-1!=a&&this.ruleBigMatchs.splice(a,1)},addRuleBigMatchs(e){this.ruleBigMatchs.push({ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",argsPrepocessList:[{args_prepocess_value:""}]})},onChangeRuleMatchs(e,a,l){var t=this.ruleBigMatchs[l].ruleSmallMatchs.indexOf(a);"default"==e[1]?(this.ruleBigMatchs[l].ruleSmallMatchs[t].showInput=!0,this.ruleBigMatchs[l].ruleSmallMatchs[t].rule_match_key=e[0]+":"):this.ruleBigMatchs[l].ruleSmallMatchs[t].rule_match_key=e[0]+":"+e[1]},onChangeRuleInput(e,a,l){var t=this.ruleBigMatchs[l].ruleSmallMatchs.indexOf(a);""==e?(this.ruleBigMatchs[l].ruleSmallMatchs[t].showInput=!1,this.ruleBigMatchs[l].ruleSmallMatchs[t].rule_match_key="",this.ruleBigMatchs[l].ruleSmallMatchs[t].rule_match_key_list=[]):this.ruleBigMatchs[l].ruleSmallMatchs[t].rule_match_key=e}}},x=(l("b594"),l("d959")),N=l.n(x);const R=N()(B,[["render",V]]);a["default"]=R},aeba:function(e,a,l){},b594:function(e,a,l){"use strict";l("aeba")}}]);
//# sourceMappingURL=chunk-2f29cf4f.675ea5d9.js.map