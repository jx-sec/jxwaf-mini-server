(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-3d044cee"],{"0788":function(e,a,t){},"0890":function(e,a,t){"use strict";t("0788")},"897a":function(e,a,t){"use strict";t.r(a);var l=t("7a23");const r={class:"custom-edit-wrap"},c=Object(l["createTextVNode"])("网站防护"),o=Object(l["createTextVNode"])("防护配置"),s=Object(l["createTextVNode"])("流量防护规则"),u=Object(l["createTextVNode"])("新增"),n=Object(l["createTextVNode"])("编辑"),i={class:"match-box-content"},d={class:"match_key_cascader"},h={class:"match_key_input"},m=Object(l["createTextVNode"])("删除"),b=Object(l["createTextVNode"])("新增"),_={class:"match-box-content"},p={class:"match_key_cascader"},g=Object(l["createTextVNode"])("删除"),O=Object(l["createTextVNode"])("新增"),j={class:"card-item-bottom"},v=Object(l["createTextVNode"])("删除"),f={class:"card-footer"},k=Object(l["createTextVNode"])("新增"),w={class:"match-box-content"},M={class:"match_key_cascader"},V={class:"match_key_input"},y=Object(l["createTextVNode"])("删除"),C=Object(l["createTextVNode"])("新增"),x=Object(l["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),B=Object(l["createTextVNode"])("保存 ");function N(e,a,t,N,R,S){const F=Object(l["resolveComponent"])("el-breadcrumb-item"),I=Object(l["resolveComponent"])("el-breadcrumb"),P=Object(l["resolveComponent"])("el-row"),U=Object(l["resolveComponent"])("el-input"),L=Object(l["resolveComponent"])("el-form-item"),D=Object(l["resolveComponent"])("el-switch"),T=Object(l["resolveComponent"])("el-cascader"),q=Object(l["resolveComponent"])("el-button"),E=Object(l["resolveComponent"])("el-option"),A=Object(l["resolveComponent"])("el-select"),$=Object(l["resolveComponent"])("el-card"),J=Object(l["resolveComponent"])("el-form"),K=Object(l["resolveComponent"])("el-col"),z=Object(l["resolveDirective"])("loading");return Object(l["openBlock"])(),Object(l["createBlock"])("div",r,[Object(l["createVNode"])(P,{class:"breadcrumb-style"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(I,{separator:"/"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(F,{to:{path:"/"}},{default:Object(l["withCtx"])(()=>[c]),_:1}),Object(l["createVNode"])(F,{to:{path:"/protection/"+R.domain}},{default:Object(l["withCtx"])(()=>[o]),_:1},8,["to"]),Object(l["createVNode"])(F,{to:{path:"/flow-rule-protection/"+R.domain}},{default:Object(l["withCtx"])(()=>[s]),_:1},8,["to"]),"new"==R.uuid?(Object(l["openBlock"])(),Object(l["createBlock"])(F,{key:0},{default:Object(l["withCtx"])(()=>[u]),_:1})):(Object(l["openBlock"])(),Object(l["createBlock"])(F,{key:1},{default:Object(l["withCtx"])(()=>[n]),_:1}))]),_:1})]),_:1}),Object(l["createVNode"])(P,{class:"container-style"},{default:Object(l["withCtx"])(()=>[Object(l["withDirectives"])(Object(l["createVNode"])(K,{span:24},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(J,{class:"custom-edit-form",model:R.flowRuleManageForm,rules:S.rules,ref:"flowRuleManageForm","label-width":"180px"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])("div",null,[Object(l["createVNode"])(L,{label:"规则名称",prop:"rule_name"},{default:Object(l["withCtx"])(()=>["new"==R.uuid?(Object(l["openBlock"])(),Object(l["createBlock"])(U,{key:0,modelValue:R.flowRuleManageForm.rule_name,"onUpdate:modelValue":a[1]||(a[1]=e=>R.flowRuleManageForm.rule_name=e),placeholder:"请输入字母开头，字母或数字组合，仅支持_-两种符号"},null,8,["modelValue"])):(Object(l["openBlock"])(),Object(l["createBlock"])(U,{key:1,modelValue:R.flowRuleManageForm.rule_name,"onUpdate:modelValue":a[2]||(a[2]=e=>R.flowRuleManageForm.rule_name=e),disabled:""},null,8,["modelValue"]))]),_:1}),Object(l["createVNode"])(L,{label:"规则详情"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(U,{modelValue:R.flowRuleManageForm.rule_detail,"onUpdate:modelValue":a[3]||(a[3]=e=>R.flowRuleManageForm.rule_detail=e)},null,8,["modelValue"])]),_:1}),Object(l["createVNode"])(L,{label:"规则匹配"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(D,{modelValue:R.flowRuleManageForm.filter,"onUpdate:modelValue":a[4]||(a[4]=e=>R.flowRuleManageForm.filter=e),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),_:1}),Object(l["withDirectives"])(Object(l["createVNode"])($,{class:"box-card-rule"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(R.ruleBigMatchs,(e,a)=>(Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"card-item",key:a},[Object(l["createVNode"])(L,{label:"匹配参数"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.ruleSmallMatchs,(e,t)=>(Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"match-box",key:t},[Object(l["createVNode"])("div",i,[Object(l["createVNode"])("div",d,[Object(l["createVNode"])(T,{separator:":",modelValue:e.rule_match_key_list,"onUpdate:modelValue":a=>e.rule_match_key_list=a,options:R.optionsMatchKey,props:R.propsMatchKey,onChange:t=>S.onChangeRuleMatchs(t,e,a),clearable:""},null,8,["modelValue","onUpdate:modelValue","options","props","onChange"])]),Object(l["withDirectives"])(Object(l["createVNode"])("div",h,[Object(l["createVNode"])(U,{modelValue:e.rule_match_key,"onUpdate:modelValue":a=>e.rule_match_key=a,clearable:"",onChange:t=>S.onChangeRuleInput(t,e,a)},null,8,["modelValue","onUpdate:modelValue","onChange"])],512),[[l["vShow"],e.showInput]])]),Object(l["createVNode"])(q,{onClick:Object(l["withModifiers"])(t=>S.removeRuleMatchs(e,a),["prevent"])},{default:Object(l["withCtx"])(()=>[m]),_:2},1032,["onClick"])]))),128)),Object(l["createVNode"])(q,{onClick:e=>S.addRuleMatchs(a),plain:"",type:"primary"},{default:Object(l["withCtx"])(()=>[b]),_:2},1032,["onClick"])]),_:2},1024),Object(l["createVNode"])(L,{label:"参数处理"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.argsPrepocessList,(e,t)=>(Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"match-box",key:t},[Object(l["createVNode"])("div",_,[Object(l["createVNode"])("div",p,[Object(l["createVNode"])(A,{modelValue:e.args_prepocess_value,"onUpdate:modelValue":a=>e.args_prepocess_value=a,placeholder:"Select"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(R.optionsArgs,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(E,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:2},1032,["modelValue","onUpdate:modelValue"])])]),Object(l["createVNode"])(q,{onClick:Object(l["withModifiers"])(t=>S.removeArgsPrepocess(e,a),["prevent"])},{default:Object(l["withCtx"])(()=>[g]),_:2},1032,["onClick"])]))),128)),Object(l["createVNode"])(q,{onClick:e=>S.addArgsPrepocess(a),plain:"",type:"primary"},{default:Object(l["withCtx"])(()=>[O]),_:2},1032,["onClick"])]),_:2},1024),Object(l["createVNode"])(L,{label:"匹配方式"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(A,{modelValue:e.match_operator,"onUpdate:modelValue":a=>e.match_operator=a,placeholder:"请选择"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(R.optionsOperator,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(E,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:2},1032,["modelValue","onUpdate:modelValue"])]),_:2},1024),Object(l["createVNode"])(L,{label:"匹配内容"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(U,{modelValue:e.match_value,"onUpdate:modelValue":a=>e.match_value=a},null,8,["modelValue","onUpdate:modelValue"])]),_:2},1024),Object(l["createVNode"])("div",j,[Object(l["createVNode"])(q,{type:"danger",plain:"",onClick:Object(l["withModifiers"])(a=>S.removeRuleBigMatchs(e),["prevent"])},{default:Object(l["withCtx"])(()=>[v]),_:2},1032,["onClick"])])]))),128)),Object(l["createVNode"])("div",f,[Object(l["createVNode"])(q,{class:"button",type:"primary",onClick:a[5]||(a[5]=a=>S.addRuleBigMatchs(e.bigIndex))},{default:Object(l["withCtx"])(()=>[k]),_:1})])]),_:1},512),[[l["vShow"],"true"==R.flowRuleManageForm.filter]]),Object(l["createVNode"])(L,{label:"统计对象",class:"is-required"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(R.ruleSmallMatchs,(a,t)=>(Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"match-box",key:t},[Object(l["createVNode"])("div",w,[Object(l["createVNode"])("div",M,[Object(l["createVNode"])(T,{separator:":",modelValue:a.rule_match_key_list,"onUpdate:modelValue":e=>a.rule_match_key_list=e,options:R.optionsMatchKey,props:R.propsMatchKey,onChange:t=>S.onChangeEntityMatchs(t,a,e.bigIndex),clearable:""},null,8,["modelValue","onUpdate:modelValue","options","props","onChange"])]),Object(l["withDirectives"])(Object(l["createVNode"])("div",V,[Object(l["createVNode"])(U,{modelValue:a.rule_match_key,"onUpdate:modelValue":e=>a.rule_match_key=e,clearable:"",onChange:t=>S.onChangeEntityInput(t,a,e.bigIndex)},null,8,["modelValue","onUpdate:modelValue","onChange"])],512),[[l["vShow"],a.showInput]])]),Object(l["createVNode"])(q,{onClick:Object(l["withModifiers"])(t=>S.removeEntityMatchs(a,e.bigIndex),["prevent"])},{default:Object(l["withCtx"])(()=>[y]),_:2},1032,["onClick"])]))),128)),Object(l["createVNode"])(q,{onClick:a[6]||(a[6]=a=>S.addEntityMatchs(e.bigIndex)),plain:"",type:"primary",class:"button-new"},{default:Object(l["withCtx"])(()=>[C]),_:1})]),_:1}),Object(l["createVNode"])(L,{label:"经过时间(秒)",prop:"stat_time"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(U,{modelValue:R.flowRuleManageForm.stat_time,"onUpdate:modelValue":a[7]||(a[7]=e=>R.flowRuleManageForm.stat_time=e),placeholder:"请输入大于0的数字"},null,8,["modelValue"])]),_:1}),Object(l["createVNode"])(L,{label:"请求次数超过",prop:"exceed_count"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(U,{modelValue:R.flowRuleManageForm.exceed_count,"onUpdate:modelValue":a[8]||(a[8]=e=>R.flowRuleManageForm.exceed_count=e),placeholder:"请输入大于0的数字"},null,8,["modelValue"])]),_:1}),Object(l["createVNode"])(L,{label:"IP处罚方式",prop:"rule_action"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(A,{modelValue:R.flowRuleManageForm.rule_action,"onUpdate:modelValue":a[9]||(a[9]=e=>R.flowRuleManageForm.rule_action=e),placeholder:"请选择",onChange:a[10]||(a[10]=e=>S.onChangeRuleAction())},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(R.ruleAction,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(E,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==R.flowRuleManageForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(L,{key:0},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(A,{modelValue:R.action_value,"onUpdate:modelValue":a[11]||(a[11]=e=>R.action_value=e),placeholder:"请选择"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(R.optionsBotCheck,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(E,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),x]),_:1})):Object(l["createCommentVNode"])("",!0),Object(l["createVNode"])(L,{label:"IP处罚时间",prop:"block_time"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(U,{modelValue:R.flowRuleManageForm.block_time,"onUpdate:modelValue":a[12]||(a[12]=e=>R.flowRuleManageForm.block_time=e),placeholder:"请输入大于0的数字"},null,8,["modelValue"])]),_:1})])]),_:1},8,["model","rules"]),Object(l["createVNode"])(P,{type:"flex",class:"margin-border",justify:"space-between"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(K,{span:12},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])("a",{class:"el-button el-button--primary is-plain",href:"/#/flow-rule-protection/"+R.domain},"返回",8,["href"])]),_:1}),Object(l["createVNode"])(K,{span:12,class:"text-align-right"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(q,{type:"primary",onClick:a[13]||(a[13]=e=>S.onClickFlowRuleProSubmit("flowRuleManageForm")),loading:R.loading},{default:Object(l["withCtx"])(()=>[B]),_:1},8,["loading"])]),_:1})]),_:1})]),_:1},512),[[z,R.loadingPage,void 0,{fullscreen:!0,lock:!0}]])]),_:1})])}var R=t("362c"),S=t("6c02"),F={mixins:[R["c"]],data(){return{loading:!1,loadingPage:!1,uuid:"new",domain:"",flowRuleManageForm:{rule_detail:"",action_value:""},type:"edit",optionsMatchKey:[{value:"http_args",label:"http_args",children:[{value:"path",label:"path",leaf:!0},{value:"query_string",label:"query_string",leaf:!0},{value:"method",label:"method",leaf:!0},{value:"src_ip",label:"src_ip",leaf:!0},{value:"raw_body",label:"raw_body",leaf:!0},{value:"version",label:"version",leaf:!0},{value:"scheme",label:"scheme",leaf:!0},{value:"raw_header",label:"raw_header",leaf:!0}]},{value:"header_args",label:"header_args",children:[{value:"host",label:"host",leaf:!0},{value:"cookie",label:"cookie",leaf:!0},{value:"referer",label:"referer",leaf:!0},{value:"user_agent",label:"user_agent",leaf:!0},{value:"default",label:"自定义",leaf:!0}]},{value:"cookie_args",label:"cookie_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"uri_args",label:"uri_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"post_args",label:"post_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"json_post_args",label:"json_post_args",children:[{value:"default",label:"自定义",leaf:!0}]}],ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],ruleBigMatchs:[{ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",argsPrepocessList:[{args_prepocess_value:""}]}],optionsOperator:[{value:"rx",label:"正则匹配"},{value:"str_prefix",label:"前缀匹配"},{value:"str_suffix",label:"后缀匹配"},{value:"str_contain",label:"包含"},{value:"str_ncontain",label:"不包含"},{value:"str_eq",label:"等于"},{value:"str_neq",label:"不等于"},{value:"gt",label:"数字大于"},{value:"lt",label:"数字小于"},{value:"eq",label:"数字等于"},{value:"neq",label:"数字不等于"}],optionsArgs:[{value:"none",label:"不处理",key:"none"},{value:"lowerCase",label:"小写处理",key:"lowerCase"},{value:"base64Decode",label:"BASE64解码",key:"base64Decode"},{value:"length",label:"长度计算",key:"length"},{value:"uriDecode",label:"URL解码",key:"uriDecode"},{value:"uniDecode",label:"UNICODE解码",key:"uniDecode"},{value:"hexDecode",label:"十六进制解码",key:"hexDecode"},{value:"type",label:"获取数据类型",key:"type"}],ruleAction:[{value:"block",label:"阻断请求"},{value:"reject_response",label:"拒绝响应"},{value:"watch",label:"观察模式"},{value:"bot_check",label:"人机识别"}],optionsBotCheck:[{value:"standard",label:"标准"},{value:"slipper",label:"滑块"},{value:"image",label:"图片验证码"}],action_value:"",propsMatchKey:{expandTrigger:"hover"}}},computed:{rules(){return{rule_name:[{required:!0,message:"请输入规则名称",trigger:["blur","change"]},{validator:R["i"],trigger:["blur","change"]}],action_value:[{required:!0,message:"请选择",trigger:"change"}],match_value:[{required:!0,message:"请输入匹配内容",trigger:["blur","change"]}],rule_action:[{required:!0,message:"请选择执行动作",trigger:"change"}],stat_time:[{required:!0,message:"请输入大于0的数字",trigger:["blur","change"]},{validator:R["h"],trigger:["blur","change"]}],exceed_count:[{required:!0,message:"请输入大于0的数字",trigger:["blur","change"]},{validator:R["h"],trigger:["blur","change"]}],block_time:[{required:!0,message:"请输入大于0的数字",trigger:["blur","change"]},{validator:R["h"],trigger:["blur","change"]}]}}},mounted(){var e=this;const a=Object(S["c"])();e.uuid=a.params.uuid,e.domain=a.params.domain,e.loadingPage=!1,"new"!=e.uuid&&e.getData()},methods:{getData(){var e=this,a="/waf/waf_get_flow_rule_protection",t={domain:e.domain,rule_name:e.uuid};Object(R["a"])("post",a,t,(function(a){if(e.loadingPage=!1,e.flowRuleManageForm=a.data.message,e.flowRuleManageForm.rule_name=e.uuid,"true"==e.flowRuleManageForm.filter){var t=JSON.parse(e.flowRuleManageForm.rule_matchs),l=[];for(var r in t){var c=[],o=[],s=["header_args","cookie_args","uri_args","post_args","json_post_args"];for(var u in t[r].match_args){var n=t[r].match_args[u],i=n.key,d=n.value,h="false";s.indexOf(i)>-1&&(h="true"),"shared_dict"==i?e.optionsDict.forEach(e=>{e.shared_dict_uuid==d&&c.push({rule_match_key_list:[i,e.shared_dict_uuid],rule_match_key:i+":"+e.shared_dict_name,showInput:h})}):c.push({rule_match_key_list:[i,d],rule_match_key:i+":"+d,showInput:h})}for(var m in t[r].args_prepocess)o.push({args_prepocess_value:t[r].args_prepocess[m]});l.push({ruleSmallMatchs:c,argsPrepocessList:o,match_operator:t[r].match_operator,match_value:t[r].match_value})}e.ruleBigMatchs=l}else e.ruleBigMatchs=[{ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",argsPrepocessList:[{args_prepocess_value:""}]}];var b=JSON.parse(e.flowRuleManageForm.entity),_=[],p=["header_args","cookie_args","uri_args","post_args","json_post_args","string"];for(var g in b){var O=b[g],j=O.key,v=O.value,f="false";p.indexOf(j)>-1&&(f="true"),_.push({rule_match_key_list:[j,v],rule_match_key:j+":"+v,showInput:f})}e.ruleSmallMatchs=_,e.action_value=e.flowRuleManageForm.action_value}),(function(){e.loadingPage=!1}),"no-message")},onChangeRuleAction(){var e=this;e.action_value=""},onClickFlowRuleProSubmit(e){var a=this,t=[];if("true"==a.flowRuleManageForm.filter){if(0==a.ruleBigMatchs.length)return a.$message({showClose:!0,message:"请输入详细规则",type:"error"}),!1;for(var l in a.ruleBigMatchs){var r=[],c=[];if(0==a.ruleBigMatchs[l].ruleSmallMatchs.length)return a.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;for(var o in a.ruleBigMatchs[l].ruleSmallMatchs){var s=a.ruleBigMatchs[l].ruleSmallMatchs[o];if(""==s.rule_match_key)return a.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;var u="",n=[],i="",d="";s.rule_match_key&&(n=s.rule_match_key.split(":")),n.length>0&&(i=n[0],d=s.rule_match_key.replace(new RegExp(i+":"),""),u='{"key":"'+i+'" , "value":"'+d+'"}'),"shared_dict"==i&&(u='{"key":"'+i+'" , "value":"'+s.rule_match_key_list[1]+'"}'),r.push(JSON.parse(u))}if(0==a.ruleBigMatchs[l].argsPrepocessList.length)return a.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;for(var h in a.ruleBigMatchs[l].argsPrepocessList){if(""==a.ruleBigMatchs[l].argsPrepocessList[h].args_prepocess_value)return a.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;c.push(a.ruleBigMatchs[l].argsPrepocessList[h].args_prepocess_value)}if(""==a.ruleBigMatchs[l].match_operator)return a.$message({showClose:!0,message:"请选择匹配方式",type:"error"}),!1;if(""==a.ruleBigMatchs[l].match_value)return a.$message({showClose:!0,message:"请输入匹配内容",type:"error"}),!1;t.push({match_args:r,args_prepocess:c,match_operator:a.ruleBigMatchs[l].match_operator,match_value:a.ruleBigMatchs[l].match_value})}}if(0==a.ruleSmallMatchs.length)return a.$message({message:"请选择匹配参数",type:"error"}),!1;if(""==a.ruleSmallMatchs[0].rule_match_key)return a.$message({message:"请选择匹配参数",type:"error"}),!1;var m=[];for(var b in a.ruleSmallMatchs){var _=a.ruleSmallMatchs[b],p="",g=[],O="",j="";_.rule_match_key&&(g=_.rule_match_key.split(":")),g.length>0&&(O=g[0],j=_.rule_match_key.replace(new RegExp(O+":"),""),p='{"key":"'+O+'" , "value":"'+j+'"}'),m.push(JSON.parse(p))}if("bot_check"==a.flowRuleManageForm.rule_action&&""==a.action_value)return a.$message({message:"请选择人机识别方式",type:"error"}),!1;a.flowRuleManageForm.domain=a.domain,a.flowRuleManageForm.action_value=a.action_value;var v="/waf/waf_edit_flow_rule_protection";"new"==a.uuid?v="/waf/waf_create_flow_rule_protection":a.flowRuleManageForm.rule_name=a.uuid,a.flowRuleManageForm.rule_matchs=JSON.stringify(t),a.flowRuleManageForm.entity=JSON.stringify(m),this.$refs[e].validate(e=>{e&&(a.loading=!0,Object(R["a"])("post",v,a.flowRuleManageForm,(function(e){a.loading=!1,window.location.href="/#/flow-rule-protection/"+a.domain}),(function(){a.loading=!1})))})},removeArgsPrepocess(e,a){var t=this.ruleBigMatchs[a].argsPrepocessList.indexOf(e);-1!=t&&this.ruleBigMatchs[a].argsPrepocessList.splice(t,1)},addArgsPrepocess(e){this.ruleBigMatchs[e].argsPrepocessList.push({args_prepocess_value:""})},addRuleMatchs(e){this.ruleBigMatchs[e].ruleSmallMatchs.push({rule_match_key:"",rule_match_key_list:[],showInput:!1})},removeRuleMatchs(e,a){var t=this.ruleBigMatchs[a].ruleSmallMatchs.indexOf(e);-1!=t&&this.ruleBigMatchs[a].ruleSmallMatchs.splice(t,1)},removeRuleBigMatchs(e){var a=this.ruleBigMatchs.indexOf(e);-1!=a&&this.ruleBigMatchs.splice(a,1)},addRuleBigMatchs(e){this.ruleBigMatchs.push({ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",argsPrepocessList:[{args_prepocess_value:""}]})},onChangeRuleMatchs(e,a,t){var l=this.ruleBigMatchs[t].ruleSmallMatchs.indexOf(a);"default"==e[1]?(this.ruleBigMatchs[t].ruleSmallMatchs[l].showInput=!0,this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key=e[0]+":"):this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key=e[0]+":"+e[1]},onChangeRuleInput(e,a,t){var l=this.ruleBigMatchs[t].ruleSmallMatchs.indexOf(a);""==e?(this.ruleBigMatchs[t].ruleSmallMatchs[l].showInput=!1,this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key="",this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key_list=[]):this.ruleBigMatchs[t].ruleSmallMatchs[l].rule_match_key=e},removeEntityMatchs(e){var a=this.ruleSmallMatchs.indexOf(e);-1!==a&&this.ruleSmallMatchs.splice(a,1)},addEntityMatchs(){this.ruleSmallMatchs.push({rule_match_key:"",showInput:!1})},onChangeEntityMatchs(e,a,t){var l=this.ruleSmallMatchs.indexOf(a);"default"==e[1]?(this.ruleSmallMatchs[l].showInput=!0,this.ruleSmallMatchs[l].rule_match_key=e[0]+":"):this.ruleSmallMatchs[l].rule_match_key=e[0]+":"+e[1]},onChangeEntityInput(e,a,t){var l=this.ruleSmallMatchs.indexOf(a);""==e?(this.ruleSmallMatchs[l].showInput=!1,this.ruleSmallMatchs[l].rule_match_key="",this.ruleSmallMatchs[l].rule_match_key_list=[]):this.ruleSmallMatchs[l].rule_match_key=e}}},I=(t("0890"),t("d959")),P=t.n(I);const U=P()(F,[["render",N]]);a["default"]=U}}]);
//# sourceMappingURL=chunk-3d044cee.3612a046.js.map