(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-493ac3d3"],{"0cb2":function(e,t,a){var r=a("7b0b"),l=Math.floor,c="".replace,n=/\$([$&'`]|\d{1,2}|<[^>]*>)/g,o=/\$([$&'`]|\d{1,2})/g;e.exports=function(e,t,a,u,i,s){var d=a+e.length,b=u.length,h=o;return void 0!==i&&(i=r(i),h=n),c.call(s,h,(function(r,c){var n;switch(c.charAt(0)){case"$":return"$";case"&":return e;case"`":return t.slice(0,a);case"'":return t.slice(d);case"<":n=i[c.slice(1,-1)];break;default:var o=+c;if(0===o)return r;if(o>b){var s=l(o/10);return 0===s?r:s<=b?void 0===u[s-1]?c.charAt(1):u[s-1]+c.charAt(1):r}n=u[o-1]}return void 0===n?"":n}))}},"1dde":function(e,t,a){var r=a("d039"),l=a("b622"),c=a("2d00"),n=l("species");e.exports=function(e){return c>=51||!r((function(){var t=[],a=t.constructor={};return a[n]=function(){return{foo:1}},1!==t[e](Boolean).foo}))}},"25f0":function(e,t,a){"use strict";var r=a("6eeb"),l=a("825a"),c=a("577e"),n=a("d039"),o=a("ad6d"),u="toString",i=RegExp.prototype,s=i[u],d=n((function(){return"/a/b"!=s.call({source:"a",flags:"b"})})),b=s.name!=u;(d||b)&&r(RegExp.prototype,u,(function(){var e=l(this),t=c(e.source),a=e.flags,r=c(void 0===a&&e instanceof RegExp&&!("flags"in i)?o.call(e):a);return"/"+t+"/"+r}),{unsafe:!0})},3520:function(e,t,a){"use strict";a.r(t);var r=a("7a23"),l={class:"custom-edit-wrap"},c=Object(r["createVNode"])("h3",null,"Web防护规则",-1),n=Object(r["createVNode"])("div",{class:"margin-4x"},null,-1),o={class:"match-box-content"},u={class:"match_key_cascader"},i={class:"match_key_input"},s=Object(r["createTextVNode"])("删除"),d=Object(r["createTextVNode"])("新增"),b={class:"match-box-content"},h={class:"match_key_cascader"},p=Object(r["createTextVNode"])("删除"),f=Object(r["createTextVNode"])("新增"),_={class:"card-item-bottom"},g=Object(r["createTextVNode"])("删除"),m={class:"card-footer"},v=Object(r["createTextVNode"])("新增"),O=Object(r["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),j=Object(r["createVNode"])("div",{class:"margin-4x"},null,-1),w=Object(r["createTextVNode"])("保存 ");function y(e,t){var a=Object(r["resolveComponent"])("el-col"),y=Object(r["resolveComponent"])("el-row"),k=Object(r["resolveComponent"])("el-input"),M=Object(r["resolveComponent"])("el-form-item"),V=Object(r["resolveComponent"])("el-cascader"),x=Object(r["resolveComponent"])("el-button"),B=Object(r["resolveComponent"])("el-option"),C=Object(r["resolveComponent"])("el-select"),N=Object(r["resolveComponent"])("el-card"),R=Object(r["resolveComponent"])("el-switch"),F=Object(r["resolveComponent"])("el-form"),S=Object(r["resolveDirective"])("loading");return Object(r["openBlock"])(),Object(r["createBlock"])("div",l,[Object(r["createVNode"])(y,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(a,{span:24},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(y,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(a,{span:12},{default:Object(r["withCtx"])((function(){return[c]})),_:1}),Object(r["createVNode"])(a,{span:12,class:"text-align-right"},{default:Object(r["withCtx"])((function(){return["group_rule"==e.ruleType?(Object(r["openBlock"])(),Object(r["createBlock"])("a",{key:0,class:"el-button el-button--primary is-plain",href:"/#/group-rule/"+e.uuid+"/web-rule-manage"},"返回",8,["href"])):(Object(r["openBlock"])(),Object(r["createBlock"])("a",{key:1,class:"el-button el-button--primary is-plain",href:"/#/web-rule-manage/"+e.ruleType},"返回",8,["href"]))]})),_:1})]})),_:1})]})),_:1})]})),_:1}),n,Object(r["withDirectives"])(Object(r["createVNode"])(y,null,{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(a,{span:24},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(F,{class:"custom-edit-form",model:e.webRuleManageForm,rules:e.rules,ref:"webRuleManageForm","label-width":"180px"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(N,{class:"box-card"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])("div",null,[Object(r["createVNode"])(M,{label:"规则名称",prop:"rule_name"},{default:Object(r["withCtx"])((function(){return["new"==e.type?(Object(r["openBlock"])(),Object(r["createBlock"])(k,{key:0,modelValue:e.webRuleManageForm.rule_name,"onUpdate:modelValue":t[1]||(t[1]=function(t){return e.webRuleManageForm.rule_name=t}),placeholder:"请输入字母开头，字母或数字组合，仅支持_-两种符号"},null,8,["modelValue"])):(Object(r["openBlock"])(),Object(r["createBlock"])(k,{key:1,modelValue:e.webRuleManageForm.rule_name,"onUpdate:modelValue":t[2]||(t[2]=function(t){return e.webRuleManageForm.rule_name=t}),disabled:""},null,8,["modelValue"]))]})),_:1}),Object(r["createVNode"])(M,{label:"规则详情"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(k,{modelValue:e.webRuleManageForm.rule_detail,"onUpdate:modelValue":t[3]||(t[3]=function(t){return e.webRuleManageForm.rule_detail=t})},null,8,["modelValue"])]})),_:1}),Object(r["createVNode"])(N,{class:"box-card-rule",shadow:"never"},{default:Object(r["withCtx"])((function(){return[(Object(r["openBlock"])(!0),Object(r["createBlock"])(r["Fragment"],null,Object(r["renderList"])(e.ruleBigMatchs,(function(t,a){return Object(r["openBlock"])(),Object(r["createBlock"])("div",{class:"card-item",key:a},[Object(r["createVNode"])(M,{label:"匹配参数"},{default:Object(r["withCtx"])((function(){return[(Object(r["openBlock"])(!0),Object(r["createBlock"])(r["Fragment"],null,Object(r["renderList"])(t.ruleSmallMatchs,(function(t,l){return Object(r["openBlock"])(),Object(r["createBlock"])("div",{class:"match-box",key:l},[Object(r["createVNode"])("div",o,[Object(r["createVNode"])("div",u,[Object(r["createVNode"])(V,{separator:":",modelValue:t.rule_match_key_list,"onUpdate:modelValue":function(e){return t.rule_match_key_list=e},options:e.optionsMatchKey,props:e.propsMatchKey,onChange:function(r){return e.onChangeRuleMatchs(r,t,a)},clearable:""},null,8,["modelValue","onUpdate:modelValue","options","props","onChange"])]),Object(r["withDirectives"])(Object(r["createVNode"])("div",i,[Object(r["createVNode"])(k,{modelValue:t.rule_match_key,"onUpdate:modelValue":function(e){return t.rule_match_key=e},clearable:"",onChange:function(r){return e.onChangeRuleInput(r,t,a)}},null,8,["modelValue","onUpdate:modelValue","onChange"])],512),[[r["vShow"],t.showInput]])]),Object(r["createVNode"])(x,{onClick:Object(r["withModifiers"])((function(r){return e.removeRuleMatchs(t,a)}),["prevent"])},{default:Object(r["withCtx"])((function(){return[s]})),_:2},1032,["onClick"])])})),128)),Object(r["createVNode"])(x,{onClick:function(t){return e.addRuleMatchs(a)},plain:"",type:"primary"},{default:Object(r["withCtx"])((function(){return[d]})),_:2},1032,["onClick"])]})),_:2},1024),Object(r["createVNode"])(M,{label:"参数处理"},{default:Object(r["withCtx"])((function(){return[(Object(r["openBlock"])(!0),Object(r["createBlock"])(r["Fragment"],null,Object(r["renderList"])(t.argsPrepocessList,(function(t,l){return Object(r["openBlock"])(),Object(r["createBlock"])("div",{class:"match-box",key:l},[Object(r["createVNode"])("div",b,[Object(r["createVNode"])("div",h,[Object(r["createVNode"])(C,{modelValue:t.args_prepocess_value,"onUpdate:modelValue":function(e){return t.args_prepocess_value=e},placeholder:"Select"},{default:Object(r["withCtx"])((function(){return[(Object(r["openBlock"])(!0),Object(r["createBlock"])(r["Fragment"],null,Object(r["renderList"])(e.optionsArgs,(function(e){return Object(r["openBlock"])(),Object(r["createBlock"])(B,{key:e.value,label:e.label,value:e.value},null,8,["label","value"])})),128))]})),_:2},1032,["modelValue","onUpdate:modelValue"])])]),Object(r["createVNode"])(x,{onClick:Object(r["withModifiers"])((function(r){return e.removeArgsPrepocess(t,a)}),["prevent"])},{default:Object(r["withCtx"])((function(){return[p]})),_:2},1032,["onClick"])])})),128)),Object(r["createVNode"])(x,{onClick:function(t){return e.addArgsPrepocess(a)},plain:"",type:"primary"},{default:Object(r["withCtx"])((function(){return[f]})),_:2},1032,["onClick"])]})),_:2},1024),Object(r["createVNode"])(M,{label:"匹配方式"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(C,{modelValue:t.match_operator,"onUpdate:modelValue":function(e){return t.match_operator=e},placeholder:"请选择"},{default:Object(r["withCtx"])((function(){return[(Object(r["openBlock"])(!0),Object(r["createBlock"])(r["Fragment"],null,Object(r["renderList"])(e.optionsOperator,(function(e){return Object(r["openBlock"])(),Object(r["createBlock"])(B,{key:e.value,label:e.label,value:e.value},null,8,["label","value"])})),128))]})),_:2},1032,["modelValue","onUpdate:modelValue"])]})),_:2},1024),Object(r["createVNode"])(M,{label:"匹配内容"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(k,{modelValue:t.match_value,"onUpdate:modelValue":function(e){return t.match_value=e}},null,8,["modelValue","onUpdate:modelValue"])]})),_:2},1024),Object(r["createVNode"])("div",_,[Object(r["createVNode"])(x,{type:"danger",plain:"",onClick:Object(r["withModifiers"])((function(a){return e.removeRuleBigMatchs(t)}),["prevent"])},{default:Object(r["withCtx"])((function(){return[g]})),_:2},1032,["onClick"])])])})),128)),Object(r["createVNode"])("div",m,[Object(r["createVNode"])(x,{class:"button",type:"primary",onClick:t[4]||(t[4]=function(t){return e.addRuleBigMatchs(e.bigIndex)})},{default:Object(r["withCtx"])((function(){return[v]})),_:1})])]})),_:1}),Object(r["createVNode"])(M,{label:"执行动作",prop:"rule_action"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(C,{modelValue:e.webRuleManageForm.rule_action,"onUpdate:modelValue":t[5]||(t[5]=function(t){return e.webRuleManageForm.rule_action=t}),placeholder:"请选择",onChange:t[6]||(t[6]=function(t){return e.onChangeRuleAction()})},{default:Object(r["withCtx"])((function(){return[(Object(r["openBlock"])(!0),Object(r["createBlock"])(r["Fragment"],null,Object(r["renderList"])(e.ruleAction,(function(e){return Object(r["openBlock"])(),Object(r["createBlock"])(B,{key:e.value,label:e.label,value:e.value},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1}),"bot_check"==e.webRuleManageForm.rule_action?(Object(r["openBlock"])(),Object(r["createBlock"])(M,{key:0},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[7]||(t[7]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(r["withCtx"])((function(){return[(Object(r["openBlock"])(!0),Object(r["createBlock"])(r["Fragment"],null,Object(r["renderList"])(e.optionsBotCheck,(function(e){return Object(r["openBlock"])(),Object(r["createBlock"])(B,{key:e.value,label:e.label,value:e.value},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"]),O]})),_:1})):Object(r["createCommentVNode"])("",!0),"add_shared_dict_key"==e.webRuleManageForm.rule_action?(Object(r["openBlock"])(),Object(r["createBlock"])(M,{key:1},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[8]||(t[8]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(r["withCtx"])((function(){return[(Object(r["openBlock"])(!0),Object(r["createBlock"])(r["Fragment"],null,Object(r["renderList"])(e.optionsDict,(function(e){return Object(r["openBlock"])(),Object(r["createBlock"])(B,{key:e.shared_dict_uuid,label:e.shared_dict_name,value:e.shared_dict_uuid},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})):Object(r["createCommentVNode"])("",!0),"add_name_list_item"==e.webRuleManageForm.rule_action?(Object(r["openBlock"])(),Object(r["createBlock"])(M,{key:2},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[9]||(t[9]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(r["withCtx"])((function(){return[(Object(r["openBlock"])(!0),Object(r["createBlock"])(r["Fragment"],null,Object(r["renderList"])(e.optionsNameList,(function(e){return Object(r["openBlock"])(),Object(r["createBlock"])(B,{key:e.name_list_uuid,label:e.name_list_name,value:e.name_list_uuid},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})):Object(r["createCommentVNode"])("",!0),Object(r["createVNode"])(M,{label:"日志记录"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(R,{modelValue:e.webRuleManageForm.rule_log,"onUpdate:modelValue":t[10]||(t[10]=function(t){return e.webRuleManageForm.rule_log=t}),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]})),_:1})])]})),_:1})]})),_:1},8,["model","rules"]),j,Object(r["createVNode"])(y,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(a,{span:24},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(y,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(a,{span:12},{default:Object(r["withCtx"])((function(){return["group_rule"==e.ruleType?(Object(r["openBlock"])(),Object(r["createBlock"])("a",{key:0,class:"el-button el-button--primary is-plain",href:"/#/group-rule/"+e.uuid+"/web-rule-manage"},"返回",8,["href"])):(Object(r["openBlock"])(),Object(r["createBlock"])("a",{key:1,class:"el-button el-button--primary is-plain",href:"/#/web-rule-manage/"+e.ruleType},"返回",8,["href"]))]})),_:1}),Object(r["createVNode"])(a,{span:12,class:"text-align-right"},{default:Object(r["withCtx"])((function(){return[Object(r["createVNode"])(x,{type:"primary",onClick:t[11]||(t[11]=function(t){return e.onClickWebRuleProSubmit("webRuleManageForm")}),loading:e.loading},{default:Object(r["withCtx"])((function(){return[w]})),_:1},8,["loading"])]})),_:1})]})),_:1})]})),_:1})]})),_:1})]})),_:1})]})),_:1},512),[[S,e.loadingPage,void 0,{fullscreen:!0,lock:!0}]])])}a("159b"),a("ac1f"),a("1276"),a("5319"),a("4d63"),a("25f0"),a("a434");var k=a("362c"),M=a("6c02"),V={mixins:[k["b"]],data:function(){return{loading:!1,loadingPage:!1,uuid:"",ruleType:"single_rule",webRuleManageForm:{rule_detail:"",action_value:"",rule_log:"true"},type:"edit",optionsMatchKey:[{value:"http_args",label:"http_args",children:[{value:"path",label:"path",leaf:!0},{value:"query_string",label:"query_string",leaf:!0},{value:"method",label:"method",leaf:!0},{value:"src_ip",label:"src_ip",leaf:!0},{value:"raw_body",label:"raw_body",leaf:!0},{value:"version",label:"version",leaf:!0},{value:"scheme",label:"scheme",leaf:!0},{value:"raw_header",label:"raw_header",leaf:!0}]},{value:"header_args",label:"header_args",children:[{value:"host",label:"host",leaf:!0},{value:"cookie",label:"cookie",leaf:!0},{value:"referer",label:"referer",leaf:!0},{value:"user_agent",label:"user_agent",leaf:!0},{value:"default",label:"自定义",leaf:!0}]},{value:"cookie_args",label:"cookie_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"uri_args",label:"uri_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"post_args",label:"post_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"json_post_args",label:"json_post_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"shared_dict",label:"shared_dict"}],ruleBigMatchs:[{ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",checkboxPreprocess:[],argsPrepocessList:[{args_prepocess_value:""}]}],operator:"",optionsOperator:[{value:"rx",label:"正则匹配"},{value:"str_prefix",label:"前缀匹配"},{value:"str_suffix",label:"后缀匹配"},{value:"str_contain",label:"包含"},{value:"str_ncontain",label:"不包含"},{value:"str_eq",label:"等于"},{value:"str_neq",label:"不等于"},{value:"gt",label:"数字大于"},{value:"lt",label:"数字小于"},{value:"eq",label:"数字等于"},{value:"neq",label:"数字不等于"}],optionsArgs:[{value:"none",label:"不处理",key:"none"},{value:"lowerCase",label:"小写处理",key:"lowerCase"},{value:"base64Decode",label:"BASE64解码",key:"base64Decode"},{value:"length",label:"长度计算",key:"length"},{value:"uriDecode",label:"URL解码",key:"uriDecode"},{value:"uniDecode",label:"UNICODE解码",key:"uniDecode"},{value:"hexDecode",label:"十六进制解码",key:"hexDecode"},{value:"type",label:"获取数据类型",key:"type"}],ruleAction:[{value:"block",label:"阻断请求"},{value:"reject_response",label:"拒绝响应"},{value:"watch",label:"观察模式"},{value:"bot_check",label:"人机识别"},{value:"add_shared_dict_key",label:"共享字典写入"},{value:"add_name_list_item",label:"名单写入"}],optionsBotCheck:[{value:"standard",label:"标准"},{value:"slipper",label:"滑块"},{value:"image",label:"图片验证码"}],optionsDict:[],optionsNameList:[],action_value:"",propsMatchKey:{expandTrigger:"hover",lazy:!0,lazyLoad:function(e,t){if("shared_dict"==e.label){var a=[];Object(k["a"])("post","/waf/waf_get_sys_shared_dict_list",{},(function(e){var r=e.data.message;r.forEach((function(e){a.push({label:e.shared_dict_name,value:e.shared_dict_uuid,leaf:!0})})),t(a)}),(function(){}),"no-message")}}}}},computed:{rules:function(){return{rule_name:[{required:!0,message:"请输入规则名称",trigger:["blur","change"]},{validator:k["g"],trigger:["blur","change"]}],action_value:[{required:!0,message:"请选择匹配方式",trigger:"change"}],match_value:[{required:!0,message:"请输入匹配内容",trigger:["blur","change"]}],rule_action:[{required:!0,message:"请选择执行动作",trigger:"change"}],checkboxPreprocess:[{type:"array",required:!0,message:"请至少选择一个",trigger:"change"}]}}},mounted:function(){var e=this,t=Object(M["c"])();e.uuid=t.params.uuid,e.ruleType=t.params.ruleType,e.type=t.params.type,"new"==e.type?e.loadingPage=!1:(e.loadingPage=!1,Object(k["a"])("post","/waf/waf_get_sys_shared_dict_list",{},(function(t){e.optionsDict=t.data.message,e.getData()}),(function(){}),"no-message"))},methods:{getData:function(){var e=this,t="/waf/waf_get_sys_web_rule_protection",a={rule_uuid:e.uuid,rule_type:e.ruleType};"group_rule"==e.ruleType&&(a={rule_uuid:e.type,rule_type:e.ruleType}),Object(k["a"])("post",t,a,(function(t){e.loadingPage=!1,e.webRuleManageForm=t.data.message;var a=JSON.parse(e.webRuleManageForm.rule_matchs),r=[];for(var l in a){var c=[],n=[],o=["header_args","cookie_args","uri_args","post_args","json_post_args"];for(var u in a[l].match_args){var i=a[l].match_args[u],s=i.key,d=i.value,b="false";o.indexOf(s)>-1&&(b="true"),"shared_dict"==s?e.optionsDict.forEach((function(e){e.shared_dict_uuid==d&&c.push({rule_match_key_list:[s,e.shared_dict_uuid],rule_match_key:s+":"+e.shared_dict_name,showInput:b})})):c.push({rule_match_key_list:[s,d],rule_match_key:s+":"+d,showInput:b})}for(var h in a[l].args_prepocess)n.push({args_prepocess_value:a[l].args_prepocess[h]});r.push({ruleSmallMatchs:c,argsPrepocessList:n,match_operator:a[l].match_operator,match_value:a[l].match_value})}e.ruleBigMatchs=r,"add_name_list_item"==e.webRuleManageForm.rule_action&&e.onChangeRuleAction(),e.action_value=e.webRuleManageForm.action_value}),(function(){e.loadingPage=!1}),"no-message")},onChangeRuleAction:function(){var e=this;e.action_value="";var t={};0==e.optionsNameList.length&&"add_name_list_item"==e.webRuleManageForm.rule_action&&Object(k["a"])("post","/waf/waf_get_sys_name_list_list",t,(function(t){e.optionsNameList=t.data.message}),(function(){}),"no-message"),0==e.optionsDict.length&&"add_shared_dict_key"==e.webRuleManageForm.rule_action&&Object(k["a"])("post","/waf/waf_get_sys_shared_dict_list",t,(function(t){e.optionsDict=t.data.message}),(function(){}),"no-message")},onClickWebRuleProSubmit:function(e){var t=this,a=[];if(0==t.ruleBigMatchs.length)return t.$message({showClose:!0,message:"请输入详细规则",type:"error"}),!1;for(var r in t.ruleBigMatchs){var l=[],c=[];if(0==t.ruleBigMatchs[r].ruleSmallMatchs.length)return t.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;for(var n in t.ruleBigMatchs[r].ruleSmallMatchs){var o=t.ruleBigMatchs[r].ruleSmallMatchs[n];if(""==o.rule_match_key)return t.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;var u="",i=[],s="",d="";o.rule_match_key&&(i=o.rule_match_key.split(":")),i.length>0&&(s=i[0],d=o.rule_match_key.replace(new RegExp(s+":"),""),u='{"key":"'+s+'" , "value":"'+d+'"}'),"shared_dict"==s&&(u='{"key":"'+s+'" , "value":"'+o.rule_match_key_list[1]+'"}'),l.push(JSON.parse(u))}if(0==t.ruleBigMatchs[r].argsPrepocessList.length)return t.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;for(var b in t.ruleBigMatchs[r].argsPrepocessList){if(""==t.ruleBigMatchs[r].argsPrepocessList[b].args_prepocess_value)return t.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;c.push(t.ruleBigMatchs[r].argsPrepocessList[b].args_prepocess_value)}if(""==t.ruleBigMatchs[r].match_operator)return t.$message({showClose:!0,message:"请选择匹配方式",type:"error"}),!1;if(""==t.ruleBigMatchs[r].match_value)return t.$message({showClose:!0,message:"请输入匹配内容",type:"error"}),!1;a.push({match_args:l,args_prepocess:c,match_operator:t.ruleBigMatchs[r].match_operator,match_value:t.ruleBigMatchs[r].match_value})}if("bot_check"==t.webRuleManageForm.rule_action&&""==t.action_value)return t.$message({message:"请选择人机识别方式",type:"error"}),!1;if("add_shared_dict_key"==t.webRuleManageForm.rule_action&&""==t.action_value)return t.$message({message:"请选择共享字典",type:"error"}),!1;if("add_name_list_item"==t.webRuleManageForm.rule_action&&""==t.action_value)return t.$message({message:"请选择名单",type:"error"}),!1;t.webRuleManageForm.action_value=t.action_value;var h="/waf/waf_edit_sys_web_rule_protection";"new"==t.type?(h="/waf/waf_create_sys_web_rule_protection","group_rule"==t.ruleType&&(t.webRuleManageForm.rule_group_uuid=t.uuid)):(t.webRuleManageForm.rule_uuid=t.uuid,"group_rule"==t.ruleType&&(t.webRuleManageForm.rule_uuid=t.type)),t.webRuleManageForm.rule_type=t.ruleType,t.webRuleManageForm.rule_matchs=JSON.stringify(a),this.$refs[e].validate((function(e){e&&(t.loading=!0,Object(k["a"])("post",h,t.webRuleManageForm,(function(e){t.loading=!1,"group_rule"==t.ruleType?window.location.href="/#/group-rule/"+t.uuid+"/web-rule-manage":window.location.href="/#/web-rule-manage/"+t.ruleType}),(function(){t.loading=!1})))}))},removeArgsPrepocess:function(e,t){var a=this.ruleBigMatchs[t].argsPrepocessList.indexOf(e);-1!=a&&this.ruleBigMatchs[t].argsPrepocessList.splice(a,1)},addArgsPrepocess:function(e){this.ruleBigMatchs[e].argsPrepocessList.push({args_prepocess_value:""})},addRuleMatchs:function(e){this.ruleBigMatchs[e].ruleSmallMatchs.push({rule_match_key:"",rule_match_key_list:[],showInput:!1})},removeRuleMatchs:function(e,t){var a=this.ruleBigMatchs[t].ruleSmallMatchs.indexOf(e);-1!=a&&this.ruleBigMatchs[t].ruleSmallMatchs.splice(a,1)},removeRuleBigMatchs:function(e){var t=this.ruleBigMatchs.indexOf(e);-1!=t&&this.ruleBigMatchs.splice(t,1)},addRuleBigMatchs:function(e){this.ruleBigMatchs.push({ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",checkboxPreprocess:[],argsPrepocessList:[{args_prepocess_value:""}]})},onChangeRuleMatchs:function(e,t,a){var r=this.ruleBigMatchs[a].ruleSmallMatchs.indexOf(t);"default"==e[1]?(this.ruleBigMatchs[a].ruleSmallMatchs[r].showInput=!0,this.ruleBigMatchs[a].ruleSmallMatchs[r].rule_match_key=e[0]+":"):this.ruleBigMatchs[a].ruleSmallMatchs[r].rule_match_key=e[0]+":"+e[1]},onChangeRuleInput:function(e,t,a){var r=this.ruleBigMatchs[a].ruleSmallMatchs.indexOf(t);""==e?(this.ruleBigMatchs[a].ruleSmallMatchs[r].showInput=!1,this.ruleBigMatchs[a].ruleSmallMatchs[r].rule_match_key="",this.ruleBigMatchs[a].ruleSmallMatchs[r].rule_match_key_list=[]):this.ruleBigMatchs[a].ruleSmallMatchs[r].rule_match_key=e}}};a("d9b38");V.render=y;t["default"]=V},"4d63":function(e,t,a){var r=a("83ab"),l=a("da84"),c=a("94ca"),n=a("7156"),o=a("9112"),u=a("9bf2").f,i=a("241c").f,s=a("44e7"),d=a("577e"),b=a("ad6d"),h=a("9f7f"),p=a("6eeb"),f=a("d039"),_=a("5135"),g=a("69f3").enforce,m=a("2626"),v=a("b622"),O=a("fce3"),j=a("107c"),w=v("match"),y=l.RegExp,k=y.prototype,M=/^\?<[^\s\d!#%&*+<=>@^][^\s!#%&*+<=>@^]*>/,V=/a/g,x=/a/g,B=new y(V)!==V,C=h.UNSUPPORTED_Y,N=r&&(!B||C||O||j||f((function(){return x[w]=!1,y(V)!=V||y(x)==x||"/a/i"!=y(V,"i")}))),R=function(e){for(var t,a=e.length,r=0,l="",c=!1;r<=a;r++)t=e.charAt(r),"\\"!==t?c||"."!==t?("["===t?c=!0:"]"===t&&(c=!1),l+=t):l+="[\\s\\S]":l+=t+e.charAt(++r);return l},F=function(e){for(var t,a=e.length,r=0,l="",c=[],n={},o=!1,u=!1,i=0,s="";r<=a;r++){if(t=e.charAt(r),"\\"===t)t+=e.charAt(++r);else if("]"===t)o=!1;else if(!o)switch(!0){case"["===t:o=!0;break;case"("===t:M.test(e.slice(r+1))&&(r+=2,u=!0),l+=t,i++;continue;case">"===t&&u:if(""===s||_(n,s))throw new SyntaxError("Invalid capture group name");n[s]=!0,c.push([s,i]),u=!1,s="";continue}u?s+=t:l+=t}return[l,c]};if(c("RegExp",N)){for(var S=function(e,t){var a,r,l,c,u,i,h=this instanceof S,p=s(e),f=void 0===t,_=[],m=e;if(!h&&p&&f&&e.constructor===S)return e;if((p||e instanceof S)&&(e=e.source,f&&(t="flags"in m?m.flags:b.call(m))),e=void 0===e?"":d(e),t=void 0===t?"":d(t),m=e,O&&"dotAll"in V&&(r=!!t&&t.indexOf("s")>-1,r&&(t=t.replace(/s/g,""))),a=t,C&&"sticky"in V&&(l=!!t&&t.indexOf("y")>-1,l&&(t=t.replace(/y/g,""))),j&&(c=F(e),e=c[0],_=c[1]),u=n(y(e,t),h?this:k,S),(r||l||_.length)&&(i=g(u),r&&(i.dotAll=!0,i.raw=S(R(e),a)),l&&(i.sticky=!0),_.length&&(i.groups=_)),e!==m)try{o(u,"source",""===m?"(?:)":m)}catch(v){}return u},P=function(e){e in S||u(S,e,{configurable:!0,get:function(){return y[e]},set:function(t){y[e]=t}})},L=i(y),T=0;L.length>T;)P(L[T++]);k.constructor=S,S.prototype=k,p(l,"RegExp",S)}m("RegExp")},5319:function(e,t,a){"use strict";var r=a("d784"),l=a("d039"),c=a("825a"),n=a("a691"),o=a("50c4"),u=a("577e"),i=a("1d80"),s=a("8aa5"),d=a("0cb2"),b=a("14c3"),h=a("b622"),p=h("replace"),f=Math.max,_=Math.min,g=function(e){return void 0===e?e:String(e)},m=function(){return"$0"==="a".replace(/./,"$0")}(),v=function(){return!!/./[p]&&""===/./[p]("a","$0")}(),O=!l((function(){var e=/./;return e.exec=function(){var e=[];return e.groups={a:"7"},e},"7"!=="".replace(e,"$<a>")}));r("replace",(function(e,t,a){var r=v?"$":"$0";return[function(e,a){var r=i(this),l=void 0==e?void 0:e[p];return void 0!==l?l.call(e,r,a):t.call(u(r),e,a)},function(e,l){var i=c(this),h=u(e);if("string"===typeof l&&-1===l.indexOf(r)&&-1===l.indexOf("$<")){var p=a(t,i,h,l);if(p.done)return p.value}var m="function"===typeof l;m||(l=u(l));var v=i.global;if(v){var O=i.unicode;i.lastIndex=0}var j=[];while(1){var w=b(i,h);if(null===w)break;if(j.push(w),!v)break;var y=u(w[0]);""===y&&(i.lastIndex=s(h,o(i.lastIndex),O))}for(var k="",M=0,V=0;V<j.length;V++){w=j[V];for(var x=u(w[0]),B=f(_(n(w.index),h.length),0),C=[],N=1;N<w.length;N++)C.push(g(w[N]));var R=w.groups;if(m){var F=[x].concat(C,B,h);void 0!==R&&F.push(R);var S=u(l.apply(void 0,F))}else S=d(x,h,B,C,R,l);B>=M&&(k+=h.slice(M,B)+S,M=B+x.length)}return k+h.slice(M)}]}),!O||!m||v)},7156:function(e,t,a){var r=a("861d"),l=a("d2bb");e.exports=function(e,t,a){var c,n;return l&&"function"==typeof(c=t.constructor)&&c!==a&&r(n=c.prototype)&&n!==a.prototype&&l(e,n),e}},8418:function(e,t,a){"use strict";var r=a("a04b"),l=a("9bf2"),c=a("5c6c");e.exports=function(e,t,a){var n=r(t);n in e?l.f(e,n,c(0,a)):e[n]=a}},"987a":function(e,t,a){},a434:function(e,t,a){"use strict";var r=a("23e7"),l=a("23cb"),c=a("a691"),n=a("50c4"),o=a("7b0b"),u=a("65f0"),i=a("8418"),s=a("1dde"),d=s("splice"),b=Math.max,h=Math.min,p=9007199254740991,f="Maximum allowed length exceeded";r({target:"Array",proto:!0,forced:!d},{splice:function(e,t){var a,r,s,d,_,g,m=o(this),v=n(m.length),O=l(e,v),j=arguments.length;if(0===j?a=r=0:1===j?(a=0,r=v-O):(a=j-2,r=h(b(c(t),0),v-O)),v+a-r>p)throw TypeError(f);for(s=u(m,r),d=0;d<r;d++)_=O+d,_ in m&&i(s,d,m[_]);if(s.length=r,a<r){for(d=O;d<v-r;d++)_=d+r,g=d+a,_ in m?m[g]=m[_]:delete m[g];for(d=v;d>v-r+a;d--)delete m[d-1]}else if(a>r)for(d=v-r;d>O;d--)_=d+r-1,g=d+a-1,_ in m?m[g]=m[_]:delete m[g];for(d=0;d<a;d++)m[d+O]=arguments[d+2];return m.length=v-r+a,s}})},d9b38:function(e,t,a){"use strict";a("987a")}}]);
//# sourceMappingURL=chunk-493ac3d3.js.map