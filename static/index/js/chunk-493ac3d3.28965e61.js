(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-493ac3d3"],{"0cb2":function(e,t,a){var l=a("7b0b"),r=Math.floor,c="".replace,n=/\$([$&'`]|\d{1,2}|<[^>]*>)/g,o=/\$([$&'`]|\d{1,2})/g;e.exports=function(e,t,a,u,i,s){var d=a+e.length,b=u.length,f=o;return void 0!==i&&(i=l(i),f=n),c.call(s,f,(function(l,c){var n;switch(c.charAt(0)){case"$":return"$";case"&":return e;case"`":return t.slice(0,a);case"'":return t.slice(d);case"<":n=i[c.slice(1,-1)];break;default:var o=+c;if(0===o)return l;if(o>b){var s=r(o/10);return 0===s?l:s<=b?void 0===u[s-1]?c.charAt(1):u[s-1]+c.charAt(1):l}n=u[o-1]}return void 0===n?"":n}))}},"1dde":function(e,t,a){var l=a("d039"),r=a("b622"),c=a("2d00"),n=r("species");e.exports=function(e){return c>=51||!l((function(){var t=[],a=t.constructor={};return a[n]=function(){return{foo:1}},1!==t[e](Boolean).foo}))}},"25f0":function(e,t,a){"use strict";var l=a("6eeb"),r=a("825a"),c=a("577e"),n=a("d039"),o=a("ad6d"),u="toString",i=RegExp.prototype,s=i[u],d=n((function(){return"/a/b"!=s.call({source:"a",flags:"b"})})),b=s.name!=u;(d||b)&&l(RegExp.prototype,u,(function(){var e=r(this),t=c(e.source),a=e.flags,l=c(void 0===a&&e instanceof RegExp&&!("flags"in i)?o.call(e):a);return"/"+t+"/"+l}),{unsafe:!0})},3520:function(e,t,a){"use strict";a.r(t);a("b0c0");var l=a("7a23"),r={class:"custom-edit-wrap"},c=Object(l["createVNode"])("h3",null,"Web防护规则",-1),n=Object(l["createVNode"])("div",{class:"margin-4x"},null,-1),o={class:"match-box-content"},u={class:"match_key_cascader"},i={class:"match_key_input"},s=Object(l["createTextVNode"])("删除"),d=Object(l["createTextVNode"])("新增"),b={class:"match-box-content"},f={class:"match_key_cascader"},_=Object(l["createTextVNode"])("删除"),p=Object(l["createTextVNode"])("新增"),h={class:"card-item-bottom"},m=Object(l["createTextVNode"])("删除"),g={class:"card-footer"},v=Object(l["createTextVNode"])("新增"),O=Object(l["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),j=Object(l["createVNode"])("div",{class:"margin-4x"},null,-1),w=Object(l["createTextVNode"])("保存 ");function k(e,t){var a=Object(l["resolveComponent"])("el-col"),k=Object(l["resolveComponent"])("el-row"),y=Object(l["resolveComponent"])("el-input"),V=Object(l["resolveComponent"])("el-form-item"),B=Object(l["resolveComponent"])("el-cascader"),M=Object(l["resolveComponent"])("el-button"),x=Object(l["resolveComponent"])("el-option"),C=Object(l["resolveComponent"])("el-select"),N=Object(l["resolveComponent"])("el-card"),R=Object(l["resolveComponent"])("el-switch"),F=Object(l["resolveComponent"])("el-form"),S=Object(l["resolveDirective"])("loading");return Object(l["openBlock"])(),Object(l["createBlock"])("div",r,[Object(l["createVNode"])(k,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(a,{span:24},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(k,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(a,{span:12},{default:Object(l["withCtx"])((function(){return[c]})),_:1}),Object(l["createVNode"])(a,{span:12,class:"text-align-right"},{default:Object(l["withCtx"])((function(){return["group_rule"==e.ruleType?(Object(l["openBlock"])(),Object(l["createBlock"])("a",{key:0,class:"el-button el-button--primary is-plain",href:"/#/group-rule/"+e.uuid+"/web-rule-manage"},"返回",8,["href"])):(Object(l["openBlock"])(),Object(l["createBlock"])("a",{key:1,class:"el-button el-button--primary is-plain",href:"/#/web-rule-manage/"+e.ruleType},"返回",8,["href"]))]})),_:1})]})),_:1})]})),_:1})]})),_:1}),n,Object(l["withDirectives"])(Object(l["createVNode"])(k,null,{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(a,{span:24},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(F,{class:"custom-edit-form",model:e.webRuleManageForm,rules:e.rules,ref:"webRuleManageForm","label-width":"180px"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(N,{class:"box-card"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])("div",null,[Object(l["createVNode"])(V,{label:"规则名称",prop:"rule_name"},{default:Object(l["withCtx"])((function(){return["new"==e.type?(Object(l["openBlock"])(),Object(l["createBlock"])(y,{key:0,modelValue:e.webRuleManageForm.rule_name,"onUpdate:modelValue":t[1]||(t[1]=function(t){return e.webRuleManageForm.rule_name=t}),placeholder:"请输入字母开头，字母或数字组合，仅支持_-两种符号"},null,8,["modelValue"])):(Object(l["openBlock"])(),Object(l["createBlock"])(y,{key:1,modelValue:e.webRuleManageForm.rule_name,"onUpdate:modelValue":t[2]||(t[2]=function(t){return e.webRuleManageForm.rule_name=t}),disabled:""},null,8,["modelValue"]))]})),_:1}),Object(l["createVNode"])(V,{label:"规则详情"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(y,{modelValue:e.webRuleManageForm.rule_detail,"onUpdate:modelValue":t[3]||(t[3]=function(t){return e.webRuleManageForm.rule_detail=t})},null,8,["modelValue"])]})),_:1}),Object(l["createVNode"])(N,{class:"box-card-rule",shadow:"never"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.ruleBigMatchs,(function(t,a){return Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"card-item",key:a},[Object(l["createVNode"])(V,{label:"匹配参数"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(t.ruleSmallMatchs,(function(t,r){return Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"match-box",key:r},[Object(l["createVNode"])("div",o,[Object(l["createVNode"])("div",u,[Object(l["createVNode"])(B,{separator:":",modelValue:t.rule_match_key_list,"onUpdate:modelValue":function(e){return t.rule_match_key_list=e},options:e.optionsMatchKey,props:e.propsMatchKey,onChange:function(l){return e.onChangeRuleMatchs(l,t,a)},clearable:""},null,8,["modelValue","onUpdate:modelValue","options","props","onChange"])]),Object(l["withDirectives"])(Object(l["createVNode"])("div",i,[Object(l["createVNode"])(y,{modelValue:t.rule_match_key,"onUpdate:modelValue":function(e){return t.rule_match_key=e},clearable:"",onChange:function(l){return e.onChangeRuleInput(l,t,a)}},null,8,["modelValue","onUpdate:modelValue","onChange"])],512),[[l["vShow"],t.showInput]])]),Object(l["createVNode"])(M,{onClick:Object(l["withModifiers"])((function(l){return e.removeRuleMatchs(t,a)}),["prevent"])},{default:Object(l["withCtx"])((function(){return[s]})),_:2},1032,["onClick"])])})),128)),Object(l["createVNode"])(M,{onClick:function(t){return e.addRuleMatchs(a)},plain:"",type:"primary"},{default:Object(l["withCtx"])((function(){return[d]})),_:2},1032,["onClick"])]})),_:2},1024),Object(l["createVNode"])(V,{label:"参数处理"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(t.argsPrepocessList,(function(t,r){return Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"match-box",key:r},[Object(l["createVNode"])("div",b,[Object(l["createVNode"])("div",f,[Object(l["createVNode"])(C,{modelValue:t.args_prepocess_value,"onUpdate:modelValue":function(e){return t.args_prepocess_value=e},placeholder:"Select"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.optionsArgs,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.value,label:e.label,value:e.value},null,8,["label","value"])})),128))]})),_:2},1032,["modelValue","onUpdate:modelValue"])])]),Object(l["createVNode"])(M,{onClick:Object(l["withModifiers"])((function(l){return e.removeArgsPrepocess(t,a)}),["prevent"])},{default:Object(l["withCtx"])((function(){return[_]})),_:2},1032,["onClick"])])})),128)),Object(l["createVNode"])(M,{onClick:function(t){return e.addArgsPrepocess(a)},plain:"",type:"primary"},{default:Object(l["withCtx"])((function(){return[p]})),_:2},1032,["onClick"])]})),_:2},1024),Object(l["createVNode"])(V,{label:"匹配方式"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(C,{modelValue:t.match_operator,"onUpdate:modelValue":function(e){return t.match_operator=e},placeholder:"请选择"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.optionsOperator,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.value,label:e.label,value:e.value},null,8,["label","value"])})),128))]})),_:2},1032,["modelValue","onUpdate:modelValue"])]})),_:2},1024),Object(l["createVNode"])(V,{label:"匹配内容"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(y,{modelValue:t.match_value,"onUpdate:modelValue":function(e){return t.match_value=e}},null,8,["modelValue","onUpdate:modelValue"])]})),_:2},1024),Object(l["createVNode"])("div",h,[Object(l["createVNode"])(M,{type:"danger",plain:"",onClick:Object(l["withModifiers"])((function(a){return e.removeRuleBigMatchs(t)}),["prevent"])},{default:Object(l["withCtx"])((function(){return[m]})),_:2},1032,["onClick"])])])})),128)),Object(l["createVNode"])("div",g,[Object(l["createVNode"])(M,{class:"button",type:"primary",onClick:t[4]||(t[4]=function(t){return e.addRuleBigMatchs(e.bigIndex)})},{default:Object(l["withCtx"])((function(){return[v]})),_:1})])]})),_:1}),Object(l["createVNode"])(V,{label:"执行动作",prop:"rule_action"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(C,{modelValue:e.webRuleManageForm.rule_action,"onUpdate:modelValue":t[5]||(t[5]=function(t){return e.webRuleManageForm.rule_action=t}),placeholder:"请选择",onChange:t[6]||(t[6]=function(t){return e.onChangeRuleAction()})},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.ruleAction,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.value,label:e.label,value:e.value},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1}),"bot_check"==e.webRuleManageForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(V,{key:0},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[7]||(t[7]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.optionsBotCheck,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.value,label:e.label,value:e.value},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"]),O]})),_:1})):Object(l["createCommentVNode"])("",!0),"add_shared_dict_key"==e.webRuleManageForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(V,{key:1},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[8]||(t[8]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.optionsDict,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.shared_dict_uuid,label:e.shared_dict_name,value:e.shared_dict_uuid},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})):Object(l["createCommentVNode"])("",!0),"add_name_list_item"==e.webRuleManageForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(V,{key:2},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[9]||(t[9]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.optionsNameList,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.name_list_uuid,label:e.name_list_name,value:e.name_list_uuid},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})):Object(l["createCommentVNode"])("",!0),"custom_response"==e.webRuleManageForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(V,{key:3},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[10]||(t[10]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.custom_response,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.name,label:e.name,value:e.name},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})):Object(l["createCommentVNode"])("",!0),"request_replace"==e.webRuleManageForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(V,{key:4},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[11]||(t[11]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.request_replace,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.name,label:e.name,value:e.name},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})):Object(l["createCommentVNode"])("",!0),"response_replace"==e.webRuleManageForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(V,{key:5},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[12]||(t[12]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.response_replace,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.name,label:e.name,value:e.name},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})):Object(l["createCommentVNode"])("",!0),"traffic_forward"==e.webRuleManageForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(V,{key:6},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(C,{modelValue:e.action_value,"onUpdate:modelValue":t[13]||(t[13]=function(t){return e.action_value=t}),placeholder:"请选择"},{default:Object(l["withCtx"])((function(){return[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(e.traffic_forward,(function(e){return Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:e.name,label:e.name,value:e.name},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})):Object(l["createCommentVNode"])("",!0),Object(l["createVNode"])(V,{label:"日志记录"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(R,{modelValue:e.webRuleManageForm.rule_log,"onUpdate:modelValue":t[14]||(t[14]=function(t){return e.webRuleManageForm.rule_log=t}),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]})),_:1})])]})),_:1})]})),_:1},8,["model","rules"]),j,Object(l["createVNode"])(k,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(a,{span:24},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(k,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(a,{span:12},{default:Object(l["withCtx"])((function(){return["group_rule"==e.ruleType?(Object(l["openBlock"])(),Object(l["createBlock"])("a",{key:0,class:"el-button el-button--primary is-plain",href:"/#/group-rule/"+e.uuid+"/web-rule-manage"},"返回",8,["href"])):(Object(l["openBlock"])(),Object(l["createBlock"])("a",{key:1,class:"el-button el-button--primary is-plain",href:"/#/web-rule-manage/"+e.ruleType},"返回",8,["href"]))]})),_:1}),Object(l["createVNode"])(a,{span:12,class:"text-align-right"},{default:Object(l["withCtx"])((function(){return[Object(l["createVNode"])(M,{type:"primary",onClick:t[15]||(t[15]=function(t){return e.onClickWebRuleProSubmit("webRuleManageForm")}),loading:e.loading},{default:Object(l["withCtx"])((function(){return[w]})),_:1},8,["loading"])]})),_:1})]})),_:1})]})),_:1})]})),_:1})]})),_:1})]})),_:1},512),[[S,e.loadingPage,void 0,{fullscreen:!0,lock:!0}]])])}a("159b"),a("ac1f"),a("1276"),a("5319"),a("4d63"),a("25f0"),a("a434");var y=a("362c"),V=a("6c02"),B={mixins:[y["b"]],data:function(){return{loading:!1,loadingPage:!1,uuid:"",ruleType:"single_rule",webRuleManageForm:{rule_detail:"",action_value:"",rule_log:"true"},type:"edit",optionsMatchKey:[{value:"http_args",label:"http_args",children:[{value:"path",label:"path",leaf:!0},{value:"query_string",label:"query_string",leaf:!0},{value:"method",label:"method",leaf:!0},{value:"src_ip",label:"src_ip",leaf:!0},{value:"raw_body",label:"raw_body",leaf:!0},{value:"version",label:"version",leaf:!0},{value:"scheme",label:"scheme",leaf:!0},{value:"raw_header",label:"raw_header",leaf:!0}]},{value:"header_args",label:"header_args",children:[{value:"host",label:"host",leaf:!0},{value:"cookie",label:"cookie",leaf:!0},{value:"referer",label:"referer",leaf:!0},{value:"user_agent",label:"user_agent",leaf:!0},{value:"default",label:"自定义",leaf:!0}]},{value:"cookie_args",label:"cookie_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"uri_args",label:"uri_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"post_args",label:"post_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"json_post_args",label:"json_post_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"ctx_args",label:"ctx_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"shared_dict",label:"shared_dict"}],ruleBigMatchs:[{ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",checkboxPreprocess:[],argsPrepocessList:[{args_prepocess_value:""}]}],operator:"",optionsOperator:[{value:"rx",label:"正则匹配"},{value:"str_prefix",label:"前缀匹配"},{value:"str_suffix",label:"后缀匹配"},{value:"str_contain",label:"包含"},{value:"str_ncontain",label:"不包含"},{value:"str_eq",label:"等于"},{value:"str_neq",label:"不等于"},{value:"gt",label:"数字大于"},{value:"lt",label:"数字小于"},{value:"eq",label:"数字等于"},{value:"neq",label:"数字不等于"}],optionsArgs:[{value:"none",label:"不处理",key:"none"},{value:"lowerCase",label:"小写处理",key:"lowerCase"},{value:"base64Decode",label:"BASE64解码",key:"base64Decode"},{value:"length",label:"长度计算",key:"length"},{value:"uriDecode",label:"URL解码",key:"uriDecode"},{value:"uniDecode",label:"UNICODE解码",key:"uniDecode"},{value:"hexDecode",label:"十六进制解码",key:"hexDecode"},{value:"type",label:"获取数据类型",key:"type"}],ruleAction:[{value:"block",label:"阻断请求"},{value:"reject_response",label:"拒绝响应"},{value:"watch",label:"观察模式"},{value:"bot_check",label:"人机识别"},{value:"add_shared_dict_key",label:"共享字典写入"},{value:"add_name_list_item",label:"名单写入"},{value:"custom_response",label:"自定义响应"},{value:"request_replace",label:"请求替换"},{value:"response_replace",label:"响应替换"},{value:"traffic_forward",label:"流量转发"}],optionsBotCheck:[{value:"standard",label:"标准"},{value:"slipper",label:"滑块"},{value:"image",label:"图片验证码"}],optionsDict:[],optionsNameList:[],custom_response:[],request_replace:[],response_replace:[],traffic_forward:[],action_value:"",propsMatchKey:{expandTrigger:"hover",lazy:!0,lazyLoad:function(e,t){if("shared_dict"==e.label){var a=[];Object(y["a"])("post","/waf/waf_get_sys_shared_dict_list",{},(function(e){var l=e.data.message;l.forEach((function(e){a.push({label:e.shared_dict_name,value:e.shared_dict_uuid,leaf:!0})})),t(a)}),(function(){}),"no-message")}}}}},computed:{rules:function(){return{rule_name:[{required:!0,message:"请输入规则名称",trigger:["blur","change"]},{validator:y["h"],trigger:["blur","change"]}],action_value:[{required:!0,message:"请选择匹配方式",trigger:"change"}],match_value:[{required:!0,message:"请输入匹配内容",trigger:["blur","change"]}],rule_action:[{required:!0,message:"请选择执行动作",trigger:"change"}],checkboxPreprocess:[{type:"array",required:!0,message:"请至少选择一个",trigger:"change"}]}}},mounted:function(){var e=this,t=Object(V["c"])();e.uuid=t.params.uuid,e.ruleType=t.params.ruleType,e.type=t.params.type,this.getMimetic(),"new"==e.type?e.loadingPage=!1:(e.loadingPage=!1,Object(y["a"])("post","/waf/waf_get_sys_shared_dict_list",{},(function(t){e.optionsDict=t.data.message,e.getData()}),(function(){}),"no-message"))},methods:{getData:function(){var e=this,t="/waf/waf_get_sys_web_rule_protection",a={rule_uuid:e.uuid,rule_type:e.ruleType};"group_rule"==e.ruleType&&(a={rule_uuid:e.type,rule_type:e.ruleType}),Object(y["a"])("post",t,a,(function(t){e.loadingPage=!1,e.webRuleManageForm=t.data.message;var a=JSON.parse(e.webRuleManageForm.rule_matchs),l=[];for(var r in a){var c=[],n=[],o=["header_args","cookie_args","uri_args","post_args","json_post_args"];for(var u in a[r].match_args){var i=a[r].match_args[u],s=i.key,d=i.value,b="false";o.indexOf(s)>-1&&(b="true"),"shared_dict"==s?e.optionsDict.forEach((function(e){e.shared_dict_uuid==d&&c.push({rule_match_key_list:[s,e.shared_dict_uuid],rule_match_key:s+":"+e.shared_dict_name,showInput:b})})):c.push({rule_match_key_list:[s,d],rule_match_key:s+":"+d,showInput:b})}for(var f in a[r].args_prepocess)n.push({args_prepocess_value:a[r].args_prepocess[f]});l.push({ruleSmallMatchs:c,argsPrepocessList:n,match_operator:a[r].match_operator,match_value:a[r].match_value})}e.ruleBigMatchs=l,"add_name_list_item"!=e.webRuleManageForm.rule_action&&"custom_response"!=e.webRuleManageForm.rule_action&&"request_replace"!=e.webRuleManageForm.rule_action&&"traffic_forward"!=e.webRuleManageForm.rule_action||e.onChangeRuleAction(),e.action_value=e.webRuleManageForm.action_value}),(function(){e.loadingPage=!1}),"no-message")},getMimetic:function(){var e=this,t="/waf/waf_get_sys_mimetic_defense_conf";Object(y["a"])("get",t,{},(function(t){e.loadingPage=!1,"true"==t.data.message.mimetic_defense&&e.ruleAction.push({value:"mimetic_defense",label:"长亭拟态防御"})}),(function(){e.loadingPage=!1}),"no-message")},onChangeRuleAction:function(){var e=this;e.action_value="";var t={};0==e.optionsNameList.length&&"add_name_list_item"==e.webRuleManageForm.rule_action&&Object(y["a"])("post","/waf/waf_get_sys_name_list_list",t,(function(t){e.optionsNameList=t.data.message}),(function(){}),"no-message"),0==e.optionsDict.length&&"add_shared_dict_key"==e.webRuleManageForm.rule_action&&Object(y["a"])("post","/waf/waf_get_sys_shared_dict_list",t,(function(t){e.optionsDict=t.data.message}),(function(){}),"no-message"),0==e.custom_response.length&&"custom_response"==e.webRuleManageForm.rule_action&&Object(y["a"])("post","/waf/waf_get_sys_custom_response_list",t,(function(t){e.custom_response=t.data.message}),(function(){}),"no-message"),0==e.request_replace.length&&"request_replace"==e.webRuleManageForm.rule_action&&Object(y["a"])("post","/waf/waf_get_sys_request_replace_list",t,(function(t){e.request_replace=t.data.message}),(function(){}),"no-message"),0==e.response_replace.length&&"response_replace"==e.webRuleManageForm.rule_action&&Object(y["a"])("post","/waf/waf_get_sys_response_replace_list",t,(function(t){e.response_replace=t.data.message}),(function(){}),"no-message"),0==e.traffic_forward.length&&"traffic_forward"==e.webRuleManageForm.rule_action&&Object(y["a"])("post","/waf/waf_get_sys_traffic_forward_list",t,(function(t){e.traffic_forward=t.data.message}),(function(){}),"no-message")},onClickWebRuleProSubmit:function(e){var t=this,a=[];if(0==t.ruleBigMatchs.length)return t.$message({showClose:!0,message:"请输入详细规则",type:"error"}),!1;for(var l in t.ruleBigMatchs){var r=[],c=[];if(0==t.ruleBigMatchs[l].ruleSmallMatchs.length)return t.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;for(var n in t.ruleBigMatchs[l].ruleSmallMatchs){var o=t.ruleBigMatchs[l].ruleSmallMatchs[n];if(""==o.rule_match_key)return t.$message({showClose:!0,message:"请选择匹配参数",type:"error"}),!1;var u="",i=[],s="",d="";o.rule_match_key&&(i=o.rule_match_key.split(":")),i.length>0&&(s=i[0],d=o.rule_match_key.replace(new RegExp(s+":"),""),u='{"key":"'+s+'" , "value":"'+d+'"}'),"shared_dict"==s&&(u='{"key":"'+s+'" , "value":"'+o.rule_match_key_list[1]+'"}'),r.push(JSON.parse(u))}if(0==t.ruleBigMatchs[l].argsPrepocessList.length)return t.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;for(var b in t.ruleBigMatchs[l].argsPrepocessList){if(""==t.ruleBigMatchs[l].argsPrepocessList[b].args_prepocess_value)return t.$message({showClose:!0,message:"请选择参数处理",type:"error"}),!1;c.push(t.ruleBigMatchs[l].argsPrepocessList[b].args_prepocess_value)}if(""==t.ruleBigMatchs[l].match_operator)return t.$message({showClose:!0,message:"请选择匹配方式",type:"error"}),!1;if(""==t.ruleBigMatchs[l].match_value)return t.$message({showClose:!0,message:"请输入匹配内容",type:"error"}),!1;a.push({match_args:r,args_prepocess:c,match_operator:t.ruleBigMatchs[l].match_operator,match_value:t.ruleBigMatchs[l].match_value})}if("bot_check"==t.webRuleManageForm.rule_action&&""==t.action_value)return t.$message({message:"请选择人机识别方式",type:"error"}),!1;if("add_shared_dict_key"==t.webRuleManageForm.rule_action&&""==t.action_value)return t.$message({message:"请选择共享字典",type:"error"}),!1;if("add_name_list_item"==t.webRuleManageForm.rule_action&&""==t.action_value)return t.$message({message:"请选择名单",type:"error"}),!1;t.webRuleManageForm.action_value=t.action_value;var f="/waf/waf_edit_sys_web_rule_protection";"new"==t.type?(f="/waf/waf_create_sys_web_rule_protection","group_rule"==t.ruleType&&(t.webRuleManageForm.rule_group_uuid=t.uuid)):(t.webRuleManageForm.rule_uuid=t.uuid,"group_rule"==t.ruleType&&(t.webRuleManageForm.rule_uuid=t.type)),t.webRuleManageForm.rule_type=t.ruleType,t.webRuleManageForm.rule_matchs=JSON.stringify(a),this.$refs[e].validate((function(e){e&&(t.loading=!0,Object(y["a"])("post",f,t.webRuleManageForm,(function(e){t.loading=!1,"group_rule"==t.ruleType?window.location.href="/#/group-rule/"+t.uuid+"/web-rule-manage":window.location.href="/#/web-rule-manage/"+t.ruleType}),(function(){t.loading=!1})))}))},removeArgsPrepocess:function(e,t){var a=this.ruleBigMatchs[t].argsPrepocessList.indexOf(e);-1!=a&&this.ruleBigMatchs[t].argsPrepocessList.splice(a,1)},addArgsPrepocess:function(e){this.ruleBigMatchs[e].argsPrepocessList.push({args_prepocess_value:""})},addRuleMatchs:function(e){this.ruleBigMatchs[e].ruleSmallMatchs.push({rule_match_key:"",rule_match_key_list:[],showInput:!1})},removeRuleMatchs:function(e,t){var a=this.ruleBigMatchs[t].ruleSmallMatchs.indexOf(e);-1!=a&&this.ruleBigMatchs[t].ruleSmallMatchs.splice(a,1)},removeRuleBigMatchs:function(e){var t=this.ruleBigMatchs.indexOf(e);-1!=t&&this.ruleBigMatchs.splice(t,1)},addRuleBigMatchs:function(e){this.ruleBigMatchs.push({ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],match_operator:"",match_value:"",checkboxPreprocess:[],argsPrepocessList:[{args_prepocess_value:""}]})},onChangeRuleMatchs:function(e,t,a){var l=this.ruleBigMatchs[a].ruleSmallMatchs.indexOf(t);"default"==e[1]?(this.ruleBigMatchs[a].ruleSmallMatchs[l].showInput=!0,this.ruleBigMatchs[a].ruleSmallMatchs[l].rule_match_key=e[0]+":"):this.ruleBigMatchs[a].ruleSmallMatchs[l].rule_match_key=e[0]+":"+e[1]},onChangeRuleInput:function(e,t,a){var l=this.ruleBigMatchs[a].ruleSmallMatchs.indexOf(t);""==e?(this.ruleBigMatchs[a].ruleSmallMatchs[l].showInput=!1,this.ruleBigMatchs[a].ruleSmallMatchs[l].rule_match_key="",this.ruleBigMatchs[a].ruleSmallMatchs[l].rule_match_key_list=[]):this.ruleBigMatchs[a].ruleSmallMatchs[l].rule_match_key=e}}};a("d9b38");B.render=k;t["default"]=B},"4d63":function(e,t,a){var l=a("83ab"),r=a("da84"),c=a("94ca"),n=a("7156"),o=a("9112"),u=a("9bf2").f,i=a("241c").f,s=a("44e7"),d=a("577e"),b=a("ad6d"),f=a("9f7f"),_=a("6eeb"),p=a("d039"),h=a("5135"),m=a("69f3").enforce,g=a("2626"),v=a("b622"),O=a("fce3"),j=a("107c"),w=v("match"),k=r.RegExp,y=k.prototype,V=/^\?<[^\s\d!#%&*+<=>@^][^\s!#%&*+<=>@^]*>/,B=/a/g,M=/a/g,x=new k(B)!==B,C=f.UNSUPPORTED_Y,N=l&&(!x||C||O||j||p((function(){return M[w]=!1,k(B)!=B||k(M)==M||"/a/i"!=k(B,"i")}))),R=function(e){for(var t,a=e.length,l=0,r="",c=!1;l<=a;l++)t=e.charAt(l),"\\"!==t?c||"."!==t?("["===t?c=!0:"]"===t&&(c=!1),r+=t):r+="[\\s\\S]":r+=t+e.charAt(++l);return r},F=function(e){for(var t,a=e.length,l=0,r="",c=[],n={},o=!1,u=!1,i=0,s="";l<=a;l++){if(t=e.charAt(l),"\\"===t)t+=e.charAt(++l);else if("]"===t)o=!1;else if(!o)switch(!0){case"["===t:o=!0;break;case"("===t:V.test(e.slice(l+1))&&(l+=2,u=!0),r+=t,i++;continue;case">"===t&&u:if(""===s||h(n,s))throw new SyntaxError("Invalid capture group name");n[s]=!0,c.push([s,i]),u=!1,s="";continue}u?s+=t:r+=t}return[r,c]};if(c("RegExp",N)){for(var S=function(e,t){var a,l,r,c,u,i,f=this instanceof S,_=s(e),p=void 0===t,h=[],g=e;if(!f&&_&&p&&e.constructor===S)return e;if((_||e instanceof S)&&(e=e.source,p&&(t="flags"in g?g.flags:b.call(g))),e=void 0===e?"":d(e),t=void 0===t?"":d(t),g=e,O&&"dotAll"in B&&(l=!!t&&t.indexOf("s")>-1,l&&(t=t.replace(/s/g,""))),a=t,C&&"sticky"in B&&(r=!!t&&t.indexOf("y")>-1,r&&(t=t.replace(/y/g,""))),j&&(c=F(e),e=c[0],h=c[1]),u=n(k(e,t),f?this:y,S),(l||r||h.length)&&(i=m(u),l&&(i.dotAll=!0,i.raw=S(R(e),a)),r&&(i.sticky=!0),h.length&&(i.groups=h)),e!==g)try{o(u,"source",""===g?"(?:)":g)}catch(v){}return u},L=function(e){e in S||u(S,e,{configurable:!0,get:function(){return k[e]},set:function(t){k[e]=t}})},P=i(k),U=0;P.length>U;)L(P[U++]);y.constructor=S,S.prototype=y,_(r,"RegExp",S)}g("RegExp")},5319:function(e,t,a){"use strict";var l=a("d784"),r=a("d039"),c=a("825a"),n=a("a691"),o=a("50c4"),u=a("577e"),i=a("1d80"),s=a("8aa5"),d=a("0cb2"),b=a("14c3"),f=a("b622"),_=f("replace"),p=Math.max,h=Math.min,m=function(e){return void 0===e?e:String(e)},g=function(){return"$0"==="a".replace(/./,"$0")}(),v=function(){return!!/./[_]&&""===/./[_]("a","$0")}(),O=!r((function(){var e=/./;return e.exec=function(){var e=[];return e.groups={a:"7"},e},"7"!=="".replace(e,"$<a>")}));l("replace",(function(e,t,a){var l=v?"$":"$0";return[function(e,a){var l=i(this),r=void 0==e?void 0:e[_];return void 0!==r?r.call(e,l,a):t.call(u(l),e,a)},function(e,r){var i=c(this),f=u(e);if("string"===typeof r&&-1===r.indexOf(l)&&-1===r.indexOf("$<")){var _=a(t,i,f,r);if(_.done)return _.value}var g="function"===typeof r;g||(r=u(r));var v=i.global;if(v){var O=i.unicode;i.lastIndex=0}var j=[];while(1){var w=b(i,f);if(null===w)break;if(j.push(w),!v)break;var k=u(w[0]);""===k&&(i.lastIndex=s(f,o(i.lastIndex),O))}for(var y="",V=0,B=0;B<j.length;B++){w=j[B];for(var M=u(w[0]),x=p(h(n(w.index),f.length),0),C=[],N=1;N<w.length;N++)C.push(m(w[N]));var R=w.groups;if(g){var F=[M].concat(C,x,f);void 0!==R&&F.push(R);var S=u(r.apply(void 0,F))}else S=d(M,f,x,C,R,r);x>=V&&(y+=f.slice(V,x)+S,V=x+M.length)}return y+f.slice(V)}]}),!O||!g||v)},7156:function(e,t,a){var l=a("861d"),r=a("d2bb");e.exports=function(e,t,a){var c,n;return r&&"function"==typeof(c=t.constructor)&&c!==a&&l(n=c.prototype)&&n!==a.prototype&&r(e,n),e}},8418:function(e,t,a){"use strict";var l=a("a04b"),r=a("9bf2"),c=a("5c6c");e.exports=function(e,t,a){var n=l(t);n in e?r.f(e,n,c(0,a)):e[n]=a}},"987a":function(e,t,a){},a434:function(e,t,a){"use strict";var l=a("23e7"),r=a("23cb"),c=a("a691"),n=a("50c4"),o=a("7b0b"),u=a("65f0"),i=a("8418"),s=a("1dde"),d=s("splice"),b=Math.max,f=Math.min,_=9007199254740991,p="Maximum allowed length exceeded";l({target:"Array",proto:!0,forced:!d},{splice:function(e,t){var a,l,s,d,h,m,g=o(this),v=n(g.length),O=r(e,v),j=arguments.length;if(0===j?a=l=0:1===j?(a=0,l=v-O):(a=j-2,l=f(b(c(t),0),v-O)),v+a-l>_)throw TypeError(p);for(s=u(g,l),d=0;d<l;d++)h=O+d,h in g&&i(s,d,g[h]);if(s.length=l,a<l){for(d=O;d<v-l;d++)h=d+l,m=d+a,h in g?g[m]=g[h]:delete g[m];for(d=v;d>v-l+a;d--)delete g[d-1]}else if(a>l)for(d=v-l;d>O;d--)h=d+l-1,m=d+a-1,h in g?g[m]=g[h]:delete g[m];for(d=0;d<a;d++)g[d+O]=arguments[d+2];return g.length=v-l+a,s}})},d9b38:function(e,t,a){"use strict";a("987a")}}]);
//# sourceMappingURL=chunk-493ac3d3.28965e61.js.map