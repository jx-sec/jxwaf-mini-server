(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-06814c0e"],{"7c80":function(e,t,a){"use strict";a("bfca")},b272:function(e,t,a){"use strict";a.r(t);var l=a("7a23");const c={class:"custom-edit-wrap"},o=Object(l["createTextVNode"])("网站防护"),r=Object(l["createTextVNode"])("防护配置"),n=Object(l["createTextVNode"])("扫描攻击防护"),s=Object(l["createTextVNode"])("新增"),u=Object(l["createTextVNode"])("编辑"),i={class:"match-box-content"},d={class:"match_key_cascader"},h=Object(l["createTextVNode"])("删除"),m=Object(l["createTextVNode"])("新增"),b={class:"match-box-content"},_={class:"match_key_cascader"},p={class:"match_key_input"},k=Object(l["createTextVNode"])("删除"),O=Object(l["createTextVNode"])("新增"),j=Object(l["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),v=Object(l["createTextVNode"])("保存 ");function g(e,t,a,g,f,V){const w=Object(l["resolveComponent"])("el-breadcrumb-item"),y=Object(l["resolveComponent"])("el-breadcrumb"),C=Object(l["resolveComponent"])("el-row"),M=Object(l["resolveComponent"])("el-input"),x=Object(l["resolveComponent"])("el-form-item"),N=Object(l["resolveComponent"])("el-cascader"),S=Object(l["resolveComponent"])("el-button"),P=Object(l["resolveComponent"])("el-option"),A=Object(l["resolveComponent"])("el-select"),F=Object(l["resolveComponent"])("el-form"),B=Object(l["resolveComponent"])("el-col"),I=Object(l["resolveDirective"])("loading");return Object(l["openBlock"])(),Object(l["createBlock"])("div",c,[Object(l["createVNode"])(C,{class:"breadcrumb-style"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(y,{separator:"/"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(w,{to:{path:"/"}},{default:Object(l["withCtx"])(()=>[o]),_:1}),Object(l["createVNode"])(w,{to:{path:"/protection/"+f.domain}},{default:Object(l["withCtx"])(()=>[r]),_:1},8,["to"]),Object(l["createVNode"])(w,{to:{path:"/scan-attack-protection/"+f.domain}},{default:Object(l["withCtx"])(()=>[n]),_:1},8,["to"]),"new"==f.uuid?(Object(l["openBlock"])(),Object(l["createBlock"])(w,{key:0},{default:Object(l["withCtx"])(()=>[s]),_:1})):(Object(l["openBlock"])(),Object(l["createBlock"])(w,{key:1},{default:Object(l["withCtx"])(()=>[u]),_:1}))]),_:1})]),_:1}),Object(l["createVNode"])(C,{class:"container-style"},{default:Object(l["withCtx"])(()=>[Object(l["withDirectives"])(Object(l["createVNode"])(B,{span:24},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(F,{class:"custom-edit-form",model:f.scanAttackProForm,rules:V.rules,ref:"scanAttackProForm","label-width":"180px"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])("div",null,[Object(l["createVNode"])(x,{label:"规则名称",prop:"rule_name"},{default:Object(l["withCtx"])(()=>["new"==f.uuid?(Object(l["openBlock"])(),Object(l["createBlock"])(M,{key:0,modelValue:f.scanAttackProForm.rule_name,"onUpdate:modelValue":t[1]||(t[1]=e=>f.scanAttackProForm.rule_name=e),placeholder:"请输入字母开头，字母或数字组合，仅支持_-两种符号"},null,8,["modelValue"])):(Object(l["openBlock"])(),Object(l["createBlock"])(M,{key:1,modelValue:f.scanAttackProForm.rule_name,"onUpdate:modelValue":t[2]||(t[2]=e=>f.scanAttackProForm.rule_name=e),disabled:""},null,8,["modelValue"]))]),_:1}),Object(l["createVNode"])(x,{label:"规则详情"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(M,{modelValue:f.scanAttackProForm.rule_detail,"onUpdate:modelValue":t[3]||(t[3]=e=>f.scanAttackProForm.rule_detail=e)},null,8,["modelValue"])]),_:1}),Object(l["createVNode"])(x,{label:"防护模块",class:"is-required"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(f.moduleSmallMatchs,(e,t)=>(Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"match-box",key:t},[Object(l["createVNode"])("div",i,[Object(l["createVNode"])("div",d,[Object(l["createVNode"])(N,{separator:":",modelValue:e.rule_match_key_list,"onUpdate:modelValue":t=>e.rule_match_key_list=t,options:f.optionsModuleMatchKey,props:f.propsModuleMatchKey,onChange:t=>V.onChangeModuleMatchs(t,e),clearable:""},null,8,["modelValue","onUpdate:modelValue","options","props","onChange"])])]),Object(l["createVNode"])(S,{onClick:Object(l["withModifiers"])(t=>V.removeModuleMatchs(e),["prevent"])},{default:Object(l["withCtx"])(()=>[h]),_:2},1032,["onClick"])]))),128)),Object(l["createVNode"])(S,{onClick:t[4]||(t[4]=e=>V.addModuleMatchs()),plain:"",type:"primary",class:"button-new"},{default:Object(l["withCtx"])(()=>[m]),_:1})]),_:1}),Object(l["createVNode"])(x,{label:"统计对象",class:"is-required"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(f.ruleSmallMatchs,(e,t)=>(Object(l["openBlock"])(),Object(l["createBlock"])("div",{class:"match-box",key:t},[Object(l["createVNode"])("div",b,[Object(l["createVNode"])("div",_,[Object(l["createVNode"])(N,{separator:":",modelValue:e.rule_match_key_list,"onUpdate:modelValue":t=>e.rule_match_key_list=t,options:f.optionsMatchKey,props:f.propsMatchKey,onChange:t=>V.onChangeRuleMatchs(t,e),clearable:""},null,8,["modelValue","onUpdate:modelValue","options","props","onChange"])]),Object(l["withDirectives"])(Object(l["createVNode"])("div",p,[Object(l["createVNode"])(M,{modelValue:e.rule_match_key,"onUpdate:modelValue":t=>e.rule_match_key=t,clearable:"",onChange:t=>V.onChangeRuleInput(t,e)},null,8,["modelValue","onUpdate:modelValue","onChange"])],512),[[l["vShow"],e.showInput]])]),Object(l["createVNode"])(S,{onClick:Object(l["withModifiers"])(t=>V.removeRuleMatchs(e),["prevent"])},{default:Object(l["withCtx"])(()=>[k]),_:2},1032,["onClick"])]))),128)),Object(l["createVNode"])(S,{onClick:t[5]||(t[5]=e=>V.addRuleMatchs()),plain:"",type:"primary",class:"button-new"},{default:Object(l["withCtx"])(()=>[O]),_:1})]),_:1}),Object(l["createVNode"])(x,{label:"经过时间(秒)",prop:"statics_time"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(M,{modelValue:f.scanAttackProForm.statics_time,"onUpdate:modelValue":t[6]||(t[6]=e=>f.scanAttackProForm.statics_time=e),placeholder:"请输入大于0的数字"},null,8,["modelValue"])]),_:1}),Object(l["createVNode"])(x,{label:"攻击次数超过",prop:"statics_count"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(M,{modelValue:f.scanAttackProForm.statics_count,"onUpdate:modelValue":t[7]||(t[7]=e=>f.scanAttackProForm.statics_count=e),placeholder:"请输入大于0的数字"},null,8,["modelValue"])]),_:1}),Object(l["createVNode"])(x,{label:"IP处罚方式",prop:"rule_action"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(A,{modelValue:f.scanAttackProForm.rule_action,"onUpdate:modelValue":t[8]||(t[8]=e=>f.scanAttackProForm.rule_action=e),placeholder:"请选择",onChange:t[9]||(t[9]=e=>V.onChangeRuleAction())},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(f.ruleAction,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(P,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==f.scanAttackProForm.rule_action?(Object(l["openBlock"])(),Object(l["createBlock"])(x,{key:0},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(A,{modelValue:f.action_value,"onUpdate:modelValue":t[10]||(t[10]=e=>f.action_value=e),placeholder:"请选择"},{default:Object(l["withCtx"])(()=>[(Object(l["openBlock"])(!0),Object(l["createBlock"])(l["Fragment"],null,Object(l["renderList"])(f.optionsBotCheck,e=>(Object(l["openBlock"])(),Object(l["createBlock"])(P,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),j]),_:1})):Object(l["createCommentVNode"])("",!0),Object(l["createVNode"])(x,{label:"IP处罚时间",prop:"block_time"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(M,{modelValue:f.scanAttackProForm.block_time,"onUpdate:modelValue":t[11]||(t[11]=e=>f.scanAttackProForm.block_time=e),placeholder:"请输入大于0的数字"},null,8,["modelValue"])]),_:1})])]),_:1},8,["model","rules"]),Object(l["createVNode"])(C,{type:"flex",class:"margin-border",justify:"space-between"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(B,{span:12},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])("a",{class:"el-button el-button--primary is-plain",href:"/#/scan-attack-protection/"+f.domain},"返回",8,["href"])]),_:1}),Object(l["createVNode"])(B,{span:12,class:"text-align-right"},{default:Object(l["withCtx"])(()=>[Object(l["createVNode"])(S,{type:"primary",onClick:t[12]||(t[12]=e=>V.onClickWebRuleProSubmit("scanAttackProForm")),loading:f.loading},{default:Object(l["withCtx"])(()=>[v]),_:1},8,["loading"])]),_:1})]),_:1})]),_:1},512),[[I,f.loadingPage,void 0,{fullscreen:!0,lock:!0}]])]),_:1})])}var f=a("362c"),V=a("6c02");let w="";var y={mixins:[f["c"]],data(){return{loading:!1,loadingPage:!1,domain:"",uuid:"new",scanAttackProForm:{rule_detail:"",action_value:"",statics_time:"60",statics_count:"1000"},type:"edit",optionsMatchKey:[{value:"http_args",label:"http_args",children:[{value:"path",label:"path",leaf:!0},{value:"query_string",label:"query_string",leaf:!0},{value:"method",label:"method",leaf:!0},{value:"src_ip",label:"src_ip",leaf:!0},{value:"raw_body",label:"raw_body",leaf:!0},{value:"version",label:"version",leaf:!0},{value:"scheme",label:"scheme",leaf:!0},{value:"raw_header",label:"raw_header",leaf:!0}]},{value:"header_args",label:"header_args",children:[{value:"host",label:"host",leaf:!0},{value:"cookie",label:"cookie",leaf:!0},{value:"referer",label:"referer",leaf:!0},{value:"user_agent",label:"user_agent",leaf:!0},{value:"default",label:"自定义",leaf:!0}]},{value:"cookie_args",label:"cookie_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"uri_args",label:"uri_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"post_args",label:"post_args",children:[{value:"default",label:"自定义",leaf:!0}]},{value:"json_post_args",label:"json_post_args",children:[{value:"default",label:"自定义",leaf:!0}]}],optionsModuleMatchKey:[{value:"web_engine_protection_result",label:"Web防护引擎",children:[{value:"sql_check",label:"SQL注入防护",leaf:!0},{value:"xss_check",label:"XSS防护",leaf:!0},{value:"cmd_exec_check",label:"命令执行防护",leaf:!0},{value:"code_exec_check",label:"代码执行防护",leaf:!0},{value:"webshell_update_check",label:"WebShell上传防护",leaf:!0},{value:"sensitive_file_check",label:"敏感文件泄露防护",leaf:!0},{value:"path_traversal_check",label:"路径穿越防护",leaf:!0},{value:"high_nday_check",label:"高危Nday防护",leaf:!0}]},{value:"web_rule_protection_result",label:"Web防护规则"}],moduleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],ruleSmallMatchs:[{rule_match_key_list:[],rule_match_key:"",showInput:!1}],ruleAction:[{value:"block",label:"阻断请求"},{value:"reject_response",label:"拒绝响应"},{value:"watch",label:"观察模式"},{value:"bot_check",label:"人机识别"}],optionsBotCheck:[{value:"standard",label:"标准"},{value:"slipper",label:"滑块"},{value:"image",label:"图片验证码"}],optionsDict:[],optionsNameList:[],custom_response:[],request_replace:[],response_replace:[],traffic_forward:[],action_value:"",propsMatchKey:{expandTrigger:"hover"},propsModuleMatchKey:{expandTrigger:"hover",lazy:!0,lazyLoad(e,t){if("web_rule_protection_result"==e.value){var a=[];Object(f["a"])("post","/waf/waf_get_web_rule_protection_list",{domain:w},(function(e){var l=e.data.message;l.length>0?l.forEach(e=>{a.push({label:e.rule_name,value:e.rule_name,leaf:!0})}):a.push({label:"无",value:"none",leaf:!0,disabled:!0}),t(a)}),(function(){}),"no-message")}}}}},computed:{rules(){return{rule_name:[{required:!0,message:"请输入规则名称",trigger:["blur","change"]},{validator:f["i"],trigger:["blur","change"]}],action_value:[{required:!0,message:"请选择匹配方式",trigger:"change"}],rule_action:[{required:!0,message:"请选择IP处罚方式",trigger:"change"}],statics_time:[{required:!0,message:"请输入大于0的数字",trigger:["blur","change"]},{validator:f["h"],trigger:["blur","change"]}],block_time:[{required:!0,message:"请输入大于0的数字",trigger:["blur","change"]},{validator:f["h"],trigger:["blur","change"]}],statics_count:[{required:!0,message:"请输入大于0的数字",trigger:["blur","change"]},{validator:f["h"],trigger:["blur","change"]}]}}},mounted(){var e=this;const t=Object(V["c"])();e.uuid=t.params.uuid,e.domain=t.params.domain,w=e.domain,e.loadingPage=!1,"new"!=e.uuid&&e.getData()},methods:{getData(){var e=this,t="/waf/waf_get_scan_attack_protection",a={domain:e.domain,rule_name:e.uuid};Object(f["a"])("post",t,a,(function(t){e.loadingPage=!1,e.scanAttackProForm=t.data.message,e.scanAttackProForm.rule_name=e.uuid;var a=JSON.parse(e.scanAttackProForm.statics_object),l=[],c=["query_string","json_post","post","cookie","waf_description","ctx","string"];for(var o in a){var r=a[o],n=r.key,s=r.value,u="false";c.indexOf(n)>-1&&(u="true"),l.push({rule_match_key_list:[n,s],rule_match_key:n+":"+s,showInput:u})}e.ruleSmallMatchs=l;var i=JSON.parse(e.scanAttackProForm.rule_module),d=[];for(var h in i){var m=i[h],b=m.key,_=m.value,p="false";d.push({rule_match_key_list:[b,_],rule_match_key:b+":"+_,showInput:p})}e.moduleSmallMatchs=d,e.action_value=e.scanAttackProForm.action_value}),(function(){e.loadingPage=!1}),"no-message")},onChangeRuleAction(){var e=this;e.action_value=""},onClickWebRuleProSubmit(e){var t=this,a=[],l=[];if(0==t.ruleSmallMatchs.length)return t.$message({message:"请选择统计对象",type:"error"}),!1;if(""==t.ruleSmallMatchs[0].rule_match_key)return t.$message({message:"请选择统计对象",type:"error"}),!1;if(0==t.moduleSmallMatchs.length)return t.$message({message:"请选择防护模块",type:"error"}),!1;if(""==t.moduleSmallMatchs[0].rule_match_key)return t.$message({message:"请选择防护模块",type:"error"}),!1;for(var c in t.ruleSmallMatchs){var o=t.ruleSmallMatchs[c],r="",n=[],s="",u="";o.rule_match_key&&(n=o.rule_match_key.split(":")),n.length>0&&(s=n[0],u=o.rule_match_key.replace(new RegExp(s+":"),""),r='{"key":"'+s+'" , "value":"'+u+'"}'),a.push(JSON.parse(r))}for(var i in t.moduleSmallMatchs){var d=t.moduleSmallMatchs[i],h="",m=[],b="",_="";d.rule_match_key&&(m=d.rule_match_key.split(":")),m.length>0&&(b=m[0],_=d.rule_match_key.replace(new RegExp(b+":"),""),h='{"key":"'+b+'" , "value":"'+_+'"}'),l.push(JSON.parse(h))}if("bot_check"==t.scanAttackProForm.rule_action&&""==t.action_value)return t.$message({message:"请选择人机识别方式",type:"error"}),!1;t.scanAttackProForm.domain=t.domain,t.scanAttackProForm.action_value=t.action_value;var p="/waf/waf_edit_scan_attack_protection";"new"==t.uuid?p="/waf/waf_create_scan_attack_protection":t.scanAttackProForm.rule_name=t.uuid,t.scanAttackProForm.statics_object=JSON.stringify(a),t.scanAttackProForm.rule_module=JSON.stringify(l),this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(f["a"])("post",p,t.scanAttackProForm,(function(e){t.loading=!1,window.location.href="/#/scan-attack-protection/"+t.domain}),(function(){t.loading=!1})))})},removeRuleMatchs(e){var t=this.ruleSmallMatchs.indexOf(e);-1!==t&&this.ruleSmallMatchs.splice(t,1)},addRuleMatchs(){this.ruleSmallMatchs.push({rule_match_key:"",showInput:!1})},onChangeRuleMatchs(e,t){if(e&&e.length>0){var a=this.ruleSmallMatchs.indexOf(t);"default"==e[1]?(this.ruleSmallMatchs[a].showInput=!0,this.ruleSmallMatchs[a].rule_match_key=e[0]+":"):this.ruleSmallMatchs[a].rule_match_key=e[0]+":"+e[1]}},onChangeRuleInput(e,t){var a=this.ruleSmallMatchs.indexOf(t);""==e?(this.ruleSmallMatchs[a].showInput=!1,this.ruleSmallMatchs[a].rule_match_key="",this.ruleSmallMatchs[a].rule_match_key_list=[]):this.ruleSmallMatchs[a].rule_match_key=e},removeModuleMatchs(e){var t=this.moduleSmallMatchs.indexOf(e);-1!==t&&this.moduleSmallMatchs.splice(t,1)},addModuleMatchs(){this.moduleSmallMatchs.push({rule_match_key:"",showInput:!1})},onChangeModuleMatchs(e,t){if(e&&e.length>0){var a=this.moduleSmallMatchs.indexOf(t);"default"==e[1]?(this.moduleSmallMatchs[a].showInput=!0,this.moduleSmallMatchs[a].rule_match_key=e[0]+":"):this.moduleSmallMatchs[a].rule_match_key=e[0]+":"+e[1]}}}},C=(a("7c80"),a("d959")),M=a.n(C);const x=M()(y,[["render",g]]);t["default"]=x},bfca:function(e,t,a){}}]);
//# sourceMappingURL=chunk-06814c0e.4c58a19e.js.map