(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-599944d2"],{"0253":function(e,t,o){},"72a2":function(e,t,o){"use strict";o("0253")},9531:function(e,t,o){"use strict";o.r(t);var a=o("7a23");const l={class:"web-deny-page-wrap"},c=Object(a["createVNode"])("h3",null,"流量攻击拦截页面",-1),r=Object(a["createVNode"])("div",{class:"margin-4x"},null,-1),n=Object(a["createTextVNode"])("无响应内容"),d=Object(a["createTextVNode"])("HTML响应内容"),i=Object(a["createVNode"])("div",{class:"margin-4x"},null,-1),b=Object(a["createTextVNode"])("保存 ");function s(e,t,o,s,u,p){const j=Object(a["resolveComponent"])("el-col"),w=Object(a["resolveComponent"])("el-row"),O=Object(a["resolveComponent"])("el-divider"),f=Object(a["resolveComponent"])("el-input"),m=Object(a["resolveComponent"])("el-form-item"),g=Object(a["resolveComponent"])("el-radio"),_=Object(a["resolveComponent"])("el-radio-group"),h=Object(a["resolveComponent"])("el-form"),y=Object(a["resolveComponent"])("el-card"),C=Object(a["resolveComponent"])("el-button");return Object(a["openBlock"])(),Object(a["createBlock"])("div",l,[Object(a["createVNode"])(w,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(j,{span:24},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(w,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(j,{span:12},{default:Object(a["withCtx"])(()=>[c]),_:1}),Object(a["createVNode"])(j,{span:12,class:"text-align-right"},{default:Object(a["withCtx"])(()=>["group_rule"==u.ruleType?(Object(a["openBlock"])(),Object(a["createBlock"])("a",{key:0,class:"el-button el-button--primary is-plain",href:"/#/group-protection/"+u.domain},"返回",8,["href"])):(Object(a["openBlock"])(),Object(a["createBlock"])("a",{key:1,class:"el-button el-button--primary is-plain",href:"/#/protection/"+u.domain+"/"+u.ruleType},"返回",8,["href"]))]),_:1})]),_:1})]),_:1})]),_:1}),Object(a["createVNode"])(O),Object(a["createVNode"])(w,null,{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(j,{span:24},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(y,{class:"box-card"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])("div",null,[r,Object(a["createVNode"])(h,{model:u.flowDenyPageForm,"label-width":"120px",rules:p.rules,ref:"flowDenyPageForm"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(m,{label:"HTTP响应码",prop:"owasp_code",key:"1"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(f,{modelValue:u.flowDenyPageForm.owasp_code,"onUpdate:modelValue":t[1]||(t[1]=e=>u.flowDenyPageForm.owasp_code=e),placeholder:"请输入100~600的响应码"},null,8,["modelValue"])]),_:1}),Object(a["createVNode"])(m,{label:"响应内容"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(_,{modelValue:u.radioContent,"onUpdate:modelValue":t[2]||(t[2]=e=>u.radioContent=e)},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(g,{label:0},{default:Object(a["withCtx"])(()=>[n]),_:1}),Object(a["createVNode"])(g,{label:1},{default:Object(a["withCtx"])(()=>[d]),_:1})]),_:1},8,["modelValue"])]),_:1}),Object(a["withDirectives"])(Object(a["createVNode"])(m,null,{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(f,{modelValue:u.flowDenyPageForm.owasp_html,"onUpdate:modelValue":t[3]||(t[3]=e=>u.flowDenyPageForm.owasp_html=e),type:"textarea",autosize:{minRows:10}},null,8,["modelValue"])]),_:1},512),[[a["vShow"],1==u.radioContent]])]),_:1},8,["model","rules"])])]),_:1}),i,Object(a["createVNode"])(w,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(j,{span:24},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(w,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(j,{span:12},{default:Object(a["withCtx"])(()=>["group_rule"==u.ruleType?(Object(a["openBlock"])(),Object(a["createBlock"])("a",{key:0,class:"el-button el-button--primary is-plain",href:"/#/group-protection/"+u.domain},"返回",8,["href"])):(Object(a["openBlock"])(),Object(a["createBlock"])("a",{key:1,class:"el-button el-button--primary is-plain",href:"/#/protection/"+u.domain+"/"+u.ruleType},"返回",8,["href"]))]),_:1}),Object(a["createVNode"])(j,{span:12,class:"text-align-right"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(C,{type:"primary",onClick:t[4]||(t[4]=e=>p.onClickFlowDenyPageSubmit("flowDenyPageForm")),loading:u.loading},{default:Object(a["withCtx"])(()=>[b]),_:1},8,["loading"])]),_:1})]),_:1})]),_:1})]),_:1})]),_:1})]),_:1})])}var u=o("362c"),p=o("6c02"),j={mixins:[u["b"]],data(){return{validateCode:(e,t,o)=>{t<100||t>600?o(new Error("请输入100~600的响应码")):o()},loading:!1,domain:"",ruleType:"single_rule",flowDenyPageForm:{owasp_code:403,owasp_html:""},radioContent:0}},computed:{rules(){return{owasp_code:[{required:!0,message:"请输入100~600的响应码",trigger:["blur","change"]},{validator:this.validateCode,trigger:"blur"}]}}},mounted(){const e=Object(p["c"])();this.ruleType=e.params.ruleType,this.domain=e.params.domain,this.getData()},methods:{getData(){var e=this,t="/waf/waf_get_flow_deny_page",o={domain:e.domain};"group_rule"==e.ruleType&&(t="/waf/waf_get_group_flow_deny_page",o={group_id:e.domain}),Object(u["a"])("post",t,o,(function(t){e.flowDenyPageForm=t.data.message,e.flowDenyPageForm.owasp_html?e.radioContent=1:e.radioContent=0}),(function(){}),"no-message")},onClickFlowDenyPageSubmit(e){var t=this,o="/waf/waf_edit_flow_deny_page";"group_rule"==t.ruleType?(o="/waf/waf_edit_group_flow_deny_page",t.webDenyPageForm.group_id=t.domain):t.webDenyPageForm.domain=t.domain,this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(u["a"])("post",o,t.flowDenyPageForm,(function(e){t.loading=!1,t.getData()}),(function(){t.loading=!1})))})}}},w=(o("72a2"),o("d959")),O=o.n(w);const f=O()(j,[["render",s]]);t["default"]=f}}]);
//# sourceMappingURL=chunk-599944d2.9ee1f147.js.map