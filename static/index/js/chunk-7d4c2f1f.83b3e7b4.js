(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-7d4c2f1f"],{"25f0":function(e,t,o){"use strict";var n=o("6eeb"),a=o("825a"),r=o("577e"),c=o("d039"),i=o("ad6d"),l="toString",u=RegExp.prototype,s=u[l],d=c((function(){return"/a/b"!=s.call({source:"a",flags:"b"})})),f=s.name!=l;(d||f)&&n(RegExp.prototype,l,(function(){var e=a(this),t=r(e.source),o=e.flags,n=r(void 0===o&&e instanceof RegExp&&!("flags"in u)?i.call(e):o);return"/"+t+"/"+n}),{unsafe:!0})},3823:function(e,t,o){},c221:function(e,t,o){"use strict";o.r(t);var n=o("7a23"),a={class:"page-owasp-wrap"},r=Object(n["createVNode"])("h3",null,"基础配置",-1),c=Object(n["createVNode"])("div",{class:"margin-4x"},null,-1),i=Object(n["createVNode"])("div",{class:"margin-4x"},null,-1),l=Object(n["createTextVNode"])("保存");function u(e,t){var o=Object(n["resolveComponent"])("el-col"),u=Object(n["resolveComponent"])("el-row"),s=Object(n["resolveComponent"])("el-divider"),d=Object(n["resolveComponent"])("el-input"),f=Object(n["resolveComponent"])("el-form-item"),b=Object(n["resolveComponent"])("el-button"),g=Object(n["resolveComponent"])("el-switch"),p=Object(n["resolveComponent"])("el-form"),j=Object(n["resolveDirective"])("loading");return Object(n["openBlock"])(),Object(n["createBlock"])("div",a,[Object(n["createVNode"])(u,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:24},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(u,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:12},{default:Object(n["withCtx"])((function(){return[r]})),_:1})]})),_:1})]})),_:1})]})),_:1}),Object(n["createVNode"])(s),c,Object(n["withDirectives"])(Object(n["createVNode"])(u,null,{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:24},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(p,{model:e.baseConfigForm,rules:e.rules,ref:"baseConfigForm","label-width":"160px"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(f,{label:"API_KEY",prop:"api_key",key:"1"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(d,{modelValue:e.baseConfigForm.api_key,"onUpdate:modelValue":t[1]||(t[1]=function(t){return e.baseConfigForm.api_key=t}),placeholder:"请输入API_KEY",disabled:""},null,8,["modelValue"])]})),_:1}),Object(n["createVNode"])(f,{label:"API_PASSWORD",prop:"api_password",key:"2"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(d,{modelValue:e.baseConfigForm.api_password,"onUpdate:modelValue":t[2]||(t[2]=function(t){return e.baseConfigForm.api_password=t}),placeholder:"请输入API_PASSWORD",class:"global-pwd"},null,8,["modelValue"]),Object(n["createVNode"])(b,{icon:"el-icon-refresh",onClick:e.onClickRefresh},null,8,["onClick"])]})),_:1}),Object(n["createVNode"])(f,{label:"JXWAF账号登陆",key:"3"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(g,{modelValue:e.baseConfigForm.jxwaf_login,"onUpdate:modelValue":t[3]||(t[3]=function(t){return e.baseConfigForm.jxwaf_login=t}),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]})),_:1}),"true"==e.baseConfigForm.jxwaf_login?(Object(n["openBlock"])(),Object(n["createBlock"])(f,{label:"JXWAF账号TOKEN",prop:"jxwaf_login_token",key:"4"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(d,{modelValue:e.baseConfigForm.jxwaf_login_token,"onUpdate:modelValue":t[4]||(t[4]=function(t){return e.baseConfigForm.jxwaf_login_token=t}),placeholder:"请输入JXWAF账号TOKEN"},null,8,["modelValue"])]})),_:1})):Object(n["createCommentVNode"])("",!0),Object(n["createVNode"])(f,{label:"网络连接代理",key:"5"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(g,{modelValue:e.baseConfigForm.proxie,"onUpdate:modelValue":t[5]||(t[5]=function(t){return e.baseConfigForm.proxie=t}),"active-value":"true","inactive-value":"false"},null,8,["modelValue"])]})),_:1}),"true"==e.baseConfigForm.proxie?(Object(n["openBlock"])(),Object(n["createBlock"])(f,{label:"代理地址",prop:"proxie_site",key:"6"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(d,{modelValue:e.baseConfigForm.proxie_site,"onUpdate:modelValue":t[6]||(t[6]=function(t){return e.baseConfigForm.proxie_site=t}),placeholder:"请输入代理地址"},null,8,["modelValue"])]})),_:1})):Object(n["createCommentVNode"])("",!0)]})),_:1},8,["model","rules"]),i,Object(n["createVNode"])(u,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:24},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(u,{type:"flex",class:"row-bg",justify:"space-between"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{span:12}),Object(n["createVNode"])(o,{span:12,class:"text-align-right"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(b,{type:"primary",onClick:t[7]||(t[7]=function(t){return e.onClickBaseConfigSubmit("baseConfigForm")}),loading:e.loading},{default:Object(n["withCtx"])((function(){return[l]})),_:1},8,["loading"])]})),_:1})]})),_:1})]})),_:1})]})),_:1})]})),_:1})]})),_:1},512),[[j,e.loadingPage,void 0,{fullscreen:!0,lock:!0}]])])}o("d3b7"),o("25f0");var s=o("362c"),d={mixins:[s["b"]],data:function(){return{loadingPage:!1,loading:!1,baseConfigForm:{}}},computed:{rules:function(){return{api_password:[{required:!0,message:"请输入API_PASSWORD",trigger:["blur","change"]}],api_key:[{required:!0,message:"请输入API_KEY",trigger:["blur","change"]}],jxwaf_login_token:[{required:!0,message:"请输入JXWAF账号TOKEN",trigger:["blur","change"]}],proxie_site:[{required:!0,message:"请输入代理地址",trigger:["blur","change"]}]}}},mounted:function(){this.getData()},methods:{getData:function(){var e=this,t="/waf/waf_get_sys_base_conf";Object(s["a"])("post",t,{},(function(t){e.loadingPage=!1,e.baseConfigForm=t.data.message}),(function(){e.loadingPage=!1}),"no-message")},onClickBaseConfigSubmit:function(e){var t=this,o="/waf/waf_edit_sys_base_conf";this.$refs[e].validate((function(e){e&&(t.loading=!0,Object(s["a"])("post",o,t.baseConfigForm,(function(e){t.loading=!1,t.getData()}),(function(){t.loading=!1})))}))},onClickRefresh:function(){function e(){return(65536*(1+Math.random())|0).toString(16).substring(1)}function t(){return e()+e()+"-"+e()+"-"+e()+"-"+e()+"-"+e()+e()+e()}this.baseConfigForm.api_password=t()}}};o("e1d6");d.render=u;t["default"]=d},e1d6:function(e,t,o){"use strict";o("3823")}}]);
//# sourceMappingURL=chunk-7d4c2f1f.83b3e7b4.js.map