(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-0ae0f898"],{"984d":function(e,t,l){"use strict";l.r(t);var o=l("7a23");const c={class:"flow-engine-wrap"},a=Object(o["createTextVNode"])("网站防护"),r=Object(o["createTextVNode"])("防护配置"),n=Object(o["createTextVNode"])("流量防护引擎"),d={class:"protection-block"},b={class:"protection-item-right"},i=Object(o["createVNode"])("div",{class:"protection-item-label"},"高频CC攻击防护",-1),u={key:0,class:"flow-engine-form"},m=Object(o["createVNode"])("span",null,"IP请求频率检测",-1),_=Object(o["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),j=Object(o["createVNode"])("div",{class:"margin-4x"},null,-1),O=Object(o["createVNode"])("span",null,"IP请求次数检测",-1),p=Object(o["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),s={class:"protection-block"},g={class:"protection-item-right"},f=Object(o["createVNode"])("div",{class:"protection-item-label"},"慢速CC攻击防护",-1),V={key:0,class:"flow-engine-form"},w=Object(o["createVNode"])("span",null,"请求IP数量检测",-1),k=Object(o["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),h=Object(o["createVNode"])("div",{class:"margin-4x"},null,-1),v=Object(o["createVNode"])("span",null,"回源保护机制",-1),N=Object(o["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),C={class:"protection-block"},x={class:"protection-item-right"},F=Object(o["createVNode"])("div",{class:"protection-item-label"},"无差别紧急防护",-1),B={key:0,class:"flow-engine-form"},E=Object(o["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),y=Object(o["createTextVNode"])("保存");function q(e,t,l,q,U,L){const P=Object(o["resolveComponent"])("el-breadcrumb-item"),A=Object(o["resolveComponent"])("el-breadcrumb"),D=Object(o["resolveComponent"])("el-row"),T=Object(o["resolveComponent"])("el-switch"),I=Object(o["resolveComponent"])("el-input"),J=Object(o["resolveComponent"])("el-form-item"),S=Object(o["resolveComponent"])("el-option"),$=Object(o["resolveComponent"])("el-select"),z=Object(o["resolveComponent"])("el-card"),G=Object(o["resolveComponent"])("el-form"),H=Object(o["resolveComponent"])("el-col"),K=Object(o["resolveComponent"])("el-button"),M=Object(o["resolveDirective"])("loading");return Object(o["openBlock"])(),Object(o["createBlock"])("div",c,[Object(o["createVNode"])(D,{class:"breadcrumb-style"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(A,{separator:"/"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(P,{to:{path:"/"}},{default:Object(o["withCtx"])(()=>[a]),_:1}),Object(o["createVNode"])(P,{to:{path:"/protection/"+U.domain}},{default:Object(o["withCtx"])(()=>[r]),_:1},8,["to"]),Object(o["createVNode"])(P,null,{default:Object(o["withCtx"])(()=>[n]),_:1})]),_:1})]),_:1}),Object(o["createVNode"])(D,{class:"container-style"},{default:Object(o["withCtx"])(()=>[Object(o["withDirectives"])(Object(o["createVNode"])(H,{span:24},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(G,{model:U.flowEngineForm,rules:L.rules,ref:"flowEngineForm","label-width":"200px"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",d,[Object(o["createVNode"])("div",b,[i,Object(o["createVNode"])(T,{modelValue:U.flowEngineForm.high_freq_cc_check,"onUpdate:modelValue":t[1]||(t[1]=e=>U.flowEngineForm.high_freq_cc_check=e),"active-text":"开启","inactive-text":"关闭","active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),"true"==U.flowEngineForm.high_freq_cc_check?(Object(o["openBlock"])(),Object(o["createBlock"])("div",u,[Object(o["createVNode"])(z,{class:"box-card"},{header:Object(o["withCtx"])(()=>[m]),default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",null,[Object(o["createVNode"])(J,{label:"请求频率限制",prop:"req_rate"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(I,{modelValue:U.flowEngineForm.req_rate,"onUpdate:modelValue":t[2]||(t[2]=e=>U.flowEngineForm.req_rate=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(J,{label:"执行动作"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.req_rate_block_mode,"onUpdate:modelValue":t[3]||(t[3]=e=>U.flowEngineForm.req_rate_block_mode=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.ruleAction,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==U.flowEngineForm.req_rate_block_mode?(Object(o["openBlock"])(),Object(o["createBlock"])(J,{key:0},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.req_rate_block_mode_extra_parameter,"onUpdate:modelValue":t[4]||(t[4]=e=>U.flowEngineForm.req_rate_block_mode_extra_parameter=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.optionsBotCheck,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),_]),_:1})):Object(o["createCommentVNode"])("",!0)])]),_:1}),j,Object(o["createVNode"])(z,{class:"box-card"},{header:Object(o["withCtx"])(()=>[O]),default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",null,[Object(o["createVNode"])(J,{label:"请求次数限制",prop:"req_rate"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(I,{modelValue:U.flowEngineForm.req_count,"onUpdate:modelValue":t[5]||(t[5]=e=>U.flowEngineForm.req_count=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(J,{label:"统计时间（秒）",prop:"req_count_stat_time_period"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(I,{modelValue:U.flowEngineForm.req_count_stat_time_period,"onUpdate:modelValue":t[6]||(t[6]=e=>U.flowEngineForm.req_count_stat_time_period=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(J,{label:"执行动作"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.req_count_block_mode,"onUpdate:modelValue":t[7]||(t[7]=e=>U.flowEngineForm.req_count_block_mode=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.ruleAction,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==U.flowEngineForm.req_count_block_mode?(Object(o["openBlock"])(),Object(o["createBlock"])(J,{key:0},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.req_count_block_mode_extra_parameter,"onUpdate:modelValue":t[8]||(t[8]=e=>U.flowEngineForm.req_count_block_mode_extra_parameter=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.optionsBotCheck,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),p]),_:1})):Object(o["createCommentVNode"])("",!0)])]),_:1})])):Object(o["createCommentVNode"])("",!0)]),Object(o["createVNode"])("div",s,[Object(o["createVNode"])("div",g,[f,Object(o["createVNode"])(T,{modelValue:U.flowEngineForm.slow_cc_check,"onUpdate:modelValue":t[9]||(t[9]=e=>U.flowEngineForm.slow_cc_check=e),"active-text":"开启","inactive-text":"关闭","active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),"true"==U.flowEngineForm.slow_cc_check?(Object(o["openBlock"])(),Object(o["createBlock"])("div",V,[Object(o["createVNode"])(z,{class:"box-card"},{header:Object(o["withCtx"])(()=>[w]),default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",null,[Object(o["createVNode"])(J,{label:"请求IP数量限制",prop:"ip_count"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(I,{modelValue:U.flowEngineForm.ip_count,"onUpdate:modelValue":t[10]||(t[10]=e=>U.flowEngineForm.ip_count=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(J,{label:"统计时间（秒）",prop:"ip_count_stat_time_period"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(I,{modelValue:U.flowEngineForm.ip_count_stat_time_period,"onUpdate:modelValue":t[11]||(t[11]=e=>U.flowEngineForm.ip_count_stat_time_period=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(J,{label:"执行动作"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.ip_count_block_mode,"onUpdate:modelValue":t[12]||(t[12]=e=>U.flowEngineForm.ip_count_block_mode=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.ruleAction,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==U.flowEngineForm.ip_count_block_mode?(Object(o["openBlock"])(),Object(o["createBlock"])(J,{key:0},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.ip_count_block_mode_extra_parameter,"onUpdate:modelValue":t[13]||(t[13]=e=>U.flowEngineForm.ip_count_block_mode_extra_parameter=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.optionsBotCheck,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),k]),_:1})):Object(o["createCommentVNode"])("",!0)])]),_:1}),h,Object(o["createVNode"])(z,{class:"box-card"},{header:Object(o["withCtx"])(()=>[v]),default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",null,[Object(o["createVNode"])(J,{label:"回源请求频率限制",prop:"domain_rate"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(I,{modelValue:U.flowEngineForm.domain_rate,"onUpdate:modelValue":t[14]||(t[14]=e=>U.flowEngineForm.domain_rate=e),placeholder:"请输入"},null,8,["modelValue"])]),_:1}),Object(o["createVNode"])(J,{label:"执行动作"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.slow_cc_block_mode,"onUpdate:modelValue":t[15]||(t[15]=e=>U.flowEngineForm.slow_cc_block_mode=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.ruleAction,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==U.flowEngineForm.slow_cc_block_mode?(Object(o["openBlock"])(),Object(o["createBlock"])(J,{key:0},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.slow_cc_block_mode_extra_parameter,"onUpdate:modelValue":t[16]||(t[16]=e=>U.flowEngineForm.slow_cc_block_mode_extra_parameter=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.optionsBotCheck,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),N]),_:1})):Object(o["createCommentVNode"])("",!0)])]),_:1})])):Object(o["createCommentVNode"])("",!0)]),Object(o["createVNode"])("div",C,[Object(o["createVNode"])("div",x,[F,Object(o["createVNode"])(T,{modelValue:U.flowEngineForm.emergency_mode_check,"onUpdate:modelValue":t[17]||(t[17]=e=>U.flowEngineForm.emergency_mode_check=e),"active-text":"开启","inactive-text":"关闭","active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),"true"==U.flowEngineForm.emergency_mode_check?(Object(o["openBlock"])(),Object(o["createBlock"])("div",B,[Object(o["createVNode"])(z,{class:"box-card"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("div",null,[Object(o["createVNode"])(J,{label:"执行动作"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.emergency_mode_block_mode,"onUpdate:modelValue":t[18]||(t[18]=e=>U.flowEngineForm.emergency_mode_block_mode=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.ruleAction,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==U.flowEngineForm.emergency_mode_block_mode?(Object(o["openBlock"])(),Object(o["createBlock"])(J,{key:0},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])($,{modelValue:U.flowEngineForm.emergency_mode_block_mode_extra_parameter,"onUpdate:modelValue":t[19]||(t[19]=e=>U.flowEngineForm.emergency_mode_block_mode_extra_parameter=e),placeholder:"请选择"},{default:Object(o["withCtx"])(()=>[(Object(o["openBlock"])(!0),Object(o["createBlock"])(o["Fragment"],null,Object(o["renderList"])(U.optionsBotCheck,e=>(Object(o["openBlock"])(),Object(o["createBlock"])(S,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),E]),_:1})):Object(o["createCommentVNode"])("",!0)])]),_:1})])):Object(o["createCommentVNode"])("",!0)])]),_:1},8,["model","rules"]),Object(o["createVNode"])(D,{type:"flex",justify:"space-between",class:"margin-no-border"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(H,{span:12},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])("a",{class:"el-button el-button--primary is-plain",href:"/#/protection/"+U.domain},"返回",8,["href"])]),_:1}),Object(o["createVNode"])(H,{span:12,class:"text-align-right"},{default:Object(o["withCtx"])(()=>[Object(o["createVNode"])(K,{type:"primary",onClick:t[20]||(t[20]=e=>L.onClickFlowEngineSubmit("flowEngineForm")),loading:U.loading},{default:Object(o["withCtx"])(()=>[y]),_:1},8,["loading"])]),_:1})]),_:1})]),_:1},512),[[M,U.loadingPage,void 0,{fullscreen:!0,lock:!0}]])]),_:1})])}var U=l("362c"),L=l("6c02"),P={mixins:[U["c"]],data(){return{loading:!1,loadingPage:!1,domain:"",ruleType:"",flowEngineForm:{},ruleAction:[{value:"block",label:"阻断请求"},{value:"reject_response",label:"拒绝响应"},{value:"bot_check",label:"人机识别"},{value:"watch",label:"观察模式"}],optionsBotCheck:[{value:"standard",label:"标准"},{value:"slipper",label:"滑块"},{value:"image",label:"图片验证码"}]}},computed:{rules(){return{eq_rate:[{required:!0,message:"请输入",trigger:["blur","change"]},{validator:U["g"],trigger:["blur","change"]}],req_count:[{required:!0,message:"请输入",trigger:["blur","change"]},{validator:U["g"],trigger:["blur","change"]}],req_count_stat_time_period:[{required:!0,message:"请输入",trigger:["blur","change"]},{validator:U["g"],trigger:["blur","change"]}],ip_count:[{required:!0,message:"请输入",trigger:["blur","change"]},{validator:U["g"],trigger:["blur","change"]}],ip_count_stat_time_period:[{required:!0,message:"请输入",trigger:["blur","change"]},{validator:U["g"],trigger:["blur","change"]}],domain_rate:[{required:!0,message:"请输入",trigger:["blur","change"]},{validator:U["g"],trigger:["blur","change"]}]}}},mounted(){const e=Object(L["c"])();this.domain=e.params.domain,this.getData()},methods:{getData(){var e=this,t="/waf/waf_get_flow_engine_protection",l={domain:e.domain};Object(U["a"])("post",t,l,(function(t){e.loadingPage=!1,e.flowEngineForm=t.data.message,e.flowEngineForm.domain=e.domain}),(function(){e.loadingPage=!1}),"no-message")},onClickFlowEngineSubmit(e){var t=this,l="/waf/waf_edit_flow_engine_protection";this.flowEngineForm.domain=t.domain,this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(U["a"])("post",l,t.flowEngineForm,(function(e){t.loading=!1,t.getData()}),(function(){t.loading=!1})))})}}},A=(l("bbb7"),l("d959")),D=l.n(A);const T=D()(P,[["render",q]]);t["default"]=T},a7a6:function(e,t,l){},bbb7:function(e,t,l){"use strict";l("a7a6")}}]);
//# sourceMappingURL=chunk-0ae0f898.a8bbef0b.js.map