(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-2d870016"],{"4a68":function(e,t,o){},a463:function(e,t,o){"use strict";o("4a68")},d462:function(e,t,o){"use strict";o.r(t);var c=o("7a23");const l={class:"page-owasp-wrap"},a=Object(c["createTextVNode"])("网站防护"),n=Object(c["createTextVNode"])("防护配置"),i=Object(c["createTextVNode"])("IP区域封禁"),r=Object(c["createTextVNode"])("全选"),d=Object(c["createVNode"])("p",{class:"form-info-color"}," 说明：标准模式无需人机交互 ",-1),b=Object(c["createTextVNode"])("保存");function s(e,t,o,s,u,h){const m=Object(c["resolveComponent"])("el-breadcrumb-item"),j=Object(c["resolveComponent"])("el-breadcrumb"),O=Object(c["resolveComponent"])("el-row"),k=Object(c["resolveComponent"])("el-switch"),p=Object(c["resolveComponent"])("el-form-item"),g=Object(c["resolveComponent"])("el-checkbox"),f=Object(c["resolveComponent"])("el-tab-pane"),w=Object(c["resolveComponent"])("el-tabs"),C=Object(c["resolveComponent"])("el-tag"),v=Object(c["resolveComponent"])("el-option"),_=Object(c["resolveComponent"])("el-select"),V=Object(c["resolveComponent"])("el-form"),B=Object(c["resolveComponent"])("el-col"),N=Object(c["resolveComponent"])("el-button"),y=Object(c["resolveDirective"])("loading");return Object(c["openBlock"])(),Object(c["createBlock"])("div",l,[Object(c["createVNode"])(O,{class:"breadcrumb-style"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(j,{separator:"/"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(m,{to:{path:"/"}},{default:Object(c["withCtx"])(()=>[a]),_:1}),Object(c["createVNode"])(m,{to:{path:"/protection/"+u.domain}},{default:Object(c["withCtx"])(()=>[n]),_:1},8,["to"]),Object(c["createVNode"])(m,null,{default:Object(c["withCtx"])(()=>[i]),_:1})]),_:1})]),_:1}),Object(c["createVNode"])(O,{class:"container-style"},{default:Object(c["withCtx"])(()=>[Object(c["withDirectives"])(Object(c["createVNode"])(B,{span:24},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])("div",null,[Object(c["createVNode"])(V,{model:u.flowIpRegionBlockForm,rules:h.rules,ref:"flowIpRegionBlockForm","label-width":"180px",class:"flow-ip-region-block-form","label-position":"left"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(p,{label:"IP区域封禁状态"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(k,{modelValue:u.flowIpRegionBlockForm.ip_region_block,"onUpdate:modelValue":t[1]||(t[1]=e=>u.flowIpRegionBlockForm.ip_region_block=e),"active-text":"开启","inactive-text":"关闭","active-value":"true","inactive-value":"false"},null,8,["modelValue"])]),_:1}),Object(c["withDirectives"])(Object(c["createVNode"])("div",null,[Object(c["createVNode"])(p,{label:"白名单区域"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(g,{modelValue:u.checkAll,"onUpdate:modelValue":t[2]||(t[2]=e=>u.checkAll=e),onChange:h.handleCheckAllChange},{default:Object(c["withCtx"])(()=>[r]),_:1},8,["modelValue","onChange"]),Object(c["createVNode"])(w,{modelValue:u.activeName,"onUpdate:modelValue":t[3]||(t[3]=e=>u.activeName=e),class:"geoip-select-country"},{default:Object(c["withCtx"])(()=>[(Object(c["openBlock"])(!0),Object(c["createBlock"])(c["Fragment"],null,Object(c["renderList"])(u.countries,(e,t)=>(Object(c["openBlock"])(),Object(c["createBlock"])(f,{label:t,name:t,key:t},{default:Object(c["withCtx"])(()=>[(Object(c["openBlock"])(!0),Object(c["createBlock"])(c["Fragment"],null,Object(c["renderList"])(e,(e,t)=>(Object(c["openBlock"])(),Object(c["createBlock"])("dl",{key:t},[Object(c["createVNode"])("dt",null,Object(c["toDisplayString"])(t),1),Object(c["createVNode"])("dd",null,[(Object(c["openBlock"])(!0),Object(c["createBlock"])(c["Fragment"],null,Object(c["renderList"])(e,e=>(Object(c["openBlock"])(),Object(c["createBlock"])(g,{label:e.name,key:e.code,onChange:t=>h.selectCountry(t,e),modelValue:e.checked,"onUpdate:modelValue":t=>e.checked=t,class:"country-"+e.code},{default:Object(c["withCtx"])(()=>[Object(c["createTextVNode"])(Object(c["toDisplayString"])(e.name),1)]),_:2},1032,["label","onChange","modelValue","onUpdate:modelValue","class"]))),128))])]))),128))]),_:2},1032,["label","name"]))),128))]),_:1},8,["modelValue"])]),_:1}),Object(c["withDirectives"])(Object(c["createVNode"])(p,{label:"白名单区域"},{default:Object(c["withCtx"])(()=>[(Object(c["openBlock"])(!0),Object(c["createBlock"])(c["Fragment"],null,Object(c["renderList"])(u.blackCountryList,e=>(Object(c["openBlock"])(),Object(c["createBlock"])(C,{key:e.code,closable:"",onClose:t=>h.handleClose(e)},{default:Object(c["withCtx"])(()=>[Object(c["createTextVNode"])(Object(c["toDisplayString"])(e.name),1)]),_:2},1032,["onClose"]))),128))]),_:1},512),[[c["vShow"],u.blackCountryList.length>0]])],512),[[c["vShow"],"true"==u.flowIpRegionBlockForm.ip_region_block]]),Object(c["createVNode"])(p,{label:"执行动作",prop:"block_action"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(_,{modelValue:u.flowIpRegionBlockForm.block_action,"onUpdate:modelValue":t[4]||(t[4]=e=>u.flowIpRegionBlockForm.block_action=e),placeholder:"请选择",onChange:t[5]||(t[5]=e=>h.onChangeRuleAction())},{default:Object(c["withCtx"])(()=>[(Object(c["openBlock"])(!0),Object(c["createBlock"])(c["Fragment"],null,Object(c["renderList"])(u.ruleAction,e=>(Object(c["openBlock"])(),Object(c["createBlock"])(v,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1}),"bot_check"==u.flowIpRegionBlockForm.block_action?(Object(c["openBlock"])(),Object(c["createBlock"])(p,{key:0},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(_,{modelValue:u.action_value,"onUpdate:modelValue":t[6]||(t[6]=e=>u.action_value=e),placeholder:"请选择"},{default:Object(c["withCtx"])(()=>[(Object(c["openBlock"])(!0),Object(c["createBlock"])(c["Fragment"],null,Object(c["renderList"])(u.optionsBotCheck,e=>(Object(c["openBlock"])(),Object(c["createBlock"])(v,{key:e.value,label:e.label,value:e.value},null,8,["label","value"]))),128))]),_:1},8,["modelValue"]),d]),_:1})):Object(c["createCommentVNode"])("",!0)]),_:1},8,["model","rules"])]),Object(c["createVNode"])(O,{type:"flex",class:"margin-border",justify:"space-between"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(B,{span:12},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])("a",{class:"el-button el-button--primary is-plain",href:"/#/protection/"+u.domain},"返回",8,["href"])]),_:1}),Object(c["createVNode"])(B,{span:12,class:"text-align-right"},{default:Object(c["withCtx"])(()=>[Object(c["createVNode"])(N,{type:"primary",onClick:t[7]||(t[7]=e=>h.onClickflowIpRegionBlockFormSubmit("flowIpRegionBlockForm")),loading:u.loading},{default:Object(c["withCtx"])(()=>[b]),_:1},8,["loading"])]),_:1})]),_:1})]),_:1},512),[[y,u.loadingPage,void 0,{fullscreen:!0,lock:!0}]])]),_:1})])}var u=o("362c"),h=o("6c02");const m=o("6680"),j={0:/^[A-C]$/i,1:/^[D-F]$/i,2:/^[G-I]$/i,3:/^[J-L]$/i,4:/^[M-N]$/i,5:/^[O-Q]$/i,6:/^[R-T]$/i,7:/^[U-W]$/i,8:/^[X-Z]$/i};var O={mixins:[u["c"]],data(){return{loadingPage:!1,loading:!1,domain:this.$route.params.domain,flowIpRegionBlockForm:{},ruleAction:[{value:"block",label:"阻断请求"},{value:"reject_response",label:"拒绝响应"},{value:"watch",label:"观察模式"},{value:"bot_check",label:"人机识别"}],optionsBotCheck:[{value:"standard",label:"标准"},{value:"slipper",label:"滑块"},{value:"image",label:"图片验证码"}],data:m,countries:{},activeName:"ABC",blackCountryList:[],geoipForm:{},action_value:"",checkAll:!1}},computed:{rules(){return{action_value:[{required:!0,message:"请选择",trigger:"change"}],block_action:[{required:!0,message:"请选择执行动作",trigger:"change"}]}}},mounted(){const e=Object(h["c"])();this.domain=e.params.domain,this.getData(),this.formatCountry()},methods:{getData(){var e=this,t="/waf/waf_get_flow_ip_region_block",o={domain:e.domain};e.blackCountryList=[],Object(u["a"])("post",t,o,(function(t){e.loadingPage=!1,e.flowIpRegionBlockForm=t.data.message,"bot_check"==e.flowIpRegionBlockForm.block_action&&(e.action_value=e.flowIpRegionBlockForm.action_value),e.stringToArr(e.flowIpRegionBlockForm.region_white_list)}),(function(){e.loadingPage=!1}),"no-message")},onChangeRuleAction(){var e=this;e.action_value=""},onClickflowIpRegionBlockFormSubmit(e){var t=this,o="/waf/waf_edit_flow_ip_region_block";this.flowIpRegionBlockForm.domain=t.domain,this.flowIpRegionBlockForm.region_white_list=t.jsonToArr(t.blackCountryList),"bot_check"!=t.flowIpRegionBlockForm.block_action?t.flowIpRegionBlockForm.action_value="":t.flowIpRegionBlockForm.action_value=t.action_value,this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(u["a"])("post",o,t.flowIpRegionBlockForm,(function(e){t.loading=!1,window.location.href="/#/flow-ip-region-block/"+t.domain}),(function(){t.loading=!1})))})},formatCountry(){let e={ABC:{},DEF:{},GHI:{},JKL:{},MN:{},OPQ:{},RST:{},UVW:{},XYZ:{}},t=Object.keys(e),o="";this.data.forEach((c,l)=>{o=this.getInitial(c);for(var a=0;a<t.length;a++)if(j[a].test(o)){e[t[a]][o]||(e[t[a]][o]=[]),this.pushCountries(e[t[a]][o],c);break}}),this.countries=e},getInitial(e){let t="";return t=e.cnSpell.substr(0,1),t},pushCountries(e,t){this.checkAll?e.push({name:t.cnName,code:t.code,checked:!0}):e.push({name:t.cnName,code:t.code,checked:!1})},selectCountry(e,t){if(1==e)t.checked=!0,this.blackCountryList.push(t);else{t.checked=!1;for(var o=0;o<this.blackCountryList.length;o++)if(this.blackCountryList[o].code==t.code){this.blackCountryList.splice(o,1);break}}this.blackCountryList.length==this.data.length?this.checkAll=!0:this.checkAll=!1},handleClose(e){let t=window.scrollY;document.querySelector(".country-"+e.code).click(),window.scrollTo(0,t)},handleAdd(e){let t=window.scrollY;document.querySelector(".country-"+e.code).click(),window.scrollTo(0,t)},handleCheckAllChange(e){this.blackCountryList=[];for(var t=0;t<this.data.length;t++){var o={};o.code=this.data[t].code,o.name=this.data[t].cnName,this.selectCountry(e,o)}this.formatCountry()},jsonToArr(e){let t=[];return e.forEach((e,o)=>{t.push(e.code)}),t},arrToString(e){let t="";return e.forEach(e=>{t=t+"|"+e.code}),t=t.substr(1),t},stringToArr(e){let t=this,o=e||[];this.data.forEach((e,c)=>{for(var l=0;l<o.length;l++){var a={};if(e.code==o[l]){a.name=e.cnName,a.code=e.code,a.checked=!0,t.handleAdd(a);break}}})}}},k=(o("a463"),o("d959")),p=o.n(k);const g=p()(O,[["render",s]]);t["default"]=g}}]);
//# sourceMappingURL=chunk-2d870016.fd5660ee.js.map