(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-67101194"],{"1dde":function(e,t,o){var n=o("d039"),r=o("b622"),i=o("2d00"),a=r("species");e.exports=function(e){return i>=51||!n((function(){var t=[],o=t.constructor={};return o[a]=function(){return{foo:1}},1!==t[e](Boolean).foo}))}},2532:function(e,t,o){"use strict";var n=o("23e7"),r=o("5a34"),i=o("1d80"),a=o("577e"),c=o("ab13");n({target:"String",proto:!0,forced:!c("includes")},{includes:function(e){return!!~a(i(this)).indexOf(a(r(e)),arguments.length>1?arguments[1]:void 0)}})},"4de4":function(e,t,o){"use strict";var n=o("23e7"),r=o("b727").filter,i=o("1dde"),a=i("filter");n({target:"Array",proto:!0,forced:!a},{filter:function(e){return r(this,e,arguments.length>1?arguments[1]:void 0)}})},"59fd":function(e,t,o){"use strict";o.r(t);o("4de4"),o("caad"),o("2532");var n=o("7a23"),r={class:"domain-search-input"},i=Object(n["createTextVNode"])("添加网站"),a=Object(n["createVNode"])("a",{class:"el-button el-button--primary is-plain",href:"/#/group"},"返回",-1),c={class:"demo-block"},l={key:0},s={key:1},u=Object(n["createTextVNode"])("网站配置"),d=Object(n["createVNode"])("p",null,"确定删除吗？",-1),m={style:{"text-align":"right",margin:"0"}},p=Object(n["createTextVNode"])("取消"),b=Object(n["createTextVNode"])("确定 "),f=Object(n["createTextVNode"])("删除"),h={key:2,class:"form-info-color"},O={key:0},j=Object(n["createVNode"])("i",{class:"el-icon-plus"},null,-1),g=Object(n["createVNode"])("p",{class:"form-info-color"}," （请输入源站IP地址） ",-1),V=Object(n["createTextVNode"])("http"),_=Object(n["createTextVNode"])("https"),k=Object(n["createTextVNode"])("取消"),C=Object(n["createTextVNode"])("确定");function w(e,t){var o=Object(n["resolveComponent"])("el-input"),w=Object(n["resolveComponent"])("el-button"),y=Object(n["resolveComponent"])("el-row"),x=Object(n["resolveComponent"])("el-table-column"),v=Object(n["resolveComponent"])("el-popover"),F=Object(n["resolveComponent"])("el-table"),T=Object(n["resolveComponent"])("el-col"),N=Object(n["resolveComponent"])("el-form-item"),L=Object(n["resolveComponent"])("el-checkbox"),I=Object(n["resolveComponent"])("el-checkbox-group"),S=Object(n["resolveComponent"])("el-option"),P=Object(n["resolveComponent"])("el-select"),B=Object(n["resolveComponent"])("el-tab-pane"),D=Object(n["resolveComponent"])("el-tabs"),U=Object(n["resolveComponent"])("el-tag"),$=Object(n["resolveComponent"])("el-radio"),H=Object(n["resolveComponent"])("el-form"),z=Object(n["resolveComponent"])("el-dialog"),q=Object(n["resolveDirective"])("loading");return Object(n["withDirectives"])((Object(n["openBlock"])(),Object(n["createBlock"])(y,null,{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(T,{span:24},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(y,{class:"text-align-right"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])("div",r,[Object(n["createVNode"])(o,{placeholder:"请输入网站名进行搜索","prefix-icon":"el-icon-search",modelValue:e.domainSearch,"onUpdate:modelValue":t[1]||(t[1]=function(t){return e.domainSearch=t})},null,8,["modelValue"])]),Object(n["createVNode"])(w,{type:"primary",onClick:t[2]||(t[2]=function(t){return e.onClickCreateDomain()})},{default:Object(n["withCtx"])((function(){return[i]})),_:1}),a]})),_:1}),Object(n["createVNode"])("div",c,[Object(n["createVNode"])(F,{data:e.tableData.filter((function(t){return!e.domainSearch||t.domain.toLowerCase().includes(e.domainSearch.toLowerCase())})),style:{width:"100%"}},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(x,{prop:"domain",label:"网站"}),Object(n["createVNode"])(x,{prop:"protocol",label:"协议"},{default:Object(n["withCtx"])((function(e){return["true"==e.row.http?(Object(n["openBlock"])(),Object(n["createBlock"])("p",l,"http")):Object(n["createCommentVNode"])("",!0),"true"==e.row.https?(Object(n["openBlock"])(),Object(n["createBlock"])("p",s,"https")):Object(n["createCommentVNode"])("",!0)]})),_:1}),Object(n["createVNode"])(x,{label:"操作",align:"right"},{default:Object(n["withCtx"])((function(t){return[Object(n["createVNode"])(w,{size:"mini",onClick:function(o){return e.handleEdit(t.row)},class:"button-block",type:"text",loading:t.row.loading},{default:Object(n["withCtx"])((function(){return[u]})),_:2},1032,["onClick","loading"]),Object(n["createVNode"])(v,{placement:"top",width:"160",visible:t.row.isVisiblePopover,"onUpdate:visible":function(e){return t.row.isVisiblePopover=e}},{reference:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(w,{type:"text",size:"mini",onClick:function(e){return t.row.isVisiblePopover=!0}},{default:Object(n["withCtx"])((function(){return[f]})),_:2},1032,["onClick"])]})),default:Object(n["withCtx"])((function(){return[d,Object(n["createVNode"])("div",m,[Object(n["createVNode"])(w,{size:"mini",type:"text",onClick:function(e){return t.row.isVisiblePopover=!1}},{default:Object(n["withCtx"])((function(){return[p]})),_:2},1032,["onClick"]),Object(n["createVNode"])(w,{type:"primary",size:"mini",onClick:function(o){return e.handleDelete(t.row)},loading:e.loading},{default:Object(n["withCtx"])((function(){return[b]})),_:2},1032,["onClick","loading"])])]})),_:2},1032,["visible","onUpdate:visible"])]})),_:1})]})),_:1},8,["data"])])]})),_:1}),Object(n["createVNode"])(z,{title:e.domainTitle,modelValue:e.dialogDomainFormVisible,"onUpdate:modelValue":t[16]||(t[16]=function(t){return e.dialogDomainFormVisible=t}),width:"520px","close-on-click-modal":!1,onClosed:e.dialogClose},{footer:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(w,{onClick:t[14]||(t[14]=function(t){return e.dialogDomainFormVisible=!1})},{default:Object(n["withCtx"])((function(){return[k]})),_:1}),Object(n["createVNode"])(w,{type:"primary",onClick:t[15]||(t[15]=function(t){return e.onClickDomainSubmit("domainForm")}),loading:e.loading},{default:Object(n["withCtx"])((function(){return[C]})),_:1},8,["loading"])]})),default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(H,{class:"form-tag-dialog",model:e.domainForm,size:"mini","label-position":"left","label-width":"130px",rules:e.rules,ref:"domainForm"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(N,{label:"网站",prop:"domain",key:"1"},{default:Object(n["withCtx"])((function(){return["new"==e.domainType?(Object(n["openBlock"])(),Object(n["createBlock"])(o,{key:0,modelValue:e.domainForm.domain,"onUpdate:modelValue":t[3]||(t[3]=function(t){return e.domainForm.domain=t}),placeholder:"支持通配符，且为小写，支持统配符，例如_*.jxwaf.com"},null,8,["modelValue"])):Object(n["createCommentVNode"])("",!0),"edit"==e.domainType?(Object(n["openBlock"])(),Object(n["createBlock"])(o,{key:1,modelValue:e.domainForm.domain,"onUpdate:modelValue":t[4]||(t[4]=function(t){return e.domainForm.domain=t}),disabled:"disabled"},null,8,["modelValue"])):Object(n["createCommentVNode"])("",!0),"new"==e.domainType?(Object(n["openBlock"])(),Object(n["createBlock"])("p",h," （支持ip和域名，域名需要省略 https:// 或 http://） ")):Object(n["createCommentVNode"])("",!0)]})),_:1}),Object(n["createVNode"])(N,{label:"协议类型",prop:"checkListProtocol",key:"2"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(I,{modelValue:e.domainForm.checkListProtocol,"onUpdate:modelValue":t[5]||(t[5]=function(t){return e.domainForm.checkListProtocol=t})},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(L,{label:"HTTP",key:"HTTP"}),Object(n["createVNode"])(L,{label:"HTTPS",key:"HTTPS"})]})),_:1},8,["modelValue"])]})),_:1}),e.domainForm.checkListProtocol.indexOf("HTTPS")>-1?(Object(n["openBlock"])(),Object(n["createBlock"])("div",O,[Object(n["createVNode"])(D,{type:"border-card",class:"domain-tabs",modelValue:e.selectTabsValue,"onUpdate:modelValue":t[9]||(t[9]=function(t){return e.selectTabsValue=t})},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(B,{label:"SSL证书管理",name:"0"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(N,{label:"SSL证书",key:"3"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(P,{modelValue:e.domainForm.ssl_domain,"onUpdate:modelValue":t[6]||(t[6]=function(t){return e.domainForm.ssl_domain=t}),placeholder:"请选择或输入模糊搜索",filterable:""},{default:Object(n["withCtx"])((function(){return[(Object(n["openBlock"])(!0),Object(n["createBlock"])(n["Fragment"],null,Object(n["renderList"])(e.sslOptions,(function(e){return Object(n["openBlock"])(),Object(n["createBlock"])(S,{key:e.ssl_domain,label:e.ssl_domain,value:e.ssl_domain},null,8,["label","value"])})),128))]})),_:1},8,["modelValue"])]})),_:1})]})),_:1}),Object(n["createVNode"])(B,{label:"手动输入",name:"1"},{default:Object(n["withCtx"])((function(){return["1"==e.selectTabsValue?(Object(n["openBlock"])(),Object(n["createBlock"])(N,{label:"公钥",prop:"public_key",key:"5"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{modelValue:e.domainForm.public_key,"onUpdate:modelValue":t[7]||(t[7]=function(t){return e.domainForm.public_key=t}),placeholder:"需包含证书链",type:"textarea",rows:4},null,8,["modelValue"])]})),_:1})):Object(n["createCommentVNode"])("",!0),"1"==e.selectTabsValue?(Object(n["openBlock"])(),Object(n["createBlock"])(N,{label:"私钥",prop:"private_key",key:"6"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{modelValue:e.domainForm.private_key,"onUpdate:modelValue":t[8]||(t[8]=function(t){return e.domainForm.private_key=t}),type:"textarea",rows:4},null,8,["modelValue"])]})),_:1})):Object(n["createCommentVNode"])("",!0)]})),_:1})]})),_:1},8,["modelValue"])])):Object(n["createCommentVNode"])("",!0),Object(n["createVNode"])(N,{label:"源站地址",key:"7"},{default:Object(n["withCtx"])((function(){return[(Object(n["openBlock"])(!0),Object(n["createBlock"])(n["Fragment"],null,Object(n["renderList"])(e.sourceIpList,(function(t,o){return Object(n["openBlock"])(),Object(n["createBlock"])(U,{key:o,closable:"","disable-transitions":!1,onClose:function(o){return e.handleCloseSourceIpList(t)}},{default:Object(n["withCtx"])((function(){return[Object(n["createTextVNode"])(Object(n["toDisplayString"])(t),1)]})),_:2},1032,["onClose"])})),128)),e.sourceIpListVisible?(Object(n["openBlock"])(),Object(n["createBlock"])(o,{key:0,class:"input-new-tag node-ip-list",modelValue:e.sourceIpListValue,"onUpdate:modelValue":t[10]||(t[10]=function(t){return e.sourceIpListValue=t}),ref:"saveTagSourceIpList",size:"mini",onKeyup:Object(n["withKeys"])(e.handleSourceIpListConfirm,["enter"]),onBlur:e.handleSourceIpListConfirm},null,8,["modelValue","onKeyup","onBlur"])):(Object(n["openBlock"])(),Object(n["createBlock"])(w,{key:1,class:"button-new-tag",size:"small",onClick:e.showSourceIpList},{default:Object(n["withCtx"])((function(){return[j]})),_:1},8,["onClick"])),g]})),_:1}),Object(n["createVNode"])(N,{label:"源站端口",prop:"source_http_port",key:"8"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])(o,{placeholder:"仅支持http",modelValue:e.domainForm.source_http_port,"onUpdate:modelValue":t[11]||(t[11]=function(t){return e.domainForm.source_http_port=t})},null,8,["modelValue"])]})),_:1}),Object(n["createVNode"])(N,{label:"回源协议",prop:"proxy_pass_https",key:"9"},{default:Object(n["withCtx"])((function(){return[Object(n["createVNode"])($,{modelValue:e.domainForm.proxy_pass_https,"onUpdate:modelValue":t[12]||(t[12]=function(t){return e.domainForm.proxy_pass_https=t}),label:"false"},{default:Object(n["withCtx"])((function(){return[V]})),_:1},8,["modelValue"]),Object(n["createVNode"])($,{modelValue:e.domainForm.proxy_pass_https,"onUpdate:modelValue":t[13]||(t[13]=function(t){return e.domainForm.proxy_pass_https=t}),label:"true"},{default:Object(n["withCtx"])((function(){return[_]})),_:1},8,["modelValue"])]})),_:1})]})),_:1},8,["model","rules"])]})),_:1},8,["title","modelValue","onClosed"])]})),_:1},512)),[[q,e.loadingPage,void 0,{fullscreen:!0,lock:!0}]])}o("a434"),o("159b"),o("a15b"),o("ac1f"),o("1276");var y=o("362c"),x=o("6c02"),v={mixins:[y["b"]],data:function(){return{domainTitle:"添加规则",domainType:"new",domainSearch:"",loadingPage:!1,dialogDomainFormVisible:!1,loading:!1,dialogSysInitVisible:!1,domainForm:{source_http_port:"80",proxy_pass_https:"false",checkListProtocol:[]},tableData:[],sourceIpList:[],sourceIpListVisible:!1,sourceIpListValue:"",flagTag:!0,sslOptions:[],selectTabsValue:"0"}},computed:{rules:function(){return{domain:[{required:!0,message:"请输入网站地址",trigger:["blur","change"]}],source_http_port:[{required:!0,message:"请输入后端服务器端口信息",trigger:["blur","change"]},{validator:y["e"],trigger:["blur","change"]}],checkListProtocol:[{type:"array",required:!0,message:"请至少选择一项协议类型",trigger:"change"}],public_key:[{required:!0,message:"请输入公钥",trigger:"blur"}],private_key:[{required:!0,message:"请输入私钥",trigger:"blur"}]}}},mounted:function(){var e=Object(x["c"])();this.groupId=e.params.groupId,this.getData()},methods:{handleCloseSourceIpList:function(e){this.sourceIpList.splice(this.sourceIpList.indexOf(e),1)},showSourceIpList:function(){var e=this;this.sourceIpListVisible=!0,this.$nextTick((function(t){e.$refs.saveTagSourceIpList.$refs.input.focus()}))},handleSourceIpListConfirm:function(){var e=this,t=this.sourceIpListValue,o=/^(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])$/;e.flagTag&&(e.flagTag=!1,t?o.test(t)?Object(y["a"])("post","/ip_check",{ip:t},(function(o){o.data.result?(e.sourceIpList.push(t),e.sourceIpListVisible=!1,e.sourceIpListValue=""):e.$message({showClose:!0,message:"请输入正确的IP地址",type:"error"})}),(function(){}),"no-message"):e.$message({showClose:!0,message:"请输入源站IP地址",type:"error"}):(e.sourceIpListVisible=!1,e.sourceIpListValue=""),setTimeout((function(){e.flagTag=!0}),50))},getData:function(){var e=this;Object(y["a"])("post","/waf/waf_get_group_domain_list",{group_id:e.groupId},(function(t){e.loadingPage=!1,e.tableData=t.data.message,e.tableData.forEach((function(e){e.isVisiblePopover=!1}))}),(function(){e.loadingPage=!1}),"no-message")},getSSL:function(){var e=this;Object(y["a"])("get","/waf/waf_get_sys_ssl_manage_list",{},(function(t){e.sslOptions=t.data.message}),(function(){}))},dialogClose:function(){this.domainForm={source_http_port:"80",proxy_pass_https:"false",checkListProtocol:[]},this.selectTabsValue="0",this.sourceIpListVisible=!1,this.sourceIpListValue="",this.sourceIpList=[],this.$refs["domainForm"].resetFields()},onClickDomainSubmit:function(e){var t=this,o=t.domainForm.checkListProtocol,n="/waf/waf_create_group_domain";if("edit"==t.domainType&&(n="/waf/waf_edit_group_domain"),t.domainForm.group_id=t.groupId,0==t.sourceIpList.length)return t.$message({message:"后端服务器ip/域名不能为空",type:"error"}),!1;if(t.domainForm.checkListProtocol.indexOf("HTTPS")<0)t.domainForm.ssl_source="ssl_manage",t.domainForm.ssl_domain="";else if("0"==t.selectTabsValue){if(""==t.domainForm.ssl_domain)return t.$message({message:"请选择SSL证书",type:"error"}),!1;t.domainForm.ssl_source="ssl_manage",t.domainForm.public_key="",t.domainForm.private_key=""}else{if(""==t.domainForm.public_key||""==t.domainForm.private_key)return t.$message({message:"公钥/私钥不能为空",type:"error"}),!1;t.domainForm.ssl_source="custom",t.domainForm.ssl_domain=""}t.domainForm.source_ip=t.sourceIpList.join(","),t.domainForm.http=o.indexOf("HTTP")>-1?"true":"false",t.domainForm.https=o.indexOf("HTTPS")>-1?"true":"false",this.$refs[e].validate((function(e){e&&(t.loading=!0,Object(y["a"])("post",n,t.domainForm,(function(e){t.loading=!1,t.dialogDomainFormVisible=!1,t.sourceIpListVisible=!1,t.sourceIpListValue="",t.sourceIpList=[],t.getData()}),(function(){t.loading=!1})))}))},onClickDefault:function(){window.location.href="/#/default"},onClickCreateDomain:function(){var e=this;e.domainTitle="添加规则",e.domainType="new",e.dialogDomainFormVisible=!0,e.getSSL()},handleEdit:function(e){var t=this;e.loading=!0,t.getSSL(),Object(y["a"])("post","/waf/waf_get_group_domain",{domain:e.domain,group_id:e.group_id},(function(o){e.loading=!1;var n=o.data.message;t.domainForm.domain=n.domain,t.domainForm.private_key=n.private_key,t.domainForm.public_key=n.public_key,t.domainForm.ssl_domain=n.ssl_domain,t.domainForm.proxy_pass_https=n.proxy_pass_https,t.domainForm.source_http_port=n.source_http_port,t.sourceIpList=n.source_ip?n.source_ip.split(","):[],t.domainForm.isVisiblePopover=!1,"true"==n.http&&t.domainForm.checkListProtocol.push("HTTP"),"true"==n.https&&t.domainForm.checkListProtocol.push("HTTPS"),""==n.ssl_domain?t.selectTabsValue="1":t.selectTabsValue="0",t.domainTitle="编辑网站",t.domainType="edit",t.dialogDomainFormVisible=!0}),(function(){e.loading=!1}),"no-message")},handleDelete:function(e){var t=this;t.loading=!0,Object(y["a"])("post","/waf/waf_del_group_domain",{domain:e.domain,group_id:e.group_id},(function(o){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))}}};o("e045");v.render=w;t["default"]=v},"5a34":function(e,t,o){var n=o("44e7");e.exports=function(e){if(n(e))throw TypeError("The method doesn't accept regular expressions");return e}},6231:function(e,t,o){},8418:function(e,t,o){"use strict";var n=o("a04b"),r=o("9bf2"),i=o("5c6c");e.exports=function(e,t,o){var a=n(t);a in e?r.f(e,a,i(0,o)):e[a]=o}},a15b:function(e,t,o){"use strict";var n=o("23e7"),r=o("44ad"),i=o("fc6a"),a=o("a640"),c=[].join,l=r!=Object,s=a("join",",");n({target:"Array",proto:!0,forced:l||!s},{join:function(e){return c.call(i(this),void 0===e?",":e)}})},a434:function(e,t,o){"use strict";var n=o("23e7"),r=o("23cb"),i=o("a691"),a=o("50c4"),c=o("7b0b"),l=o("65f0"),s=o("8418"),u=o("1dde"),d=u("splice"),m=Math.max,p=Math.min,b=9007199254740991,f="Maximum allowed length exceeded";n({target:"Array",proto:!0,forced:!d},{splice:function(e,t){var o,n,u,d,h,O,j=c(this),g=a(j.length),V=r(e,g),_=arguments.length;if(0===_?o=n=0:1===_?(o=0,n=g-V):(o=_-2,n=p(m(i(t),0),g-V)),g+o-n>b)throw TypeError(f);for(u=l(j,n),d=0;d<n;d++)h=V+d,h in j&&s(u,d,j[h]);if(u.length=n,o<n){for(d=V;d<g-n;d++)h=d+n,O=d+o,h in j?j[O]=j[h]:delete j[O];for(d=g;d>g-n+o;d--)delete j[d-1]}else if(o>n)for(d=g-n;d>V;d--)h=d+n-1,O=d+o-1,h in j?j[O]=j[h]:delete j[O];for(d=0;d<o;d++)j[d+V]=arguments[d+2];return j.length=g-n+o,u}})},ab13:function(e,t,o){var n=o("b622"),r=n("match");e.exports=function(e){var t=/./;try{"/./"[e](t)}catch(o){try{return t[r]=!1,"/./"[e](t)}catch(n){}}return!1}},caad:function(e,t,o){"use strict";var n=o("23e7"),r=o("4d64").includes,i=o("44d2");n({target:"Array",proto:!0},{includes:function(e){return r(this,e,arguments.length>1?arguments[1]:void 0)}}),i("includes")},e045:function(e,t,o){"use strict";o("6231")}}]);
//# sourceMappingURL=chunk-67101194.342ff445.js.map