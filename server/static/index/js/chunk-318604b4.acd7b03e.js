(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["chunk-318604b4"],{"59fd":function(e,t,o){"use strict";o.r(t);var a=o("7a23");const l={class:"domain-search-input"},i=Object(a["createTextVNode"])("添加网站"),c=Object(a["createVNode"])("a",{class:"el-button el-button--primary is-plain",href:"/#/group"},"返回",-1),r={class:"demo-block"},s={key:0},d={key:1},n=Object(a["createTextVNode"])("网站配置"),m=Object(a["createVNode"])("p",null,"确定删除吗？",-1),p={style:{"text-align":"right",margin:"0"}},b=Object(a["createTextVNode"])("取消"),u=Object(a["createTextVNode"])("确定 "),O=Object(a["createTextVNode"])("删除"),j={key:2,class:"form-info-color"},h={key:0},V=Object(a["createVNode"])("i",{class:"el-icon-plus"},null,-1),_=Object(a["createVNode"])("p",{class:"form-info-color"}," （支持IP和域名，域名需要省略https:// 或 http://） ",-1),g=Object(a["createTextVNode"])("IP_HASH"),f=Object(a["createTextVNode"])("轮询"),k=Object(a["createTextVNode"])("http"),C=Object(a["createTextVNode"])("https"),w=Object(a["createTextVNode"])("协议跟随"),y=Object(a["createTextVNode"])("取消"),x=Object(a["createTextVNode"])("确定");function F(e,t,o,F,N,v){const T=Object(a["resolveComponent"])("el-input"),L=Object(a["resolveComponent"])("el-button"),I=Object(a["resolveComponent"])("el-row"),P=Object(a["resolveComponent"])("el-table-column"),S=Object(a["resolveComponent"])("el-popover"),B=Object(a["resolveComponent"])("el-table"),D=Object(a["resolveComponent"])("el-col"),U=Object(a["resolveComponent"])("el-form-item"),H=Object(a["resolveComponent"])("el-checkbox"),$=Object(a["resolveComponent"])("el-checkbox-group"),q=Object(a["resolveComponent"])("el-option"),z=Object(a["resolveComponent"])("el-select"),E=Object(a["resolveComponent"])("el-tab-pane"),K=Object(a["resolveComponent"])("el-tabs"),J=Object(a["resolveComponent"])("el-tag"),A=Object(a["resolveComponent"])("el-radio"),G=Object(a["resolveComponent"])("el-form"),M=Object(a["resolveComponent"])("el-dialog"),Q=Object(a["resolveDirective"])("loading");return Object(a["withDirectives"])((Object(a["openBlock"])(),Object(a["createBlock"])(I,null,{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(D,{span:24},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(I,{class:"text-align-right"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])("div",l,[Object(a["createVNode"])(T,{placeholder:"请输入网站名进行搜索","prefix-icon":"el-icon-search",modelValue:N.domainSearch,"onUpdate:modelValue":t[1]||(t[1]=e=>N.domainSearch=e)},null,8,["modelValue"])]),Object(a["createVNode"])(L,{type:"primary",onClick:t[2]||(t[2]=e=>v.onClickCreateDomain())},{default:Object(a["withCtx"])(()=>[i]),_:1}),c]),_:1}),Object(a["createVNode"])("div",r,[Object(a["createVNode"])(B,{data:N.tableData.filter(e=>!N.domainSearch||e.domain.toLowerCase().includes(N.domainSearch.toLowerCase())),style:{width:"100%"}},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(P,{prop:"domain",label:"域名/IP"}),Object(a["createVNode"])(P,{prop:"protocol",label:"协议"},{default:Object(a["withCtx"])(e=>["true"==e.row.http?(Object(a["openBlock"])(),Object(a["createBlock"])("p",s,"http")):Object(a["createCommentVNode"])("",!0),"true"==e.row.https?(Object(a["openBlock"])(),Object(a["createBlock"])("p",d,"https")):Object(a["createCommentVNode"])("",!0)]),_:1}),Object(a["createVNode"])(P,{label:"操作",align:"right"},{default:Object(a["withCtx"])(e=>[Object(a["createVNode"])(L,{size:"mini",onClick:t=>v.handleEdit(e.row),class:"button-block",type:"text",loading:e.row.loading},{default:Object(a["withCtx"])(()=>[n]),_:2},1032,["onClick","loading"]),Object(a["createVNode"])(S,{placement:"top",width:"160",visible:e.row.isVisiblePopover,"onUpdate:visible":t=>e.row.isVisiblePopover=t},{reference:Object(a["withCtx"])(()=>[Object(a["createVNode"])(L,{type:"text",size:"mini",onClick:t=>e.row.isVisiblePopover=!0},{default:Object(a["withCtx"])(()=>[O]),_:2},1032,["onClick"])]),default:Object(a["withCtx"])(()=>[m,Object(a["createVNode"])("div",p,[Object(a["createVNode"])(L,{size:"mini",type:"text",onClick:t=>e.row.isVisiblePopover=!1},{default:Object(a["withCtx"])(()=>[b]),_:2},1032,["onClick"]),Object(a["createVNode"])(L,{type:"primary",size:"mini",onClick:t=>v.handleDelete(e.row),loading:N.loading},{default:Object(a["withCtx"])(()=>[u]),_:2},1032,["onClick","loading"])])]),_:2},1032,["visible","onUpdate:visible"])]),_:1})]),_:1},8,["data"])])]),_:1}),Object(a["createVNode"])(M,{title:N.domainTitle,modelValue:N.dialogDomainFormVisible,"onUpdate:modelValue":t[19]||(t[19]=e=>N.dialogDomainFormVisible=e),width:"520px","close-on-click-modal":!1,onClosed:v.dialogClose},{footer:Object(a["withCtx"])(()=>[Object(a["createVNode"])(L,{onClick:t[17]||(t[17]=e=>N.dialogDomainFormVisible=!1)},{default:Object(a["withCtx"])(()=>[y]),_:1}),Object(a["createVNode"])(L,{type:"primary",onClick:t[18]||(t[18]=e=>v.onClickDomainSubmit("domainForm")),loading:N.loading},{default:Object(a["withCtx"])(()=>[x]),_:1},8,["loading"])]),default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(G,{class:"form-tag-dialog",model:N.domainForm,size:"mini","label-position":"left","label-width":"130px",rules:v.rules,ref:"domainForm"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(U,{label:"域名/IP",prop:"domain",key:"1"},{default:Object(a["withCtx"])(()=>["new"==N.domainType?(Object(a["openBlock"])(),Object(a["createBlock"])(T,{key:0,modelValue:N.domainForm.domain,"onUpdate:modelValue":t[3]||(t[3]=e=>N.domainForm.domain=e),placeholder:"请输入IP或域名，域名支持通配符，例如*.jxwaf.com"},null,8,["modelValue"])):Object(a["createCommentVNode"])("",!0),"edit"==N.domainType?(Object(a["openBlock"])(),Object(a["createBlock"])(T,{key:1,modelValue:N.domainForm.domain,"onUpdate:modelValue":t[4]||(t[4]=e=>N.domainForm.domain=e),disabled:"disabled"},null,8,["modelValue"])):Object(a["createCommentVNode"])("",!0),"new"==N.domainType?(Object(a["openBlock"])(),Object(a["createBlock"])("p",j," （请输入IP或域名，域名支持通配符，例如*.jxwaf.com） ")):Object(a["createCommentVNode"])("",!0)]),_:1}),Object(a["createVNode"])(U,{label:"协议类型",prop:"checkListProtocol",key:"2"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])($,{modelValue:N.domainForm.checkListProtocol,"onUpdate:modelValue":t[5]||(t[5]=e=>N.domainForm.checkListProtocol=e)},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(H,{label:"HTTP",key:"HTTP"}),Object(a["createVNode"])(H,{label:"HTTPS",key:"HTTPS"})]),_:1},8,["modelValue"])]),_:1}),N.domainForm.checkListProtocol.indexOf("HTTPS")>-1?(Object(a["openBlock"])(),Object(a["createBlock"])("div",h,[Object(a["createVNode"])(K,{type:"border-card",class:"domain-tabs",modelValue:N.selectTabsValue,"onUpdate:modelValue":t[9]||(t[9]=e=>N.selectTabsValue=e)},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(E,{label:"SSL证书管理",name:"0"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(U,{label:"SSL证书",key:"3"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(z,{modelValue:N.domainForm.ssl_domain,"onUpdate:modelValue":t[6]||(t[6]=e=>N.domainForm.ssl_domain=e),placeholder:"请选择或输入模糊搜索",filterable:""},{default:Object(a["withCtx"])(()=>[(Object(a["openBlock"])(!0),Object(a["createBlock"])(a["Fragment"],null,Object(a["renderList"])(N.sslOptions,e=>(Object(a["openBlock"])(),Object(a["createBlock"])(q,{key:e.ssl_domain,label:e.ssl_domain,value:e.ssl_domain},null,8,["label","value"]))),128))]),_:1},8,["modelValue"])]),_:1})]),_:1}),Object(a["createVNode"])(E,{label:"手动输入",name:"1"},{default:Object(a["withCtx"])(()=>["1"==N.selectTabsValue?(Object(a["openBlock"])(),Object(a["createBlock"])(U,{label:"公钥",prop:"public_key",key:"5"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(T,{modelValue:N.domainForm.public_key,"onUpdate:modelValue":t[7]||(t[7]=e=>N.domainForm.public_key=e),placeholder:"需包含证书链",type:"textarea",rows:4},null,8,["modelValue"])]),_:1})):Object(a["createCommentVNode"])("",!0),"1"==N.selectTabsValue?(Object(a["openBlock"])(),Object(a["createBlock"])(U,{label:"私钥",prop:"private_key",key:"6"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(T,{modelValue:N.domainForm.private_key,"onUpdate:modelValue":t[8]||(t[8]=e=>N.domainForm.private_key=e),type:"textarea",rows:4},null,8,["modelValue"])]),_:1})):Object(a["createCommentVNode"])("",!0)]),_:1})]),_:1},8,["modelValue"])])):Object(a["createCommentVNode"])("",!0),Object(a["createVNode"])(U,{label:"源站地址",key:"7",class:"is-required"},{default:Object(a["withCtx"])(()=>[(Object(a["openBlock"])(!0),Object(a["createBlock"])(a["Fragment"],null,Object(a["renderList"])(N.sourceIpList,(e,t)=>(Object(a["openBlock"])(),Object(a["createBlock"])(J,{key:t,closable:"","disable-transitions":!1,onClose:t=>v.handleCloseSourceIpList(e)},{default:Object(a["withCtx"])(()=>[Object(a["createTextVNode"])(Object(a["toDisplayString"])(e),1)]),_:2},1032,["onClose"]))),128)),N.sourceIpListVisible?(Object(a["openBlock"])(),Object(a["createBlock"])(T,{key:0,class:"input-new-tag node-ip-list",modelValue:N.sourceIpListValue,"onUpdate:modelValue":t[10]||(t[10]=e=>N.sourceIpListValue=e),ref:"saveTagSourceIpList",size:"mini",onKeyup:Object(a["withKeys"])(v.handleSourceIpListConfirm,["enter"]),onBlur:v.handleSourceIpListConfirm},null,8,["modelValue","onKeyup","onBlur"])):(Object(a["openBlock"])(),Object(a["createBlock"])(L,{key:1,class:"button-new-tag",size:"small",onClick:v.showSourceIpList},{default:Object(a["withCtx"])(()=>[V]),_:1},8,["onClick"])),_]),_:1}),Object(a["createVNode"])(U,{label:"源站端口",prop:"source_http_port",key:"8"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(T,{placeholder:"仅支持http",modelValue:N.domainForm.source_http_port,"onUpdate:modelValue":t[11]||(t[11]=e=>N.domainForm.source_http_port=e)},null,8,["modelValue"])]),_:1}),Object(a["createVNode"])(U,{label:"负载均衡",key:"10",class:"is-required"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(A,{modelValue:N.domainForm.balance_type,"onUpdate:modelValue":t[12]||(t[12]=e=>N.domainForm.balance_type=e),label:"ip_hash"},{default:Object(a["withCtx"])(()=>[g]),_:1},8,["modelValue"]),Object(a["createVNode"])(A,{modelValue:N.domainForm.balance_type,"onUpdate:modelValue":t[13]||(t[13]=e=>N.domainForm.balance_type=e),label:"round_robin"},{default:Object(a["withCtx"])(()=>[f]),_:1},8,["modelValue"])]),_:1}),Object(a["createVNode"])(U,{label:"回源协议",prop:"proxy_pass_https",key:"9",class:"is-required"},{default:Object(a["withCtx"])(()=>[Object(a["createVNode"])(A,{modelValue:N.domainForm.proxy_pass_https,"onUpdate:modelValue":t[14]||(t[14]=e=>N.domainForm.proxy_pass_https=e),label:"false"},{default:Object(a["withCtx"])(()=>[k]),_:1},8,["modelValue"]),Object(a["createVNode"])(A,{modelValue:N.domainForm.proxy_pass_https,"onUpdate:modelValue":t[15]||(t[15]=e=>N.domainForm.proxy_pass_https=e),label:"true"},{default:Object(a["withCtx"])(()=>[C]),_:1},8,["modelValue"]),Object(a["createVNode"])(A,{modelValue:N.domainForm.proxy_pass_https,"onUpdate:modelValue":t[16]||(t[16]=e=>N.domainForm.proxy_pass_https=e),label:"follow"},{default:Object(a["withCtx"])(()=>[w]),_:1},8,["modelValue"])]),_:1})]),_:1},8,["model","rules"])]),_:1},8,["title","modelValue","onClosed"])]),_:1},512)),[[Q,N.loadingPage,void 0,{fullscreen:!0,lock:!0}]])}var N=o("362c"),v=o("6c02"),T={mixins:[N["b"]],data(){return{domainTitle:"添加网站",domainType:"new",domainSearch:"",loadingPage:!1,dialogDomainFormVisible:!1,loading:!1,dialogSysInitVisible:!1,domainForm:{source_http_port:"80",proxy_pass_https:"false",balance_type:"ip_hash",checkListProtocol:[]},tableData:[],sourceIpList:[],sourceIpListVisible:!1,sourceIpListValue:"",flagTag:!0,sslOptions:[],selectTabsValue:"0"}},computed:{rules(){return{domain:[{required:!0,message:"请输入网站地址",trigger:["blur","change"]},{validator:N["c"],trigger:["blur","change"]}],source_http_port:[{required:!0,message:"请输入后端服务器端口信息",trigger:["blur","change"]},{validator:N["e"],trigger:["blur","change"]}],checkListProtocol:[{type:"array",required:!0,message:"请至少选择一项协议类型",trigger:"change"}],public_key:[{required:!0,message:"请输入公钥",trigger:"blur"}],private_key:[{required:!0,message:"请输入私钥",trigger:"blur"}]}}},mounted(){const e=Object(v["c"])();this.groupId=e.params.groupId,this.getData()},methods:{handleCloseSourceIpList(e){this.sourceIpList.splice(this.sourceIpList.indexOf(e),1)},showSourceIpList(){this.sourceIpListVisible=!0,this.$nextTick(e=>{this.$refs.saveTagSourceIpList.$refs.input.focus()})},handleSourceIpListConfirm(){let e=this,t=this.sourceIpListValue,o=/^(((https|http)?:\/)?\/)/;e.flagTag&&(e.flagTag=!1,t?o.test(t)?e.$message({showClose:!0,message:"请输入正确的域名格式",type:"error"}):(e.sourceIpList.push(t),e.sourceIpListVisible=!1,e.sourceIpListValue=""):(e.sourceIpListVisible=!1,e.sourceIpListValue=""),setTimeout((function(){e.flagTag=!0}),50))},getData(){var e=this;Object(N["a"])("post","/waf/waf_get_group_domain_list",{group_id:e.groupId},(function(t){e.loadingPage=!1,e.tableData=t.data.message,e.tableData.forEach(e=>{e.isVisiblePopover=!1})}),(function(){e.loadingPage=!1}),"no-message")},getSSL(){var e=this;Object(N["a"])("get","/waf/waf_get_sys_ssl_manage_list",{},(function(t){e.sslOptions=t.data.message}),(function(){}))},dialogClose(){this.domainForm={source_http_port:"80",proxy_pass_https:"false",balance_type:"ip_hash",checkListProtocol:[]},this.selectTabsValue="0",this.sourceIpListVisible=!1,this.sourceIpListValue="",this.sourceIpList=[],this.$refs["domainForm"].resetFields()},onClickDomainSubmit(e){var t=this,o=t.domainForm.checkListProtocol,a="/waf/waf_create_group_domain";if("edit"==t.domainType&&(a="/waf/waf_edit_group_domain"),t.domainForm.group_id=t.groupId,0==t.sourceIpList.length)return t.$message({message:"源站地址不能为空",type:"error"}),!1;if(t.domainForm.checkListProtocol.indexOf("HTTPS")<0)t.domainForm.ssl_source="ssl_manage",t.domainForm.ssl_domain="";else if("0"==t.selectTabsValue){if(""==t.domainForm.ssl_domain)return t.$message({message:"请选择SSL证书",type:"error"}),!1;t.domainForm.ssl_source="ssl_manage",t.domainForm.public_key="",t.domainForm.private_key=""}else{if(""==t.domainForm.public_key||""==t.domainForm.private_key)return t.$message({message:"公钥/私钥不能为空",type:"error"}),!1;t.domainForm.ssl_source="custom",t.domainForm.ssl_domain=""}t.domainForm.source_ip=t.sourceIpList.join(","),t.domainForm.http=o.indexOf("HTTP")>-1?"true":"false",t.domainForm.https=o.indexOf("HTTPS")>-1?"true":"false",this.$refs[e].validate(e=>{e&&(t.loading=!0,Object(N["a"])("post",a,t.domainForm,(function(e){t.loading=!1,t.dialogDomainFormVisible=!1,t.sourceIpListVisible=!1,t.sourceIpListValue="",t.sourceIpList=[],t.getData()}),(function(){t.loading=!1})))})},onClickDefault(){window.location.href="/#/default"},onClickCreateDomain(){var e=this;e.domainTitle="添加网站",e.domainType="new",e.dialogDomainFormVisible=!0,e.getSSL()},handleEdit(e){var t=this;e.loading=!0,t.getSSL(),Object(N["a"])("post","/waf/waf_get_group_domain",{domain:e.domain,group_id:e.group_id},(function(o){e.loading=!1;var a=o.data.message;t.domainForm.domain=a.domain,t.domainForm.private_key=a.private_key,t.domainForm.public_key=a.public_key,t.domainForm.ssl_domain=a.ssl_domain,t.domainForm.proxy_pass_https=a.proxy_pass_https,t.domainForm.source_http_port=a.source_http_port,t.domainForm.balance_type=a.balance_type,t.sourceIpList=a.source_ip?a.source_ip.split(","):[],t.domainForm.isVisiblePopover=!1,"true"==a.http&&t.domainForm.checkListProtocol.push("HTTP"),"true"==a.https&&t.domainForm.checkListProtocol.push("HTTPS"),""==a.ssl_domain?t.selectTabsValue="1":t.selectTabsValue="0",t.domainTitle="编辑网站",t.domainType="edit",t.dialogDomainFormVisible=!0}),(function(){e.loading=!1}),"no-message")},handleDelete(e){var t=this;t.loading=!0,Object(N["a"])("post","/waf/waf_del_group_domain",{domain:e.domain,group_id:e.group_id},(function(o){e.isVisiblePopover=!1,t.loading=!1,t.getData()}),(function(){t.loading=!1}))}}},L=(o("e42d"),o("d959")),I=o.n(L);const P=I()(T,[["render",F]]);t["default"]=P},d8ac:function(e,t,o){},e42d:function(e,t,o){"use strict";o("d8ac")}}]);
//# sourceMappingURL=chunk-318604b4.acd7b03e.js.map