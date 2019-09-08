/**
 * BrowserWAF（浏览器WAF）
 * http://www.ShareWAF.com/BrowserWAF/
 * Auther:WangErGou
 * Email:6465660@qq.com
 */

//版本
var BrowserWAF_Version = "v0.0.1";
//浏览器指纹
var BrowserWAF_BrowserID;
//拦截提示
var bWAF_warning = "You are blocked by BrowserWAF!";

/* BrowserWAF启动函数 */
function BrowserWAF_Run(BrowserWAF_Config){

	//执行页面原有的onload函数（如果存在的话）
	var bWAF_pre_window_load = window.onload;
	if (bWAF_pre_window_load != undefined){
		bWAF_pre_window_load();
	}

	//在新的新的页面onload函数中，执行各BrowserWAF功能
	window.onload=function(){
		console.log("BrowserWAF",BrowserWAF_Version);

		//浏览器指纹防护
		BrowserWAF_BrowserID = bWAF_Get_BrowserID();
		if(BrowserWAF_Config.BrowserID_Enable == 1){
			console.log("BrowserWAF defend automated attack enabled,BrowserID:",BrowserWAF_BrowserID);

			//向BrowserWAF后台提交浏览器指纹，如果该指纹在指纹库黑名单中，则访问会被拦截
			ajax_query_browserid();
		}

		//防自动化攻击
		if(BrowserWAF_Config.Defend_Automated_Attack_Enable == 1){
			console.log("BrowserWAF defend automated attack enabled");
			bwaf_defend_automated_attack();
		}

		//防SQL注入等
		if(BrowserWAF_Config.Defend_Sql_Inject_Enable == 1){
			console.log("BrowserWAF defend sql inject attack enabled");
			bwaf_defend_sql_inject();
		}

		//防CRSF
		if(BrowserWAF_Config.Defend_CRSF_Enable == 1){
			console.log("BrowserWAF defend CRSF attack enabled");
			bwaf_defend_crsf();
		}

		//防Iframe
		if(BrowserWAF_Config.Defend_Iframe_Enable == 1){
			console.log("BrowserWAF defend iframe attack enabled");
			bwaf_defend_iframe();
		}

		//防爬虫
		if(BrowserWAF_Config.Defend_Spider_Enable == 1){
			console.log("BrowserWAF defend Spider attack enabled");
			bwaf_defend_spider();
		}

		//防XSS
		if(BrowserWAF_Config.Defend_XSS_Enable == 1){
			console.log("BrowserWAF defend XSS attack enabled");
			bwaf_defend_xss();
		}

	}

}

/* 防爬虫 */
{
	//全局变量，存储全部链接的href
	var bwaf_pre_href=[];

	function bwaf_defend_spider(){
		
		//识别Agent，拦截第三方库驱动的访问
		var user_agent = navigator.userAgent.toLowerCase();
		if( (user_agent.indexOf("phantomjs") != -1) || (user_agent.indexOf("selenium") != -1) || (user_agent.indexOf("casperjs") != -1) ){
			document.body.innerHTML = bWAF_warning;
			
			//向BrowserWAF后台提交浏览器指纹
			ajax_insert_browserid();
		}
	
		//清空链接的href，使爬虫无法获取链接
		var link = document.getElementsByTagName("a");
		for(var i=0; i<link.length; i++){
	
			bwaf_pre_href[i] = link[i].href;
			link[i].href="";
	
			//获取之前的onclick事件
			var pre_onclick = link[i].onclick;
	
			//注册click事件处理程序，即onclick
			link[i].addEventListener("click",function(){
	
				//如果之前有onclick事件处理程序，则先执行
				if(pre_onclick!=undefined){
					pre_onclick;
				}

				//还原链接
				bwaf_restore_href(this)
			});
	
		}
	}

	//还原href，使链接可打开
	function bwaf_restore_href(t){
		var href = document.getElementsByTagName('a');
		for(var i=0; i<href.length; i++){
			if(href[i]==t){
				href[i].href=bwaf_pre_href[i];
			}
		}
	}

}

/* 防Iframe */
{
	function bwaf_defend_iframe(){
		if(top.location != self.location){
			console.log("BrowserWAF detected iframe attack");
			document.body.innerHTML = bWAF_warning;
		}
	}
}

/* 防CRSF */
{
	function bwaf_defend_crsf(){
		var pre_cookie = document.cookie.toLowerCase();
		if(pre_cookie.indexOf("samesite")==-1){
			document.cookie = pre_cookie + ";SameSite=Strict;";
		}
	}
}

/* 防XSS */
{
	function bwaf_defend_xss(){

		//判断input输入框中没有没xss
		var input = document.getElementsByTagName("input");
		for(var i=0; i<input.length; i++){
	
			//不处理密码输入框
			if (input[i].type != "password"){

				//获取之前的onblur事件
				var pre_blur = input[i].onblur;
	
				//注册blur事件处理程序，即onblur
				input[i].addEventListener("blur",function(){
	
					//如果之前有oncblur事件处理程序，则先执行
					if(pre_blur!=undefined){
						pre_blur;
					}
					bwaf_detect_input_xss(this);
				});
			}
		}
		
		//判断textarea输入框中没有没xss语句
		var textarea = document.getElementsByTagName("textarea");
		for(var i=0; i<textarea.length; i++){
	
			//获取之前的onblur事件
			var pre_blur = textarea[i].onblur;
	
			//注册blur事件处理程序，即onblur
			textarea[i].addEventListener("blur",function(){
	
				//如果之前有oncblur事件处理程序，则先执行
				if(pre_blur!=undefined){
					pre_blur;
				}
				bwaf_detect_input_xss(this);
			});
			   
		}
	}

	//检测xss关键字符
	function bwaf_detect_input_xss(t){
		//技巧：判断包含"和'的方法
		if(t.value.indexOf("<")!=-1 || t.value.indexOf(">")!=-1 || t.value.indexOf("'")!=-1 || t.value.indexOf('"')!=-1  ){
			console.log("BrowserWAF transformed xss character");
			t.value = bwaf_transform_xss(t.value);
		}
	}
	
	//对xss关键字符编码
	function bwaf_transform_xss(s){
		return s.replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g, "&quot;").replace(/'/g, "&#039;");
	}
}

/* 传统WAF防护功能：如SQL注入、命令行注入、文件包含等 */
/* 注：SQL注入最为典型，因此以此命名函数，将攻击都归类为SQL注入 */
{
	function bwaf_defend_sql_inject(){

		//检测URL
		var url = location.search.toLowerCase();
		url = url.substring(url.indexOf("?"));
		if( bwaf_regexp_detect_sqlinj(url) == true ){
			console.log("BrowserWAF detected SQL inject attack");
			document.body.innerHTML = bWAF_warning;

			//向BrowserWAF后台提交浏览器指纹
			ajax_insert_browserid();
		}
	
		//检测input输入框
		var input = document.getElementsByTagName("input");
		for(var i=0; i<input.length; i++){
	
			//获取之前的onblur事件
			var pre_blur = input[i].onblur;
	
			//注册blur事件处理程序，即onblur
			input[i].addEventListener("blur",function(){
	
				//如果之前有oncblur事件处理程序，则先执行
				if(pre_blur!=undefined){
					pre_blur;
				}
				if(bwaf_regexp_detect_sqlinj(this.value) == true){
					this.value = "";
					console.log("BrowserWAF detected SQL inject attack");
					document.body.innerHTML = bWAF_warning;

					//向BrowserWAF后台提交浏览器指纹
					ajax_insert_browserid();
				}
			});
	
		}
	}

	//检测SQL注入
	function bwaf_regexp_detect_sqlinj(str_to_detect){

		for(i=0; i< regexp_rule.length; i++){
			if(regexp_rule[i].test(str_to_detect) == true){
				console.log("BrowserWAF detected SQL inject attack,regexp rule:", "(" + i + ")", regexp_rule[i]);
				return true;
			}
		}
		return false;
	}

	//正则表达式检测规则
	regexp_rule = [
		/select.+(from|limit)/i,
		/(?:(union(.*?)select))/i,
		/sleep\((\s*)(\d*)(\s*)\)/i,
		/group\s+by.+\(/i,
		/(?:from\W+information_schema\W)/i,
		/(?:(?:current_)user|database|schema|connection_id)\s*\(/i,
		/\s*or\s+.*=.*/i,
		/order\s+by\s+.*--$/i,
		/benchmark\((.*)\,(.*)\)/i,
		/base64_decode\(/i,
		/(?:(?:current_)user|database|version|schema|connection_id)\s*\(/i,
		/(?:etc\/\W*passwd)/i,
		/into(\s+)+(?:dump|out)file\s*/i,
		/xwork.MethodAccessor/i,
		/(?:define|eval|file_get_contents|include|require|require_once|shell_exec|phpinfo|system|passthru|preg_\w+|execute|echo|print|print_r|var_dump|(fp)open|alert|showmodaldialog)\(/i,
		/\<(iframe|script|body|img|layer|div|meta|style|base|object|input)/i,
		/(onmouseover|onmousemove|onerror|onload)\=/i,
		/javascript:/i,
		/\.\.\/\.\.\//i,
		/\|\|.*(?:ls|pwd|whoami|ll|ifconfog|ipconfig|&&|chmod|cd|mkdir|rmdir|cp|mv)/i,
		/(?:ls|pwd|whoami|ll|ifconfog|ipconfig|&&|chmod|cd|mkdir|rmdir|cp|mv).*\|\|/i,
		/(gopher|doc|php|glob|file|phar|zlib|ftp|ldap|dict|ogg|data)\:\//i
	];
}

/* 防自动化攻击 */
{
	//存储页面全部input控件的id、name
	var bWAF_input_id=[], bWAF_input_name=[];

	function bwaf_defend_automated_attack(){

		//防Xpath
		var rand_num = (Math.floor(Math.random()*3));
		for(i=0;i<rand_num ;i++){
			var rand_div = document.createElement("input");
			rand_div.setAttribute("type","hidden");

			var first_input = document.getElementsByTagName("input")[0];
			if(first_input!=undefined){
				//节点的父节点插入新节点，参数：新元素，节点
				first_input.parentElement.insertBefore(rand_div,first_input);
			}
		}

		//清空input控件id和name，防控件定位
		var input = document.getElementsByTagName("input");
		
		for(var i=0; i<input.length; i++){
			
			//只处理password输入框
			if(input[i].type=="password"){
				bWAF_input_id[i] = input[i].id;
				bWAF_input_name[i] = input[i].name;
				input[i].id = "";
				input[i].name = "";

				//获取之前的onchange事件
				var pre_onchange = input[i].onchange;

				//注册change事件处理程序，即onchange
				input[i].addEventListener("change", function(){

					//如果之前有onchange事件处理程序，则先执行
					if(pre_onchange != undefined){
						pre_onchange;
					}
					bWAF_restore_id_name(this)
				});

				//获取之前的oninput事件
				var pre_oninput = input[i].oninput;
				//注册input事件处理程序，即oninput
				input[i].addEventListener("input", function(){

					//如果之前有oninput事件处理程序，则先执行
					if (pre_oninput != undefined){
						pre_oninput;
					}
					var input_ret = bWAF_detect_input(this);
					if (input_ret==false){
						this.value="";
					}
				});
			}
		}
	}

	//恢复Input控件的Id和Name
	function bWAF_restore_id_name(t){
		var input = document.getElementsByTagName('input');
		for(var i=0; i<input.length; i++){
			if(input[i]==t){
				input[i].id=bWAF_input_id[i];
				input[i].name=bWAF_input_name[i];
			}
		}
	}

	var bwaf_input_password_len = 0;
	//输入检测，防自动按键软件
	function bWAF_detect_input(t){
		console.log("BrowserWAF detected input:", t.value);

		if(t.value.length - bwaf_input_password_len>1){
			console.log("BrowserWAF detected abnormal input")
			return false;
		}
		bwaf_input_password_len = t.value.length;
		return true;
	}
	
}

/* 浏览器指纹功能 */
{
	/* 获取浏览器指纹 */
	function bWAF_Get_BrowserID(){

		//系统特征
		var ISig = [];
		ISig.push({key: "user_agent", value: navigator.userAgent });
		ISig.push({key: "language", value: navigator.language || navigator.userLanguage || navigator.browserLanguage || navigator.systemLanguage || "" });
		ISig.push({key: "color_depth", value: screen.colorDepth || -1 });
		ISig.push({key: "pixel_ratio", value: window.devicePixelRatio || "" });
		ISig.push({key: "hardware_concurrency", value: navigator.hardwareConcurrency });
		ISig.push({key: "resolution", value: [screen.width, screen.height] });
		ISig.push({key: "available_resolution", value: [screen.availHeight, screen.availWidth] });
		ISig.push({key: "timezone_offset", value: new Date().getTimezoneOffset() });
		ISig.push({key: "session_storage", value: !window.sessionStorage });
		ISig.push({key: "local_storage", value: !window.localStorage });
		ISig.push({key: "indexed_db", value: !window.indexedDB });
		ISig.push({key: "open_database", value: !window.openDatabase });
		ISig.push({key: "cpu_class", value: bWAF_GetNavigatorCpuClass() });
		ISig.push({key: "navigator_platform", value: bWAF_GetNavigatorPlatform() });
		ISig.push({key: "do_not_track", value: bWAF_GetDoNotTrack() });
		ISig.push({key: "has_lied_languages", value: bWAF_GetHasLiedLanguages() });
		ISig.push({key: "has_lied_resolution", value: bWAF_GetHasLiedResolution() });
		ISig.push({key: "has_lied_os", value: bWAF_GetHasLiedOs() });
		ISig.push({key: "has_lied_browser", value: bWAF_GetHasLiedBrowser() });
		ISig.push({key: "touch_support", value: bWAF_GetTouchSupport() });
		ISig.push({key: "js_fonts", value: bWAF_JsFontsKey() });
		var sysSig = bWAF_X64hash128(JSON.stringify(ISig),31);

		//浏览器特征
		var JSig = [];
		JSig.push({key: "add_behavior", value: !(document.body && document.body.addBehavior) });
		JSig.push({key: "regular_plugins", value: bWAF_GetRegularPlugins() });
		JSig.push({key: "canvas", value: bWAF_GetCanvasFp() });
		JSig.push({key: "webgl", value: bWAF_GetWebglFp() });
		JSig.push({key: "adblock", value: bWAF_GetAdBlock() });
		var navSig = bWAF_X64hash128(JSON.stringify(JSig),31);
		return sysSig.toString().substr(0, 16) + navSig.toString().substr(0, 16);
	}

	function bWAF_GetNavigatorPlatform(){
		if(navigator.platform) {
			return navigator.platform;
		}else{
			return "unknown";
		}
	}
		
	function bWAF_GetNavigatorCpuClass(){
		if(navigator.cpuClass){
			return navigator.cpuClass;
		}else{
			return "unknown";
		}
	}

	function bWAF_GetDoNotTrack() {
		if(navigator.doNotTrack) {
			return navigator.doNotTrack;
		}else if(navigator.msDoNotTrack) {
			return navigator.msDoNotTrack;
		}else if(window.doNotTrack) {
			return window.doNotTrack;
		}else{
			return "unknown";
		}
	}

	function bWAF_GetRegularPlugins(){
		var plugins = [];
		for(var i = 0, l = navigator.plugins.length; i < l; i++) 
		{
			plugins.push(navigator.plugins[i].name);
		}
		return plugins;
	}

	function bWAF_GetCanvasFp(){
		var result = [];
		var canvas = document.createElement("canvas");
		canvas.width = 2000;
		canvas.height = 200;
		canvas.style.display = "inline";
		var ctx = canvas.getContext("2d");
		ctx.rect(0, 0, 10, 10);
		ctx.rect(2, 2, 6, 6);
		result.push("canvas winding:" + ((ctx.isPointInPath(5, 5, "evenodd") === false) ? "yes" : "no"));
		ctx.textBaseline = "alphabetic";
		ctx.fillStyle = "#f60";
		ctx.fillRect(125, 1, 62, 20);
		ctx.fillStyle = "#069";
		ctx.font = "11pt Arial";
		ctx.fillText("Cwm fjordbank glyphs vext quiz, \ud83d\ude03", 2, 15);
		ctx.fillStyle = "rgba(102, 204, 0, 0.2)";
		ctx.font = "18pt Arial";
		ctx.fillText("Cwm fjordbank glyphs vext quiz, \ud83d\ude03", 4, 45);
		ctx.globalCompositeOperation = "multiply";
		ctx.fillStyle = "rgb(255,0,255)";
		ctx.beginPath();
		ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
		ctx.closePath();
		ctx.fill();
		ctx.fillStyle = "rgb(0,255,255)";
		ctx.beginPath();
		ctx.arc(100, 50, 50, 0, Math.PI * 2, true);
		ctx.closePath();
		ctx.fill();
		ctx.fillStyle = "rgb(255,255,0)";
		ctx.beginPath();
		ctx.arc(75, 100, 50, 0, Math.PI * 2, true);
		ctx.closePath();
		ctx.fill();
		ctx.fillStyle = "rgb(255,0,255)";
		ctx.arc(75, 75, 75, 0, Math.PI * 2, true);
		ctx.arc(75, 75, 25, 0, Math.PI * 2, true);
		ctx.fill("evenodd");
		result.push("canvas fp:" + canvas.toDataURL());
		return result.join("~");
	}

	function bWAF_GetWebglFp() {
		var gl;
		var fa2s = function(fa) {
			gl.clearColor(0.0, 0.0, 0.0, 1.0);
			gl.enable(gl.DEPTH_TEST);
			gl.depthFunc(gl.LEQUAL);
			gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
			return "[" + fa[0] + ", " + fa[1] + "]";
		};
		var maxAnisotropy = function(gl) {
			var anisotropy, ext = gl.getExtension("EXT_texture_filter_anisotropic") || gl.getExtension("WEBKIT_EXT_texture_filter_anisotropic") || gl.getExtension("MOZ_EXT_texture_filter_anisotropic");
			return ext ? (anisotropy = gl.getParameter(ext.MAX_TEXTURE_MAX_ANISOTROPY_EXT), 0 === anisotropy && (anisotropy = 2), anisotropy) : null;
		};
		gl = bWAF_GetWebglCanvas();
		if(!gl) { return null; }
		var result = [];
		var vShaderTemplate = "attribute vec2 attrVertex;varying vec2 varyinTexCoordinate;uniform vec2 uniformOffset;void main(){varyinTexCoordinate=attrVertex+uniformOffset;gl_Position=vec4(attrVertex,0,1);}";
		var fShaderTemplate = "precision mediump float;varying vec2 varyinTexCoordinate;void main() {gl_FragColor=vec4(varyinTexCoordinate,0,1);}";
		var vertexPosBuffer = gl.createBuffer();
		gl.bindBuffer(gl.ARRAY_BUFFER, vertexPosBuffer);
		var vertices = new Float32Array([-.2, -.9, 0, .4, -.26, 0, 0, .732134444, 0]);
		gl.bufferData(gl.ARRAY_BUFFER, vertices, gl.STATIC_DRAW);
		vertexPosBuffer.itemSize = 3;
		vertexPosBuffer.numItems = 3;
		var program = gl.createProgram(), vshader = gl.createShader(gl.VERTEX_SHADER);
		gl.shaderSource(vshader, vShaderTemplate);
		gl.compileShader(vshader);
		var fshader = gl.createShader(gl.FRAGMENT_SHADER);
		gl.shaderSource(fshader, fShaderTemplate);
		gl.compileShader(fshader);
		gl.attachShader(program, vshader);
		gl.attachShader(program, fshader);
		gl.linkProgram(program);
		gl.useProgram(program);
		program.vertexPosAttrib = gl.getAttribLocation(program, "attrVertex");
		program.offsetUniform = gl.getUniformLocation(program, "uniformOffset");
		gl.enableVertexAttribArray(program.vertexPosArray);
		gl.vertexAttribPointer(program.vertexPosAttrib, vertexPosBuffer.itemSize, gl.FLOAT, !1, 0, 0);
		gl.uniform2f(program.offsetUniform, 1, 1);
		gl.drawArrays(gl.TRIANGLE_STRIP, 0, vertexPosBuffer.numItems);
		if (gl.canvas != null) { result.push(gl.canvas.toDataURL()); }
		result.push("extensions:" + gl.getSupportedExtensions().join(";"));
		result.push("webgl aliased line width range:" + fa2s(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)));
		result.push("webgl aliased point size range:" + fa2s(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)));
		result.push("webgl alpha bits:" + gl.getParameter(gl.ALPHA_BITS));
		result.push("webgl antialiasing:" + (gl.getContextAttributes().antialias ? "yes" : "no"));
		result.push("webgl blue bits:" + gl.getParameter(gl.BLUE_BITS));
		result.push("webgl depth bits:" + gl.getParameter(gl.DEPTH_BITS));
		result.push("webgl green bits:" + gl.getParameter(gl.GREEN_BITS));
		result.push("webgl max anisotropy:" + maxAnisotropy(gl));
		result.push("webgl max combined texture image units:" + gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS));
		result.push("webgl max cube map texture size:" + gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE));
		result.push("webgl max fragment uniform vectors:" + gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS));
		result.push("webgl max render buffer size:" + gl.getParameter(gl.MAX_RENDERBUFFER_SIZE));
		result.push("webgl max texture image units:" + gl.getParameter(gl.MAX_TEXTURE_IMAGE_UNITS));
		result.push("webgl max texture size:" + gl.getParameter(gl.MAX_TEXTURE_SIZE));
		result.push("webgl max varying vectors:" + gl.getParameter(gl.MAX_VARYING_VECTORS));
		result.push("webgl max vertex attribs:" + gl.getParameter(gl.MAX_VERTEX_ATTRIBS));
		result.push("webgl max vertex texture image units:" + gl.getParameter(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS));
		result.push("webgl max vertex uniform vectors:" + gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS));
		result.push("webgl max viewport dims:" + fa2s(gl.getParameter(gl.MAX_VIEWPORT_DIMS)));
		result.push("webgl red bits:" + gl.getParameter(gl.RED_BITS));
		result.push("webgl renderer:" + gl.getParameter(gl.RENDERER));
		result.push("webgl shading language version:" + gl.getParameter(gl.SHADING_LANGUAGE_VERSION));
		result.push("webgl stencil bits:" + gl.getParameter(gl.STENCIL_BITS));
		result.push("webgl vendor:" + gl.getParameter(gl.VENDOR));
		result.push("webgl version:" + gl.getParameter(gl.VERSION));
		
		try {
			var extensionDebugRendererInfo = gl.getExtension("WEBGL_debug_renderer_info");
			if (extensionDebugRendererInfo) {
				result.push("webgl unmasked vendor:" + gl.getParameter(extensionDebugRendererInfo.UNMASKED_VENDOR_WEBGL));
				result.push("webgl unmasked renderer:" + gl.getParameter(extensionDebugRendererInfo.UNMASKED_RENDERER_WEBGL));
			}
		} catch(e) { /* squelch */ }
		
		if (!gl.getShaderPrecisionFormat) {
			return result.join("~");
		}
		
		result.push("webgl vertex shader high float precision:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.HIGH_FLOAT ).precision);
		result.push("webgl vertex shader high float precision rangeMin:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.HIGH_FLOAT ).rangeMin);
		result.push("webgl vertex shader high float precision rangeMax:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.HIGH_FLOAT ).rangeMax);
		result.push("webgl vertex shader medium float precision:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.MEDIUM_FLOAT ).precision);
		result.push("webgl vertex shader medium float precision rangeMin:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.MEDIUM_FLOAT ).rangeMin);
		result.push("webgl vertex shader medium float precision rangeMax:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.MEDIUM_FLOAT ).rangeMax);
		result.push("webgl vertex shader low float precision:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.LOW_FLOAT ).precision);
		result.push("webgl vertex shader low float precision rangeMin:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.LOW_FLOAT ).rangeMin);
		result.push("webgl vertex shader low float precision rangeMax:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.LOW_FLOAT ).rangeMax);
		result.push("webgl fragment shader high float precision:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT ).precision);
		result.push("webgl fragment shader high float precision rangeMin:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT ).rangeMin);
		result.push("webgl fragment shader high float precision rangeMax:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_FLOAT ).rangeMax);
		result.push("webgl fragment shader medium float precision:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.MEDIUM_FLOAT ).precision);
		result.push("webgl fragment shader medium float precision rangeMin:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.MEDIUM_FLOAT ).rangeMin);
		result.push("webgl fragment shader medium float precision rangeMax:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.MEDIUM_FLOAT ).rangeMax);
		result.push("webgl fragment shader low float precision:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.LOW_FLOAT ).precision);
		result.push("webgl fragment shader low float precision rangeMin:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.LOW_FLOAT ).rangeMin);
		result.push("webgl fragment shader low float precision rangeMax:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.LOW_FLOAT ).rangeMax);
		result.push("webgl vertex shader high int precision:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.HIGH_INT ).precision);
		result.push("webgl vertex shader high int precision rangeMin:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.HIGH_INT ).rangeMin);
		result.push("webgl vertex shader high int precision rangeMax:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.HIGH_INT ).rangeMax);
		result.push("webgl vertex shader medium int precision:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.MEDIUM_INT ).precision);
		result.push("webgl vertex shader medium int precision rangeMin:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.MEDIUM_INT ).rangeMin);
		result.push("webgl vertex shader medium int precision rangeMax:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.MEDIUM_INT ).rangeMax);
		result.push("webgl vertex shader low int precision:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.LOW_INT ).precision);
		result.push("webgl vertex shader low int precision rangeMin:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.LOW_INT ).rangeMin);
		result.push("webgl vertex shader low int precision rangeMax:" + gl.getShaderPrecisionFormat(gl.VERTEX_SHADER, gl.LOW_INT ).rangeMax);
		result.push("webgl fragment shader high int precision:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_INT ).precision);
		result.push("webgl fragment shader high int precision rangeMin:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_INT ).rangeMin);
		result.push("webgl fragment shader high int precision rangeMax:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.HIGH_INT ).rangeMax);
		result.push("webgl fragment shader medium int precision:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.MEDIUM_INT ).precision);
		result.push("webgl fragment shader medium int precision rangeMin:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.MEDIUM_INT ).rangeMin);
		result.push("webgl fragment shader medium int precision rangeMax:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.MEDIUM_INT ).rangeMax);
		result.push("webgl fragment shader low int precision:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.LOW_INT ).precision);
		result.push("webgl fragment shader low int precision rangeMin:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.LOW_INT ).rangeMin);
		result.push("webgl fragment shader low int precision rangeMax:" + gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER, gl.LOW_INT ).rangeMax);
		return result.join("~");
	}

	function bWAF_GetWebglCanvas() {
		var canvas = document.createElement("canvas");
		var gl = null;
		try {
			gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
		} catch(e) { /* squelch */ }
		if (!gl) { gl = null; }
		return gl;
	}

	function bWAF_GetAdBlock(){
		var ads = document.createElement("div");
		ads.innerHTML = "&nbsp;";
		ads.className = "adsbox";
		var result = false;
		try {
			// body may not exist, that's why we need try/catch
			document.body.appendChild(ads);
			result = document.getElementsByClassName("adsbox")[0].offsetHeight === 0;
			document.body.removeChild(ads);
		} catch (e) {
			result = false;
		}
		return result;
	}

	function bWAF_GetHasLiedLanguages(){
		//We check if navigator.language is equal to the first language of navigator.languages
		if(typeof navigator.languages !== "undefined"){
			try {
				var firstLanguages = navigator.languages[0].substr(0, 2);
				if(firstLanguages !== navigator.language.substr(0, 2)){
					return true;
				}
			} catch(err) {
				return true;
			}
		}
		return false;
	}

	function bWAF_GetHasLiedResolution(){
		if(screen.width < screen.availWidth){
			return true;
		}
		if(screen.height < screen.availHeight){
			return true;
		}
		return false;
	}

	function bWAF_GetHasLiedOs(){
		var userAgent = navigator.userAgent.toLowerCase();
		var oscpu = navigator.oscpu;
		var platform = navigator.platform.toLowerCase();
		var os;
		//We extract the OS from the user agent (respect the order of the if else if statement)
		if(userAgent.indexOf("windows phone") >= 0){
			os = "Windows Phone";
		} else if(userAgent.indexOf("win") >= 0){
			os = "Windows";
		} else if(userAgent.indexOf("android") >= 0){
			os = "Android";
		} else if(userAgent.indexOf("linux") >= 0){
			os = "Linux";
		} else if(userAgent.indexOf("iphone") >= 0 || userAgent.indexOf("ipad") >= 0 ){
			os = "iOS";
		} else if(userAgent.indexOf("mac") >= 0){
			os = "Mac";
		} else{
			os = "Other";
		}
		// We detect if the person uses a mobile device
		var mobileDevice;
		if (("ontouchstart" in window) ||
		(navigator.maxTouchPoints > 0) ||
		(navigator.msMaxTouchPoints > 0)) {
			mobileDevice = true;
		} else{
			mobileDevice = false;
		}
		if(mobileDevice && os !== "Windows Phone" && os !== "Android" && os !== "iOS" && os !== "Other"){
			return true;
		}
		// We compare oscpu with the OS extracted from the UA
		if(typeof oscpu !== "undefined"){
			oscpu = oscpu.toLowerCase();
			if(oscpu.indexOf("win") >= 0 && os !== "Windows" && os !== "Windows Phone"){
				return true;
			} else if(oscpu.indexOf("linux") >= 0 && os !== "Linux" && os !== "Android"){
				return true;
			} else if(oscpu.indexOf("mac") >= 0 && os !== "Mac" && os !== "iOS"){
				return true;
			} else if(oscpu.indexOf("win") === 0 && oscpu.indexOf("linux") === 0 && oscpu.indexOf("mac") >= 0 && os !== "other"){
				return true;
			}
		}
		//We compare platform with the OS extracted from the UA
		if(platform.indexOf("win") >= 0 && os !== "Windows" && os !== "Windows Phone"){
			return true;
		} else if((platform.indexOf("linux") >= 0 || platform.indexOf("android") >= 0 || platform.indexOf("pike") >= 0) && os !== "Linux" && os !== "Android"){
			return true;
		} else if((platform.indexOf("mac") >= 0 || platform.indexOf("ipad") >= 0 || platform.indexOf("ipod") >= 0 || platform.indexOf("iphone") >= 0) && os !== "Mac" && os !== "iOS"){
			return true;
		} else if(platform.indexOf("win") === 0 && platform.indexOf("linux") === 0 && platform.indexOf("mac") >= 0 && os !== "other"){
			return true;
		}
		if(typeof navigator.plugins === "undefined" && os !== "Windows" && os !== "Windows Phone"){
			//We are are in the case where the person uses ie, therefore we can infer that it's windows
			return true;
		}
		return false;
	}

	function bWAF_GetHasLiedBrowser(){
		var userAgent = navigator.userAgent.toLowerCase();
		var productSub = navigator.productSub;
		//we extract the browser from the user agent (respect the order of the tests)
		var browser;
		if(userAgent.indexOf("firefox") >= 0){
			browser = "Firefox";
		} else if(userAgent.indexOf("opera") >= 0 || userAgent.indexOf("opr") >= 0){
			browser = "Opera";
		} else if(userAgent.indexOf("chrome") >= 0){
			browser = "Chrome";
		} else if(userAgent.indexOf("safari") >= 0){
			browser = "Safari";
		} else if(userAgent.indexOf("trident") >= 0){
			browser = "Internet Explorer";
		} else{
			browser = "Other";
		}
		if((browser === "Chrome" || browser === "Safari" || browser === "Opera") && productSub !== "20030107"){
			return true;
		}
		var tempRes = eval.toString().length;
		if(tempRes === 37 && browser !== "Safari" && browser !== "Firefox" && browser !== "Other"){
			return true;
		} else if(tempRes === 39 && browser !== "Internet Explorer" && browser !== "Other"){
			return true;
		} else if(tempRes === 33 && browser !== "Chrome" && browser !== "Opera" && browser !== "Other"){
			return true;
		}
		//We create an error to see how it is handled
		var errFirefox;
		try {
			throw "a";
		} catch(err){
				try{
				err.toSource();
				errFirefox = true;
			} catch(errOfErr){
				errFirefox = false;
			}
		}
		if(errFirefox && browser !== "Firefox" && browser !== "Other"){
			return true;
		}
		return false;
	}

	function bWAF_GetTouchSupport() {
		var maxTouchPoints = 0;
		var touchEvent = false;
		if(typeof navigator.maxTouchPoints !== "undefined") {
			maxTouchPoints = navigator.maxTouchPoints;
		} else if (typeof navigator.msMaxTouchPoints !== "undefined") {
			maxTouchPoints = navigator.msMaxTouchPoints;
		}
		try {
			document.createEvent("TouchEvent");
			touchEvent = true;
		} catch(_) { /* squelch */ }
		var touchStart = "ontouchstart" in window;
		return [maxTouchPoints, touchEvent, touchStart];
	}

	function bWAF_JsFontsKey(done) {
		var keys = [];
		
		// a font will be compared against all the three default fonts.
		// and if it doesn't match all 3 then that font is not available.
		var baseFonts = ["monospace", "sans-serif", "serif"];
		
		var fontList = [
			"Andale Mono", "Arial", "Arial Black", "Arial Hebrew", "Arial MT", "Arial Narrow", "Arial Rounded MT Bold", "Arial Unicode MS",
			"Bitstream Vera Sans Mono", "Book Antiqua", "Bookman Old Style",
			"Calibri", "Cambria", "Cambria Math", "Century", "Century Gothic", "Century Schoolbook", "Comic Sans", "Comic Sans MS", "Consolas", "Courier", "Courier New",
			"Garamond", "Geneva", "Georgia",
			"Helvetica", "Helvetica Neue",
			"Impact",
			"Lucida Bright", "Lucida Calligraphy", "Lucida Console", "Lucida Fax", "LUCIDA GRANDE", "Lucida Handwriting", "Lucida Sans", "Lucida Sans Typewriter", "Lucida Sans Unicode",
			"Microsoft Sans Serif", "Monaco", "Monotype Corsiva", "MS Gothic", "MS Outlook", "MS PGothic", "MS Reference Sans Serif", "MS Sans Serif", "MS Serif", "MYRIAD", "MYRIAD PRO",
			"Palatino", "Palatino Linotype",
			"Segoe Print", "Segoe Script", "Segoe UI", "Segoe UI Light", "Segoe UI Semibold", "Segoe UI Symbol",
			"Tahoma", "Times", "Times New Roman", "Times New Roman PS", "Trebuchet MS",
			"Verdana", "Wingdings", "Wingdings 2", "Wingdings 3"
			];
		var extendedFontList = [
			"Abadi MT Condensed Light", "Academy Engraved LET", "ADOBE CASLON PRO", "Adobe Garamond", "ADOBE GARAMOND PRO", "Agency FB", "Aharoni", "Albertus Extra Bold", "Albertus Medium", "Algerian", "Amazone BT", "American Typewriter",
			"American Typewriter Condensed", "AmerType Md BT", "Andalus", "Angsana New", "AngsanaUPC", "Antique Olive", "Aparajita", "Apple Chancery", "Apple Color Emoji", "Apple SD Gothic Neo", "Arabic Typesetting", "ARCHER",
			"ARNO PRO", "Arrus BT", "Aurora Cn BT", "AvantGarde Bk BT", "AvantGarde Md BT", "AVENIR", "Ayuthaya", "Bandy", "Bangla Sangam MN", "Bank Gothic", "BankGothic Md BT", "Baskerville",
			"Baskerville Old Face", "Batang", "BatangChe", "Bauer Bodoni", "Bauhaus 93", "Bazooka", "Bell MT", "Bembo", "Benguiat Bk BT", "Berlin Sans FB", "Berlin Sans FB Demi", "Bernard MT Condensed", "BernhardFashion BT", "BernhardMod BT", "Big Caslon", "BinnerD",
			"Blackadder ITC", "BlairMdITC TT", "Bodoni 72", "Bodoni 72 Oldstyle", "Bodoni 72 Smallcaps", "Bodoni MT", "Bodoni MT Black", "Bodoni MT Condensed", "Bodoni MT Poster Compressed",
			"Bookshelf Symbol 7", "Boulder", "Bradley Hand", "Bradley Hand ITC", "Bremen Bd BT", "Britannic Bold", "Broadway", "Browallia New", "BrowalliaUPC", "Brush Script MT", "Californian FB", "Calisto MT", "Calligrapher", "Candara",
			"CaslonOpnface BT", "Castellar", "Centaur", "Cezanne", "CG Omega", "CG Times", "Chalkboard", "Chalkboard SE", "Chalkduster", "Charlesworth", "Charter Bd BT", "Charter BT", "Chaucer",
			"ChelthmITC Bk BT", "Chiller", "Clarendon", "Clarendon Condensed", "CloisterBlack BT", "Cochin", "Colonna MT", "Constantia", "Cooper Black", "Copperplate", "Copperplate Gothic", "Copperplate Gothic Bold",
			"Copperplate Gothic Light", "CopperplGoth Bd BT", "Corbel", "Cordia New", "CordiaUPC", "Cornerstone", "Coronet", "Cuckoo", "Curlz MT", "DaunPenh", "Dauphin", "David", "DB LCD Temp", "DELICIOUS", "Denmark",
			"DFKai-SB", "Didot", "DilleniaUPC", "DIN", "DokChampa", "Dotum", "DotumChe", "Ebrima", "Edwardian Script ITC", "Elephant", "English 111 Vivace BT", "Engravers MT", "EngraversGothic BT", "Eras Bold ITC", "Eras Demi ITC", "Eras Light ITC", "Eras Medium ITC",
			"EucrosiaUPC", "Euphemia", "Euphemia UCAS", "EUROSTILE", "Exotc350 Bd BT", "FangSong", "Felix Titling", "Fixedsys", "FONTIN", "Footlight MT Light", "Forte",
			"FrankRuehl", "Fransiscan", "Freefrm721 Blk BT", "FreesiaUPC", "Freestyle Script", "French Script MT", "FrnkGothITC Bk BT", "Fruitger", "FRUTIGER",
			"Futura", "Futura Bk BT", "Futura Lt BT", "Futura Md BT", "Futura ZBlk BT", "FuturaBlack BT", "Gabriola", "Galliard BT", "Gautami", "Geeza Pro", "Geometr231 BT", "Geometr231 Hv BT", "Geometr231 Lt BT", "GeoSlab 703 Lt BT",
			"GeoSlab 703 XBd BT", "Gigi", "Gill Sans", "Gill Sans MT", "Gill Sans MT Condensed", "Gill Sans MT Ext Condensed Bold", "Gill Sans Ultra Bold", "Gill Sans Ultra Bold Condensed", "Gisha", "Gloucester MT Extra Condensed", "GOTHAM", "GOTHAM BOLD",
			"Goudy Old Style", "Goudy Stout", "GoudyHandtooled BT", "GoudyOLSt BT", "Gujarati Sangam MN", "Gulim", "GulimChe", "Gungsuh", "GungsuhChe", "Gurmukhi MN", "Haettenschweiler", "Harlow Solid Italic", "Harrington", "Heather", "Heiti SC", "Heiti TC", "HELV",
			"Herald", "High Tower Text", "Hiragino Kaku Gothic ProN", "Hiragino Mincho ProN", "Hoefler Text", "Humanst 521 Cn BT", "Humanst521 BT", "Humanst521 Lt BT", "Imprint MT Shadow", "Incised901 Bd BT", "Incised901 BT",
			"Incised901 Lt BT", "INCONSOLATA", "Informal Roman", "Informal011 BT", "INTERSTATE", "IrisUPC", "Iskoola Pota", "JasmineUPC", "Jazz LET", "Jenson", "Jester", "Jokerman", "Juice ITC", "Kabel Bk BT", "Kabel Ult BT", "Kailasa", "KaiTi", "Kalinga", "Kannada Sangam MN",
			"Kartika", "Kaufmann Bd BT", "Kaufmann BT", "Khmer UI", "KodchiangUPC", "Kokila", "Korinna BT", "Kristen ITC", "Krungthep", "Kunstler Script", "Lao UI", "Latha", "Leelawadee", "Letter Gothic", "Levenim MT", "LilyUPC", "Lithograph", "Lithograph Light", "Long Island",
			"Lydian BT", "Magneto", "Maiandra GD", "Malayalam Sangam MN", "Malgun Gothic",
			"Mangal", "Marigold", "Marion", "Marker Felt", "Market", "Marlett", "Matisse ITC", "Matura MT Script Capitals", "Meiryo", "Meiryo UI", "Microsoft Himalaya", "Microsoft JhengHei", "Microsoft New Tai Lue", "Microsoft PhagsPa", "Microsoft Tai Le",
			"Microsoft Uighur", "Microsoft YaHei", "Microsoft Yi Baiti", "MingLiU", "MingLiU_HKSCS", "MingLiU_HKSCS-ExtB", "MingLiU-ExtB", "Minion", "Minion Pro", "Miriam", "Miriam Fixed", "Mistral", "Modern", "Modern No. 20", "Mona Lisa Solid ITC TT", "Mongolian Baiti",
			"MONO", "MoolBoran", "Mrs Eaves", "MS LineDraw", "MS Mincho", "MS PMincho", "MS Reference Specialty", "MS UI Gothic", "MT Extra", "MUSEO", "MV Boli",
			"Nadeem", "Narkisim", "NEVIS", "News Gothic", "News GothicMT", "NewsGoth BT", "Niagara Engraved", "Niagara Solid", "Noteworthy", "NSimSun", "Nyala", "OCR A Extended", "Old Century", "Old English Text MT", "Onyx", "Onyx BT", "OPTIMA", "Oriya Sangam MN",
			"OSAKA", "OzHandicraft BT", "Palace Script MT", "Papyrus", "Parchment", "Party LET", "Pegasus", "Perpetua", "Perpetua Titling MT", "PetitaBold", "Pickwick", "Plantagenet Cherokee", "Playbill", "PMingLiU", "PMingLiU-ExtB",
			"Poor Richard", "Poster", "PosterBodoni BT", "PRINCETOWN LET", "Pristina", "PTBarnum BT", "Pythagoras", "Raavi", "Rage Italic", "Ravie", "Ribbon131 Bd BT", "Rockwell", "Rockwell Condensed", "Rockwell Extra Bold", "Rod", "Roman", "Sakkal Majalla",
			"Santa Fe LET", "Savoye LET", "Sceptre", "Script", "Script MT Bold", "SCRIPTINA", "Serifa", "Serifa BT", "Serifa Th BT", "ShelleyVolante BT", "Sherwood",
			"Shonar Bangla", "Showcard Gothic", "Shruti", "Signboard", "SILKSCREEN", "SimHei", "Simplified Arabic", "Simplified Arabic Fixed", "SimSun", "SimSun-ExtB", "Sinhala Sangam MN", "Sketch Rockwell", "Skia", "Small Fonts", "Snap ITC", "Snell Roundhand", "Socket",
			"Souvenir Lt BT", "Staccato222 BT", "Steamer", "Stencil", "Storybook", "Styllo", "Subway", "Swis721 BlkEx BT", "Swiss911 XCm BT", "Sylfaen", "Synchro LET", "System", "Tamil Sangam MN", "Technical", "Teletype", "Telugu Sangam MN", "Tempus Sans ITC",
			"Terminal", "Thonburi", "Traditional Arabic", "Trajan", "TRAJAN PRO", "Tristan", "Tubular", "Tunga", "Tw Cen MT", "Tw Cen MT Condensed", "Tw Cen MT Condensed Extra Bold",
			"TypoUpright BT", "Unicorn", "Univers", "Univers CE 55 Medium", "Univers Condensed", "Utsaah", "Vagabond", "Vani", "Vijaya", "Viner Hand ITC", "VisualUI", "Vivaldi", "Vladimir Script", "Vrinda", "Westminster", "WHITNEY", "Wide Latin",
			"ZapfEllipt BT", "ZapfHumnst BT", "ZapfHumnst Dm BT", "Zapfino", "Zurich BlkEx BT", "Zurich Ex BT", "ZWAdobeF"
			];
		
		fontList = fontList.concat(extendedFontList);
		
		//we use m or w because these two characters take up the maximum width.
		// And we use a LLi so that the same matching fonts can get separated
		var testString = "mmmmmmmmmmlli";
		
		//we test using 72px font size, we may use any size. I guess larger the better.
		var testSize = "72px";
		
		var h = document.getElementsByTagName("body")[0];
		//var h =document.createElement("div");
		
		// div to load spans for the base fonts
		var baseFontsDiv = document.createElement("div");
		
		// div to load spans for the fonts to detect
		var fontsDiv = document.createElement("div");
		
		var defaultWidth = {};
		var defaultHeight = {};
		
		// creates a span where the fonts will be loaded
		var createSpan = function() {
			var s = document.createElement("span");
			/*
			* We need this css as in some weird browser this
			* span elements shows up for a microSec which creates a
			* bad user experience
			*/
			s.style.position = "absolute";
			s.style.left = "-9999px";
			s.style.fontSize = testSize;
			s.style.lineHeight = "normal";
			s.innerHTML = testString;
			return s;
		};
		
		// creates a span and load the font to detect and a base font for fallback
		var createSpanWithFonts = function(fontToDetect, baseFont) {
			var s = createSpan();
			s.style.fontFamily = "'" + fontToDetect + "'," + baseFont;
			return s;
		};
		
		// creates spans for the base fonts and adds them to baseFontsDiv
		var initializeBaseFontsSpans = function() {
			var spans = [];
			for (var index = 0, length = baseFonts.length; index < length; index++) {
				var s = createSpan();
				s.style.fontFamily = baseFonts[index];
				baseFontsDiv.appendChild(s);
				spans.push(s);
			}
			return spans;
		};
		
		// creates spans for the fonts to detect and adds them to fontsDiv
		var initializeFontsSpans = function() {
			var spans = {};
			for(var i = 0, l = fontList.length; i < l; i++) {
				var fontSpans = [];
				for(var j = 0, numDefaultFonts = baseFonts.length; j < numDefaultFonts; j++) {
					var s = createSpanWithFonts(fontList[i], baseFonts[j]);
					fontsDiv.appendChild(s);
					fontSpans.push(s);
				}
				spans[fontList[i]] = fontSpans; // Stores {fontName : [spans for that font]}
			}
			return spans;
		};
		
		// checks if a font is available
		var isFontAvailable = function(fontSpans) {
			var detected = false;
			for(var i = 0; i < baseFonts.length; i++) {
				detected = (fontSpans[i].offsetWidth !== defaultWidth[baseFonts[i]] || fontSpans[i].offsetHeight !== defaultHeight[baseFonts[i]]);
				if(detected) {
					return detected;
				}
			}
			return detected;
		};
		
		// create spans for base fonts
		var baseFontsSpans = initializeBaseFontsSpans();
		
		// add the spans to the DOM
		h.appendChild(baseFontsDiv);
		
		// get the default width for the three base fonts
		for (var index = 0, length = baseFonts.length; index < length; index++) {
			// width for the default font
			defaultWidth[baseFonts[index]] = baseFontsSpans[index].offsetWidth; 
			// height for the default font
			defaultHeight[baseFonts[index]] = baseFontsSpans[index].offsetHeight; 
		}
		
		// create spans for fonts to detect
		var fontsSpans = initializeFontsSpans();
		
		// add all the spans to the DOM
		h.appendChild(fontsDiv);
		
		// check available fonts
		var available = [];
		for(var i = 0, l = fontList.length; i < l; i++) {
			if(isFontAvailable(fontsSpans[fontList[i]])) {
				available.push(fontList[i]);
			}
		}
		
		// remove spans from DOM
		h.removeChild(fontsDiv);
		h.removeChild(baseFontsDiv);
		
		keys.push({key: "js_fonts", value: available});
		return keys;
	}

	function bWAF_X64hash128(key, seed) {
		key = key || "";
		seed = seed || 0;
		var remainder = key.length % 16;
		var bytes = key.length - remainder;
		var h1 = [0, seed];
		var h2 = [0, seed];
		var k1 = [0, 0];
		var k2 = [0, 0];
		var c1 = [0x87c37b91, 0x114253d5];
		var c2 = [0x4cf5ad43, 0x2745937f];
		for (var i = 0; i < bytes; i = i + 16) {
			k1 = [((key.charCodeAt(i + 4) & 0xff)) | ((key.charCodeAt(i + 5) & 0xff) << 8) | ((key.charCodeAt(i + 6) & 0xff) << 16) | ((key.charCodeAt(i + 7) & 0xff) << 24), ((key.charCodeAt(i) & 0xff)) | ((key.charCodeAt(i + 1) & 0xff) << 8) | ((key.charCodeAt(i + 2) & 0xff) << 16) | ((key.charCodeAt(i + 3) & 0xff) << 24)];
			k2 = [((key.charCodeAt(i + 12) & 0xff)) | ((key.charCodeAt(i + 13) & 0xff) << 8) | ((key.charCodeAt(i + 14) & 0xff) << 16) | ((key.charCodeAt(i + 15) & 0xff) << 24), ((key.charCodeAt(i + 8) & 0xff)) | ((key.charCodeAt(i + 9) & 0xff) << 8) | ((key.charCodeAt(i + 10) & 0xff) << 16) | ((key.charCodeAt(i + 11) & 0xff) << 24)];
			k1 = bWAF_X64Multiply(k1, c1);
			k1 = bWAF_X64Rotl(k1, 31);
			k1 = bWAF_X64Multiply(k1, c2);
			h1 = bWAF_X64Xor(h1, k1);
			h1 = bWAF_X64Rotl(h1, 27);
			h1 = bWAF_X64Add(h1, h2);
			h1 = bWAF_X64Add(bWAF_X64Multiply(h1, [0, 5]), [0, 0x52dce729]);
			k2 = bWAF_X64Multiply(k2, c2);
			k2 = bWAF_X64Rotl(k2, 33);
			k2 = bWAF_X64Multiply(k2, c1);
			h2 = bWAF_X64Xor(h2, k2);
			h2 = bWAF_X64Rotl(h2, 31);
			h2 = bWAF_X64Add(h2, h1);
			h2 = bWAF_X64Add(bWAF_X64Multiply(h2, [0, 5]), [0, 0x38495ab5]);
		}
		k1 = [0, 0];
		k2 = [0, 0];
		switch(remainder) {
			case 15:
				k2 = bWAF_X64Xor(k2, bWAF_X64LeftShift([0, key.charCodeAt(i + 14)], 48));
			case 14:
				k2 = bWAF_X64Xor(k2, bWAF_X64LeftShift([0, key.charCodeAt(i + 13)], 40));
			case 13:
				k2 = bWAF_X64Xor(k2, bWAF_X64LeftShift([0, key.charCodeAt(i + 12)], 32));
			case 12:
				k2 = bWAF_X64Xor(k2, bWAF_X64LeftShift([0, key.charCodeAt(i + 11)], 24));
			case 11:
				k2 = bWAF_X64Xor(k2, bWAF_X64LeftShift([0, key.charCodeAt(i + 10)], 16));
			case 10:
				k2 = bWAF_X64Xor(k2, bWAF_X64LeftShift([0, key.charCodeAt(i + 9)], 8));
			case 9:
				k2 = bWAF_X64Xor(k2, [0, key.charCodeAt(i + 8)]);
				k2 = bWAF_X64Multiply(k2, c2);
				k2 = bWAF_X64Rotl(k2, 33);
				k2 = bWAF_X64Multiply(k2, c1);
				h2 = bWAF_X64Xor(h2, k2);
			case 8:
				k1 = bWAF_X64Xor(k1, bWAF_X64LeftShift([0, key.charCodeAt(i + 7)], 56));
			case 7:
				k1 = bWAF_X64Xor(k1, bWAF_X64LeftShift([0, key.charCodeAt(i + 6)], 48));
			case 6:
				k1 = bWAF_X64Xor(k1, bWAF_X64LeftShift([0, key.charCodeAt(i + 5)], 40));
			case 5:
				k1 = bWAF_X64Xor(k1, bWAF_X64LeftShift([0, key.charCodeAt(i + 4)], 32));
			case 4:
				k1 = bWAF_X64Xor(k1, bWAF_X64LeftShift([0, key.charCodeAt(i + 3)], 24));
			case 3:
				k1 = bWAF_X64Xor(k1, bWAF_X64LeftShift([0, key.charCodeAt(i + 2)], 16));
			case 2:
				k1 = bWAF_X64Xor(k1, bWAF_X64LeftShift([0, key.charCodeAt(i + 1)], 8));
			case 1:
				k1 = bWAF_X64Xor(k1, [0, key.charCodeAt(i)]);
				k1 = bWAF_X64Multiply(k1, c1);
				k1 = bWAF_X64Rotl(k1, 31);
				k1 = bWAF_X64Multiply(k1, c2);
				h1 = bWAF_X64Xor(h1, k1);
		}
		h1 = bWAF_X64Xor(h1, [0, key.length]);
		h2 = bWAF_X64Xor(h2, [0, key.length]);
		h1 = bWAF_X64Add(h1, h2);
		h2 = bWAF_X64Add(h2, h1);
		h1 = bWAF_X64Fmix(h1);
		h2 = bWAF_X64Fmix(h2);
		h1 = bWAF_X64Add(h1, h2);
		h2 = bWAF_X64Add(h2, h1);
		return ("00000000" + (h1[0] >>> 0).toString(16)).slice(-8) + ("00000000" + (h1[1] >>> 0).toString(16)).slice(-8) + ("00000000" + (h2[0] >>> 0).toString(16)).slice(-8) + ("00000000" + (h2[1] >>> 0).toString(16)).slice(-8);
	}

	function bWAF_X64LeftShift(m, n){
		n %= 64;
		if (n === 0) {
			return m;
		}
		else if (n < 32) {
			return [(m[0] << n) | (m[1] >>> (32 - n)), m[1] << n];
		}
		else {
			return [m[1] << (n - 32), 0];
		}
	}

	function bWAF_X64Multiply(m, n) {
		m = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff];
		n = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff];
		var o = [0, 0, 0, 0];
		o[3] += m[3] * n[3];
		o[2] += o[3] >>> 16;
		o[3] &= 0xffff;
		o[2] += m[2] * n[3];
		o[1] += o[2] >>> 16;
		o[2] &= 0xffff;
		o[2] += m[3] * n[2];
		o[1] += o[2] >>> 16;
		o[2] &= 0xffff;
		o[1] += m[1] * n[3];
		o[0] += o[1] >>> 16;
		o[1] &= 0xffff;
		o[1] += m[2] * n[2];
		o[0] += o[1] >>> 16;
		o[1] &= 0xffff;
		o[1] += m[3] * n[1];
		o[0] += o[1] >>> 16;
		o[1] &= 0xffff;
		o[0] += (m[0] * n[3]) + (m[1] * n[2]) + (m[2] * n[1]) + (m[3] * n[0]);
		o[0] &= 0xffff;
		return [(o[0] << 16) | o[1], (o[2] << 16) | o[3]];
	}

	function bWAF_X64Rotl(m, n) {
		n %= 64;
		if (n === 32) {
			return [m[1], m[0]];
		}
		else if (n < 32) {
			return [(m[0] << n) | (m[1] >>> (32 - n)), (m[1] << n) | (m[0] >>> (32 - n))];
		}
		else {
			n -= 32;
			return [(m[1] << n) | (m[0] >>> (32 - n)), (m[0] << n) | (m[1] >>> (32 - n))];
		}
	}

	function bWAF_X64Xor(m, n) {
		return [m[0] ^ n[0], m[1] ^ n[1]];
	}

	function bWAF_X64Add(m, n) {
		m = [m[0] >>> 16, m[0] & 0xffff, m[1] >>> 16, m[1] & 0xffff];
		n = [n[0] >>> 16, n[0] & 0xffff, n[1] >>> 16, n[1] & 0xffff];
		var o = [0, 0, 0, 0];
		o[3] += m[3] + n[3];
		o[2] += o[3] >>> 16;
		o[3] &= 0xffff;
		o[2] += m[2] + n[2];
		o[1] += o[2] >>> 16;
		o[2] &= 0xffff;
		o[1] += m[1] + n[1];
		o[0] += o[1] >>> 16;
		o[1] &= 0xffff;
		o[0] += m[0] + n[0];
		o[0] &= 0xffff;
		return [(o[0] << 16) | o[1], (o[2] << 16) | o[3]];
	}

	function bWAF_X64Fmix(h) {
		h = bWAF_X64Xor(h, [0, h[0] >>> 1]);
		h = bWAF_X64Multiply(h, [0xff51afd7, 0xed558ccd]);
		h = bWAF_X64Xor(h, [0, h[0] >>> 1]);
		h = bWAF_X64Multiply(h, [0xc4ceb9fe, 0x1a85ec53]);
		h = bWAF_X64Xor(h, [0, h[0] >>> 1]);
		return h;
	}
}

/* 使用ajax方式与BrowserWAF后台通迅，提交浏览器指纹 */
{
	function ajax_insert_browserid(){
		
		if( typeof $ == "undefined"){
			console.error("BrowserWAF Error: JQuery not loaded");
			
		}else{

			if(window.location.protocol.toString().toLowerCase() == "https:"){
				$.ajax({

					type:'post',
					url:'https://123.57.9.93:444/insert/',
					data:{
						browserid : BrowserWAF_BrowserID,
						host : window.location.host,
						url: window.location.href
					},

					//错误
					error:function(err){
						console.error("BrowserWAF Error:", err)
					}
				})
			}else{
				$.ajax({

					type:'post',
					url:'http://123.57.9.93:81/insert/',
					data:{
						browserid : BrowserWAF_BrowserID,
						host : window.location.host,
						url: window.location.href
					},

					//错误
					error:function(err){
						console.error("BrowserWAF Error:", err)
					}
				})
			}
		}
	}

	//-------------------------------------------------//
	// 向BrwoserWAF后台查询浏览器指纹信息
	// 如果检测到是恶意的指纹，返回值为1，则阻止访问
	//-------------------------------------------------//
	function ajax_query_browserid(){
		
		//判断Jquery库是否被引用
		if( typeof $ == "undefined"){
			console.error("BrowserWAF Error: JQuery not loaded");
			
		}else{

			//两种请求方式：Http和Https方式
			if(window.location.protocol.toString().toLowerCase() == "https:"){
				$.ajax({

					type: "post",
					url: "https://123.57.9.93:444/query/",
					data: {
						browserid : BrowserWAF_BrowserID
					},
				
					//成功
					success:function(return_value){
	
						//返回的数据
						console.log("BrowserWAF ajax query rowserID return value :", return_value);
		
						//返回值为1，意味着浏览器指纹在黑名单中，访问会被阻止
						if (return_value == 1){

							console.log("BrowserWAF ajax rule block the visit", return_value);
							document.body.innerHTML = bWAF_warning;
						}
					},
				
					//错误
					error:function(err){
						console.error("BrowserWAF Error:", err)
					}
				})
			}else{
				$.ajax({

					type: "post",
					url: "http://123.57.9.93:81/query/",
					data: {
						browserid : BrowserWAF_BrowserID
					},
				
					//成功
					success:function(return_value){
	
						//返回的数据
						console.log("BrowserWAF ajax query rowserID return value :", return_value);
		
						//返回值为1，意味着浏览器指纹在黑名单中，访问会被阻止
						if (return_value == 1){
							console.log("BrowserWAF ajax rule block the visit", return_value);
							document.body.innerHTML = bWAF_warning;
						}
					},
				
					//错误
					error:function(err){
						console.error("BrowserWAF Error:", err)
					}
				})
			}
			
		}
	}
}
