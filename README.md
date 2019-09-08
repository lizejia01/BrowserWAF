# BrowserWAF
Browser side waf

# Auther
王二狗（WangErGou）

http://www.ShareWAF.com/BrowserWAF/

Email：6465660@qq.com

微信/Tel：13015406167

语言：JavaScript（JS）

<img src="http://www.sharewaf.com/browserwaf/me.jpg" style="max-width:290px;width:100%;"/><br>

# 功能
运行于浏览器端的WAF、轻量化的WAF、开源WAF。用于保护网站（含H5功能页、游戏、小程序）、防多种常见网络攻击。

BrowserWAF是先驱、探索性的新型WAF，应该是互联网首个部署于浏览器端的WAF，其前身是ShareWAF（ http://www.sharewaf.com ）的前端WAF模块。

具体防护功能：

* 1、防自动化攻击。如：撞库、暴力破解、批量注册、批量发贴回复、自动按键软件等；
* 2、指纹防护。通过大数据指纹库识别来防者，自动拦截黑名单访客；
* 3、防SQL注入、文件包含、目录遍历等（传统WAF功能）；
* 4、防CRSF攻击；
* 5、防Iframe框架嵌套；
* 6、防爬虫；
* 7、防XSS；

更多功能持续开发中...

与传统WAF相比，有优势也有不足：

优势：
1、简单方便：传统WAF部署、使用繁杂。BrowserWAF在浏览器加载，1行代码引用，10行代码完成部署；
2、维护：BrowserWAF几乎无维护工作；
3、性能：传统WAF由于是反向代理或透明代理，对所有达到Web的数据都要过滤处理，因此对性能有较大损失，BrowserWAF运行于网页中，无乎无性能影响；
4、兼容性良好、不影响原业务功能；

不足：
* 1、防护效果报表不够详尽（额……报表功能正在开发中，目前尚未推出:D）；
* 2、防护功能无法覆盖某些攻击，如：COOKIE注入、重放、嗅探等。

# 适用场景
* 1、传统WAF的补充、多加一重防护，多一重安全；
* 2、防护强度要求不是特别高的网站，如中小企业、个人网站。

# 接入
需要引用JQuery和BrowserWAF两个JS文件，代码如下：

注：这段代码放在body中，所有内容之后body结束之前。

```javascript
<!-- 引用JQuery库，可为其它版本，可从本地下载-->
<script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>
<!-- 引用BrowserWAF库，可放到本地，可用http或https方式 -->
<script src="http://www.sharewaf.com/browserwaf/BrowserWAF.js"></script>
<script>
    //参数，控制各功能是否启用，1为启用，0为不启用
    var config = {
        //防自动化攻击
        Defend_Automated_Attack_Enable : 1,
        //浏览器指纹识别防护
        BrowserID_Enable : 1,
        //防SQL注入、文件包含、目录遍历等功能
        Defend_Sql_Inject_Enable : 1,
        //防CRSF攻
        Defend_CRSF_Enable : 1,
        //防Iframe嵌套
        Defend_Iframe_Enable : 0,
        //防爬虫、按键模拟
        Defend_Spider_Enable : 1,
        //防XSS攻击
        Defend_XSS_Enable : 0,
    }
    //启动BrowserWAF
    BrowserWAF_Run(config);
</script>        
```
# 效果
* 1、防SQL注入
<img src="http://www.sharewaf.com/browserwaf/sql_inj.gif" style="max-width:654px;width:100%;"/>

说明：在URL中检测到SQL注入等语句时，访问会被拦截。

注：实际使用时，除URL，也检测输入框内容。

* 2、浏览器指纹识别拦截
<img src="http://www.sharewaf.com/browserwaf/browser_id.gif" style="max-width:654px;width:100%;"/>

说明：如果浏览器指纹已在BrowserWAF指纹库中，访问会被直接拦截。

留意：动画中右方向cmd窗口中是存入BrowserWAF指纹库中的指纹，还有浏览器中显示出的BrowserID，这两者相同。

该技术类似外界传言的AI识别、大数据（大案犊术？）。其实，本质上就是匹配识别罢了（吁：不足为外人道也）。

不过，这种技术方案，也确实管用和实用。

理论原理：所有接入了BrowserWAF的网站，都是恶意指纹的采集提供者，同时也是受益方，因为数据是共享的。有种：One for all，All for one的意味。

* 3、防爬虫、防自动化攻击

<img src="http://www.sharewaf.com/browserwaf/spider.gif" style="max-width:654px;width:100%;"/>

* 防自动化攻击：
如动画中，浏览器下方，开始时候密码输入框的id和name都为空，也就意味着通过识别元素id和name属性的方式，是无法被定位到的，那么也就无法进行自动赋值，也就无法进行暴力破解、撞库等攻击（burp嗅探重放式的除外）。

同时，注意有一个属性为hidden的input框。它是被随机插入在页面中的，这样也就可以防止使用xpath方式定位的攻击。
* 防爬虫：
注意链接元素，起初href是为空的。那么，通过从页面中获取href方式的爬虫，就无法获取链接，将无法工作。

但href为空的链接，还是可以正常点击使用的，被点击后，href会被还原。（注：测试时，示例中的地址本身就是不存在的，所以打开的是404页面）。

更多示例正在制作中...

# 捐助
<img src="http://www.sharewaf.com/browserwaf/mei_ye.jpg" style="max-width:634px;width:100%;"/>

<img src="http://www.sharewaf.com/browserwaf/wx.jpg" style="max-width:522px;width:100%;"/>

谢谢
