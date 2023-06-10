Attention: 
1. 由于中国的中考，我将停止一段时间来编辑这个文件。当我再次有空时，我将继续把各文件夹中的文章编进readme.md中，毕竟各文件夹内的文档可视性并不高(I will be taking a break from working on this document for a while due to the senior high school entrance exams in China. When I am free again, I will continue to compile the articles in the various folders into a readme.md. After all, there is not much visibility of the documents in each folder.)
2. 在阅读各内容之前，建议先阅读rules.md文件(It is recommended to read the rules.md file before reading the individual contents.)
3. 我的英语水平非常差，所以本文中的英文可能会出现一些差错，如果发现比较奇怪的英语语法或内容时，建议使用翻译器翻译上方的中文，请谅解(My English is very poor, so there may be some errors in the English in this article. If you find strange English grammar or content, please understand that you are advised to use a translator to translate the Chinese above.)
4. 本文章内的所有内容均以中文呈现。本作者现在正在学习英语，现只到达托福60分的水准，等到以后我的英语学习之路基本完成，我会继续编写英文版内容，请谅解(All content in this article is presented in Chinese. The author is currently studying English and has only reached a TOEFL score of 60. Please understand that I will continue to write English content when my English learning journey is basically complete.)
5. 文段中存在重复的问题的地方，会只在一处地方讲解(Where there are repetitive questions in the passage, they will be explained in one place only.)
6. 一些重要内容会用红色标注，标题会用黄色标注，但颜色不会在github界面显示，如果可以，请调至code模式观看，如果将文档下载至本地，则建议使用深色界面观看(Some important content will be marked in red, title will be marked in yellow, but the colour will not be displayed in the github interface, if possible, please turn to code mode to watch, if you are downloading a document locally, it is recommended that you use the dark interface to view it)
7. 如果现在有需要阅读英文版的文章，请使用翻译器辅助阅读(推荐使用chatGPT进行翻译，因为翻译器不能完整且准确地表达出本文中的专业性知识，若使用chatGPT，建议给一个前情提要)(If you now have to read the English version of the article, please use a translator to assist you in reading it. (It is recommended to use chatGPT for translation, as the translator does not give a complete and accurate representation of the expertise in this article, if you use chatGPT, it is recommended to give a foreword.))
8. 如果我的文章中存在任何问题，欢迎大家指出(If there are any problems in my article, please feel free to point them out.)

csdn address:[hackjacking.blog.csdn.net](https://hackjacking.blog.csdn.net/)

# Web

参考资料来源于
- CSDN
- GitHub
- Google
- 维基百科
- YouTube
- MDN Web Docs
- 其他小型网站与书籍

## <font color="yellow">0x00世界观安全</font>

### <font color="yellow">01 Web发展史</font>

#### <font color="yellow">001 静态网页的诞生</font>

> 1989年，在欧洲粒子物理实验室(粒子物理研究通常与来自世界各地的研究所进行合作)的IT部门工作的Tim Berners-Lee向其领导提出了一项名为Information Management: A Proposal的提议：使来自世界各地的远程站点的研究人员能够组织和汇集信息，在个人计算机上访问大量的科研文献，并建议在文档中链接其他文档，这就是Web的原型
>
> 1990年，Tim以超文本语言HTML为基础在NeXT电脑上发明了最原始的Web浏览器
>
> 1991年，Tim作为布道者在Internet上广泛推广Web的理念，与此同时，美国国家超算应用中心(National Center for Supercomputer Applications)对此表现出了浓厚的兴趣，并开发了名为Mosaic的浏览器，于1993年4月进行了发布
>
> 1994年5月，第一届万维网大会在日内瓦召开
>
> 1994年7月，HTML2规范发布
>
> 1994年9月，因特网工程任务组(Internet Engineering Task Force)设立了HTML工作组
>
> 1994年11月，Mosaic浏览器的开发人员创建了网景公司(Netscape Communications Corp.)，并发布了Mosaic Netscape 1.0 beta浏览器，后改名为Navigator

#### <font color="yellow">002 万维网(W3C)诞生</font>

> 1994年底，由Tim牵头的万维网联盟(World Wide Web Consortium)成立，这标志着万维网的正式诞生
>
> 此时的网页以HTML为主，是纯静态的网页，网页是“只读”的，信息流只能通过服务器到客户端单向流通，由此世界进入了Web 1.0时代
>
> W3C在1994年被创建的目的是，为了完成麻省理工学院(MIT)与欧洲粒子物理研究所(CERN)之间的协同工作，并得到了美国国防部高级研究计划局(DARPA)和欧洲委员会(European Commission)的支持
>
> W3C最重要的工作是发展Web规范(称为推荐，Recommendations)，这些规范描述了Web的通信协议(比如HTML和XHTML)和其他的构建模块

#### <font color="yellow">003 JavaScript的诞生</font>

> 1995年，网景工程师Brendan Eich花了10天时间设计了JavaScript语言。起初这种脚本语言叫做Mocha，后改名LiveScript，后来为了借助Java语言创造良好的营销效果最终改名为JavaScript。网景公司把这种脚本语言嵌入到了Navigator 2.0之中，使其能在浏览器中运行
>
> 与此相对的是，1996年，微软发布了VBScript和JScript。JScript是对JavaScript进行逆向工程的实现，并内置于Internet Explorer 3中。但是JavaScript与JScript两种语言的实现存在差别，这导致了程序员开发的网页不能同时兼容Navigator和Internet Explorer浏览器。Internet Explorer开始抢夺Netscape的市场份额，这导致了第一次浏览器战争

#### <font color="yellow">004 第一次浏览器战争</font>

> Netscape的市场份额逐年萎缩
>
> 1996年11月，为了确保JavaScript的市场领导地位，网景将JavaScript提交到欧洲计算机制造商协会（European Computer Manufacturers Association）以便将其进行国际标准化
> 
> 1997年6月，ECMA以JavaScript语言为基础制定了ECMAScript标准规范ECMA-262。JavaScript是ECMAScript规范最著名的实现之一，除此之外，ActionScript和JScript也都是ECMAScript规范的实现语言。自此，浏览器厂商都开始逐步实现ECMAScript规范
> 
> 1998年6月，ECMAScript2规范发布，并通过ISO生成了正式的国际标准ISO/IEC 16262
> 
> 1999年12月，ECMAScript3规范发布，在此后的十年间，ECMAScript规范基本没有发生变动。ECMAScript3成为当今主流浏览器最广泛使用和实现的语言规范基础
> 
> 第一次浏览器战争以IE浏览器完胜Netscape而结束，IE开始统领浏览器市场，份额的最高峰达到2002年的96%。随着第一轮大战的结束，浏览器的创新也随之减少

#### <font color="yellow">005 动态页面的崛起</font>

> JavaScript诞生之后，可以用来更改前端DOM的样式，实现一些类似于时钟之类的小功能。那时候的JavaScript仅限于此，大部分的前端界面还很简单，显示的都是纯静态的文本和图片。这种静态页面不能读取后台数据库中的数据，为了使得Web更加充满活力，以PHP、JSP、ASP.NET为代表的动态页面技术相继诞生
>
> PHP（PHP：Hypertext Preprocessor）最初是由Rasmus Lerdorf在1995年开始开发的，现在PHP的标准由PHP Group维护。PHP是一种开源的通用计算机脚本语言，尤其适用于网络开发并可嵌入HTML中使用。PHP的语法借鉴吸收C语言、Java和Perl等流行计算机语言的特点，易于一般程序员学习。PHP的主要目标是允许网络开发人员快速编写动态页面
>
> JSP（JavaServer Pages）是由Sun公司倡导和许多公司参与共同创建的一种使软件开发者可以响应客户端请求，从而动态生成HTML、XML或其他格式文档的Web网页的技术标准。JSP技术是以Java语言为基础的。1999年，JSP1.2规范随着J2EE1.2发布
>
> ASP（Active Server Pages）1.0 在1996年随着IIS 3.0而发布。2002年，ASP.NET发布，用于替代ASP
> 
> 随着这些动态服务器页面技术的出现，页面不再是静止的，页面可以获取服务器数据信息并不断更新。以Google为代表的搜索引擎以及各种论坛相继出现，使得Web充满了活力
> 
> 随着动态页面技术的不断发展，后台代码变得庞大臃肿，后端逻辑也越来越复杂，逐渐难以维护。此时，后端的各种MVC框架逐渐发展起来，以JSP为例，Struct、Spring等框架层出不穷
> 
> 从Web诞生至2005年，一直处于后端重、前端轻的状态

#### <font color="yellow">006 XHTML</font>

> 1999年，W3C发布HTML 4.01标准，同年微软推出用于异步数据传输的ActiveX，随即各大浏览器厂商模仿实现了XMLHttpRequest（AJAX雏形）
>
> 2000年，W3C采用了一个大胆的计划，把XML引入HTML，XHTML 1.0作为W3C推荐标准发布
>
> 2001年5月，W3C推出了CSS 3.0规范草案
>
> 2002年到2006年，XHTML 2.0最终放弃
>
> 2009年，W3C宣布XHTML 2.0不再继续，宣告死亡

#### <font color="yellow">007 AJAX的流行</font>

> 在Web最初发展的阶段，前端页面要想获取后台信息需要刷新整个页面，这是很糟糕的用户体验
>
> Google分别在2004年和2005年先后发布了两款重量级的Web产品：Gmail和Google Map。这两款Web产品都大量使用了AJAX技术，不需要刷新页面就可以使得前端与服务器进行网络通信，这虽然在当今看来是理所应当的，但是在十几年前AJAX却是一项革命性的技术，颠覆了用户体验
>
> 随着AJAX的流行，越来越多的网站使用AJAX动态获取数据，这使得动态网页内容变成可能，像Facebook这样的社交网络开始变得繁荣起来，前端一时间呈现出了欣欣向荣的局面
>
> AJAX使得浏览器客户端可以更方便地向服务器发送数据信息，这促进了Web 2.0的发展
>
> Google Trend: AJAX从2005年开始得到开发人员的广泛关注

#### <font color="yellow">008 第二次浏览器大战</font>

> 前端兼容性框架的出现
>
> IE在第一次浏览器大战中击败Netscape赢得胜利，垄断了浏览器市场。作为独裁者，IE并不遵循W3C的标准，IE成了事实标准
>
> Netscape于1998年被AOL收购前创建了Mozilla社区，Firefox于2004年11月首次发布，并且9个月内下载量超过6000万，获取了巨大的成功，IE的主导地位首次受到了挑战，Firefox被认为是Netscape的精神续作
>
> 之后Firefox浏览器一路奋起直追，逐渐蚕食IE市场份额，这引发了第二次浏览器战争。在2008年底时，Firefox的市场份额达到了25%以上，IE则跌至65%以下
>
> 第二次浏览器战争中，随着以Firefox和Opera为首的W3C阵营与IE对抗程度的加剧，浏览器碎片化问题越来越严重，不同的浏览器执行不同的标准，对于开发人员来说这是一个恶梦
>
> 为了解决浏览器兼容性问题，Dojo、jQuery、YUI、ExtJS、MooTools等前端Framework相继诞生。前端开发人员用这些Framework频繁发送AJAX请求到后台，在得到数据后，再用这些Framework更新DOM树
>
> 其中，jQuery独领风骚，几乎成了所有网站的标配。Dojo、YUI、ExtJS等提供了很多组件，这使得开发复杂的企业级Web应用成为可能
>
> Google Trend: 蓝色jQuery，红色Dojo，绿色YUI，紫色ExtJS，黄色MooTools

#### <font color="yellow">009 HTML5</font>

> 1999年，W3C发布了HTML 4.0.1版本，在之后的几年，没有再发布更新的Web标准。随着Web的迅猛发展，旧的Web标准已不能满足Web应用的快速增长
>
> 2004年6月，Mozilla基金会和Opera软件公司在万维网联盟（W3C）所主办的研讨会上提出了一份联合建议书，其中包括Web Forms 2.0的初步规范草案。建议举行一次投票，以表决W3C是否应该扩展HTML和DOM，从而满足Web应用中的新需求。研讨会最后以8票赞成，14票反对否决此建议，这引起一些人的不满，不久后，部分浏览器厂商宣布成立网页超文本技术工作小组（WHATWG），以继续推动该规范的开发工作，该组织再度提出Web Applications 1.0规范草案，后来这两种规范合并形成HTML5。2007年，获得W3C接纳，并成立了新的HTML工作团队。2008年1月22日，第一份正式草案发布
>
> HTML5草案发布不久，Google在2008年12月发布了Chrome浏览器，加入了第二次浏览器大战当中。Chrome使用了Safari开源的WebKit作为布局引擎，并且研发了高效的JavaScript引擎V8
>
> 尽管HTML5在网络开发人员中非常出名了，但是它成为主流媒体的一个话题是在2010年的4月，当时苹果公司的CEO乔布斯发表一篇题为“对Flash的思考”的文章，指出随着HTML5的发展，观看视频或其它内容时，Adobe Flash将不再是必须的。这引发了开发人员间的争论，包括HTML5虽然提供了加强的功能，但开发人员必须考虑到不同浏览器对标准不同部分的支持程度的不同，以及HTML5和Flash间的功能差异
>
> 在第二次浏览器大战中，各个浏览器厂商都以提升JavaScript运行效率和支持HTML5各种新特性为主要目标，促进了浏览器的良性竞争。在这一场战争中，Chrome攻城略地，抢夺IE市场份额。2013年，Chrome超过IE，成为市场份额最高的浏览器。2016年，Chrome占据了浏览器市场的半壁江山
>
> 全球浏览器市场份额（2009-2017）
>
> 自2008年以来，浏览器中不断支持的HTML5新特性让开发者激动不已：WebWorker可以让JavaScript运行在多线程中，WebSocket可以实现前端与后台的双工通信，WebGL可以创建Web3D网页游戏......
>
> 桌面浏览器对HTML5支持程度（2009-2017）
>
> 2014年10月28日，W3C正式发布HTML 5.0推荐标准

#### <font color="yellow">010 Node.js的爆发</font>

> 早在1994年，Netspace就公布了其Netspace Enterprise Server中的一种服务器脚本实现，叫做LiveWire，是最早的服务器端JavaScript，甚至早于浏览器中的JavaScript。对于这门图灵完备的语言，Netspace很早就开始尝试将它用在后端
>
> 微软在1996年发布的IE 3.0中内嵌了自己的JScript语言，其兼容JavaScript语法。1997年年初，微软在它的服务器IIS 3.0中也包含了JScript，这就是我们在ASP中能使用的脚本语言
>
> 1997年，Netspace为了用Java实现JavaScript而创建了Rhino项目，最终Rhino演变成一个基于Java实现的JavaScript引擎，由Mozilla维护并开源。Rhino可以为Java应用程序提供脚本能力。2006年12月，J2SE 6将Rhino作为Java默认的脚本引擎
>
> SpiderMonkey是Mozilla用C/C++语言实现的一个JavaScript引擎，从Firefox 3.5开始作为JavaScript编译引擎，并被CouchDB等项目作为服务端脚本语言使用
>
> 可以看到，JavaScript最开始就能同时运行在前后端，但时在前后端的待遇却不尽相同。随着Java、PHP、.Net等服务器端技术的风靡，与前端浏览器中的JavaScript越来越流行相比，服务端JavaScript逐渐式微
>
> 2008年Chrome发布，其JavaScript引擎V8的高效执行引起了Ryan Dahl的注意。2009年，Ryan利用Chrome的V8引擎打造了基于事件循环的异步I/O框架——Node.js诞生
>
> Node.js具有以下特点
>
> - 基于事件循环的异步I/O框架，能够提高I/O吞吐量
> - 单线程运行，能够避免了多线程变量同步的问题
> - 使得JavaScript可以编写后台代码，前后端编程语言统一
>
> Node.js的出现吸引了很多前端开发人员开始用JavaScript开发服务器代码，其异步编程风格也深受开发人员的喜爱。Node.js的伟大不仅在于拓展了JavaScript在服务器端的无限可能，更重要的是它构建了一个庞大的生态系统
>
> 2010年1月，NPM作为Node.js的包管理系统首次发布。开发人员可以按照CommonJS的规范编写Node.js模块，然后将其发布到NPM上面供其他开发人员使用。目前NPM具有40万左右的模块，是世界上最大的包模块管理系统
>
> 2016年常见包管理系统模块数量，NPM高居榜首
>
> Node.js也催生了node-webkit等项目，用JavaScript开发跨平台的桌面软件也成为可能。Node.js给开发人员带来了无穷的想象，JavaScript大有一统天下的趋势

#### <font color="yellow">011 前端MV*架构</font>

> 随着HTML5的流行，前端不再是人们眼中的小玩意，以前在C/S中实现的桌面软件的功能逐步迁移到了前端，前端的代码逻辑逐渐变得复杂起
>
> 以前只用于后台的MV*等架构在前端逐渐使用起来，以下列举了部分常用的MV*框架来
>
> 随着这些MV*框架的出现，网页逐渐由Web Site演变成了Web App，最终导致了复杂的单页应用（ Single Page Application）的出现
>
> 移动Web和Hybrid App
>
> 随着iOS和Android等智能手机的广泛使用，移动浏览器也逐步加强了对HTML5特性的支持力度
>
> 移动浏览器对HTML5支持程度（2009-2017）
>
> 移动浏览器的发展，导致了流量入口逐渐从PC分流到移动平台，这是Web发展的新机遇。移动Web面临着更大的碎片化和兼容性问题，jQuery Mobile、Sencha Touch、Framework7、Ionic等移动Web框架也随之出现
>
> 相比于Native App，移动Web开发成本低、跨平台、发布周期短的优势愈发明显，但是Native App的性能和UI体验要远胜于移动Web。移动Web与Native App孰优孰劣的争论愈演愈烈，在无数开发者的实践中，人们发现两者不是替代关系，而是应该将两者结合起来，取长补短，Hybrid技术逐渐得到认同
>
> Hybrid技术指的是利用Web开发技术，调用Native相关API，实现移动与Web二者的有机结合，既能体现Web开发周期短的优势，又能为用户提供Native体验
>
> 根据实现原理，Hybrid技术可以分为两大类
> 
> - 将HTML5的代码放到Native App的WebView控件中运行，WebView为Web提供宿主环境，JavaScript代码通过WebView调用Native API。典型代表有PhoneGap(Cordova)以及国内的AppCan等
> - 将HTML5代码针对不同平台编译成不同的原生应用，实现了Web开发，Native部署。这一类的典型代表有Titanium和NativeScript
>
> Hybrid一系列技术中很难找出一种方案适应所有应用场景，我们需要根据自身需求对不同技术进行筛选与整合

#### <font color="yellow">012 ECMAScript6</font>

> JavaScript语言是ECMAScript标准的一种实现，截止2017年2月，ECMAScript一共发布了7个版本
>
> 1997年6月， ECMAScript 1.0标准发布
>
> 1998年6月，ECMAScript 2.0发布
>
> 1999年12月，ECMAScript 3.0发布
>
> 2007年10月，Mozilla主张的ECMAScript 4.0版草案发布，对3.0版做了大幅升级，该草案遭到了以Yahoo、Microsoft、Google为首的大公司的强烈反对，JavaScript语言的创造者Brendan Eich和IE架构师Chris Wilson甚至在博客上就ES4向后兼容性问题打起了口水仗，最后由于各方分歧太大，ECMA开会决定废弃中止ECMAScript 4.0草案。经各方妥协，在保证向下兼容的情况下，将部分增强的功能放到ECMAScript 3.1标准中，将原有ECMAScript 4.0草案中激进的功能放到以后的标准中。不久，ECMAScript 3.1就改名为ECMAScript 5
>
> 2009年12月，本着'Don’t break the web'原则，ECMAScript 5发布。新增了strict模式、属性getter和setter等
>
> 2011年6月，ECMAScript 5.1发布
>
> 2015年6月，ECMAScript 6.0发布。该版本增加了许多新的语法，包括支持let、const、Arrow function、Class、Module、Promise、Iterator、Generator、Set、Map、async、Symbol、Proxy、Reflect、Decorator等。TC39委员会计划以后每年都发布一个新版本的ECMAScript，所以ECMAScript 6.0改名为ECMAScript 2015
>
> 2016年6月，在ECMAScript 2015的基础上进行了部分增强，发布了ECMAScript 2016
>
> 在ECMAScript的各个版本中，ECMAScript 6.0无疑最受人瞩目的，它增加了许多新特性，极大拓展了JavaScript语法和能力，以至于许多浏览器都只能支持部分ES6中的新特性。随之，Babel和TypeScript逐渐流行起来，编写ES6代码，然后用Babel或TypeScript将其编译为ES5等浏览器支持的JavaScript
>
> ECMAScript以后每年将会发布一个新版本，这无疑将持续促使浏览器厂商不断为JavaScript注入新的功能与特性，JavaScript走上了快速发展的正轨

### <font color="yellow">02 安全世界观</font>

#### <font color="yellow">001 简介</font>

用户的最高权限叫做root(administrator) ，黑客最渴望的就是获得root

黑客使用的漏洞利用代码叫做exploit

黑客中的种类

- 一、精通计算机技术，能自己挖漏洞，并编写exploit，`多为白帽`
- 二、只对攻击本身感兴趣，对技术方面各项的了解比较浅，自己没有动手能力，只能看懂别人的代码，这类黑客被称为Script kids，`这是大多数黑客的类型`，`虽然黑客本身是具有破坏性的，但是第一种黑客是鳳毛麟角`


现实中，真正能够造成大规模破坏的往往不是挖掘并研究漏洞的黑客，而是这些Script Kids

SQL注入、XSS攻击的出现是Web安全史上的一个里程碑

伴随着Web 2.0 的兴起，XSS、CSRF等攻击已经变得更强大了

#### <font color="yellow">002 黑帽子、白帽子</font>

黑帽子：利用黑客技术造成破坏
1. 工作心态方面：
   - 工作心态：找到系统的一个漏洞，达到入侵的目的
   - 工作环境：一个人或小团队(黑客有关)
   - 工作目的：入侵系统，找到对自己价值的数据，以点突破，找到对自己最有作用的点以此渗透
   - 工作观察方面：思考问题的出发点必然是选择性的、微观性的
2. 对待问题方式：
   - 对待问题：为了完成一次入侵，需要利用各种不同漏洞的组合来达到目的

白帽子：精通安全技术，但工作在反黑客领域的网络安全专家
1. 工作心态方面：
    - 工作心态：找到系统的所有漏洞，不有遗漏项，保证系统不再出问题，`不可能做到100%无漏洞，只是让黑客无从下手`
    - 工作环境：为企业或安全公司工作
    - 工作目的：出发点在于解决一切安全问题
    - 工作观察方面：所看所想要全面和宏观
2. 对待问题方式：
    - 对待问题：在设计方案时，如果只看到各种问题组合后产生的效果，就会把事情变得更复杂，难以细致入微地解决根本问题，所以白帽子必然是在不断地分解问题，在对分解后的问题逐个给予解决
    - 选用的方法：客服某种攻击方式，而并非抵御单次攻击

#### <font color="yellow">003 安全的本质</font>

通过安全检测的过程，可与梳理未知的人或物，使其变得可信任，被划分出来的具有不同信任级别的区域，被称为信任域，划分两个信任域的分界线，被称为信任边界

安全问题的考虑选择：选择内容为发生概率高的安全问题，不太会考虑不可能发生的事件

一旦我们做出决策的依据、条件被打破、被绕过，那么就会导致安全假设的前提条件不再可靠，变成一个伪命题

把握住信任条件的度，使其恰到好处，正是设计安全方案的难点所在，也正是安全这门学问的魅力所在

安全是一个持续学习的内容

#### <font color="yellow">004 安全三要素</font>

简称CIA

- 机密性(Confidentiality)：要求保护数据内容不能泄露，加密是实现机密性要求的常见手段
- 完整性(Integrity)：要求保护数据内容是完整、没有更改的，常见的保证一致性的技术手段是数字签名
- 可用性(Availability)：要求保护资源是随需而得的

随着时代的进步，后人又增加了可设计性、不可抵赖性等，但最核心的还是以上三要素在设计安全方案时也要以这三要素为思考的出发点，更全面地思考问题

> 不可抵赖性，又称不可否认性，英文为Non-repudiation，电子商务交易各方在交易完成时要保证的不可抵赖性，指在传输数据时必须携带含有自身特质、别人无法复制的信息，防止交易发生后对行为的否认，通常可通过对发送的消息进行数字签名来实现信息的不可抵赖性

#### <font color="yellow">005 如何实施安全评估</font>

安全评估的过程
1. 资产等级划分

有时候资源的可用性可以理解为数据的可用性，互联网安全的核心问题是数据安全的问题

2. 威胁分析

`威胁：只可能导致对系统或组织危害的事故潜在的起因`，可能造成危害的来源叫做危害；可能出现的损失叫做分险

威胁建模方法 —— STRIDE
- Spoofing(伪装)
	- 定义：冒充他人身份
	- 对应的安全属性：认证
- Tampering(更改)
	- 定义：修改数据或代码
	- 对应的安全属性：完整性
- Repudiation(抵赖)
	- 定义：否认做过的事情
	- 对应的安全属性：不可抵赖性
- InformationDisclosure(信息泄露)
	- 定义：机密信息泄露
	- 对应的安全属性：机密性
- Denial of Service(拒绝服务)
	- 定义：拒绝服务
	- 对应的安全属性：可用性
- Elevation of Privilege(提升权限)
	- 定义：未经授权获得许可
	- 对应的安全属性：授权

在进行威胁分析时，要尽可能地不遗漏威胁，头脑风暴的过程可以确定攻击面(Attack Surface)

漏洞的定义：系统中可能被威胁利用以造成危害的地方

3. 风险分析

`风险：指某种特定的危险事件(事故或意外事件)发生的可能性与其产生的后果的组合`

影响风险高低的因素
  1. 造成损失的大小
  2. 发生的概率

风险程度模型 —— DREAD
- Damage Potential
	- 高：获取完整的验证权限；执行管理员操作；非法上传文件
	- 中：泄露敏感信息
	- 低：泄露其他信息
- Reproducibility
	- 高：攻击者可以重复攻击
	- 中：攻击者可以重复攻击，但有时间限制
	- 低：攻击者很难重复攻击
- Exploitability
	- 高：初学者在短期内能掌握攻击方法
	- 中：熟练的攻击者才能完成这次攻击
	- 低：漏洞利用条件非常苛刻
- Affected Users
	- 高：所有用户，默认设置，关键用户
	- 中：部分用户，非默认配置
	- 低：极少数用户，匿名用户
- Discoverability
	- 高：漏洞很显眼，攻击条件很容易获得
	- 中：在私有区域，部分人能看到，需要深入挖掘漏洞
	- 低：发现该漏洞极为困难

风险高低的定义(高(3)中(2)低(1))
  - Risk = D(a)+R(b)+E(c)+A(d)+D(e) = a+b+c+d+e
		- 高危：Risk = 12～15
		- 中危：Risk = 8～11
		- 低危：Risk = 0～7

***模型只是工具，起决定性作用的是人***

4. 确认解决方案
解决方案一定要有针对性，针对前三点做出安全方案

安全评估的产出物就是安全解决方案

一个好的安全解决方案须具备以下几点：
  - 能够有效解决问题
  - 用户体验好
  - 高性能
  - 低耦合`耦合度：是对模块间关联程度的度量，耦合的强弱取决于模块间接口的复杂性，调用模块的方式以及通过界面传送数据的多少`

`优势：易于扩展与升级，如果是由专职的安全团队长期维护的系统，有些阶段可以只是实施一次`

#### <font color="yellow">006 白帽子兵法</font>

1. Secure By Default 原则

`最基本也是最重要的原则`

a. 黑白名单

`SSH段口有很多功能可以替代Telent，又可以为FTP、POP、PPP提供一个安全的通道`

`SSH是目前比较可靠的专为远程登录会话和其他网络服务提供安全性的协议`

- 黑名单：不安全程序
- 白名单：较安全程序

如果允许工程师在服务器上随意安装软件的话，则可能会因为安全部门不知道、不熟悉的软件，导致一些漏洞出现，从而增大攻击面

`在电脑系统里，有很多软件都应用到了黑白名单规则，操作系统、防火墙、杀毒软件、邮件系统、应用软件等，凡是涉及到控制方面几乎都应用了黑白名单规则`

b. 最小权限原则

`最小权限是指每个程序和系统用户都应该具有完成任务所必需的最小权限集合，因此，对于系统管理员而言，一个用户应该只能访问履行他的相关职责所需访问的数据和硬件`

最小权限原则要求系统只授予主体必要的权限，而不要过度授权，这样能有效的减少系统、网络、应用、数据库出错的机会

`sudo：linux系统管理指令，是允许系统管理员让普通用户执行一些或者全部的root命令`

2. 纵深防御原理

Defense in Depth

- 要在各个不同层面、不同方面实施安全方案，避免出现疏漏，不同安全方案之间需要相互配合，构成一个整体
- 要在正确的地方做正确的事，在解决根本问题的地方实施针对行的安全方案
	
他要求我们深入理解威胁的本质，从而做出正确的应对措施，更全面、正确地看待问题

UTM(Unified Threat Management)统一威胁管理

`纵深防御：通过设置多层重叠的安全防护系统而构成多道防线，使得即使某一防线失效也能被其他防线弥补或纠正，即通过增加系统的防御屏障或将各层之间的漏洞错开的方式防范差错发生的`

3. 数据与代码分离原理
	
这一原则广泛适用于各种由于注入(e.g.：SQL Injection;XSS;CRLF Injection;X-Path Injection)而引发的安全问题场景

缓冲区溢出也可以认为是程序违背了这一原则的后果

`缓冲区是一块连续的计算机内存区域,可保存相同数据类型的多个实例`

`缓冲区溢出是针对程序设计缺陷，向程序输入缓冲区写入使之溢出的内容(通常是超过缓冲区能保存的最大数据量的数据)，从而破坏程序运行、趁著中断之际并获取程序乃至系统的控制权`

从漏洞成因上看待问题

4. 不可预测性原则

克服攻击方法的角度看问题

Unpredictable

能够有效地对抗基于篡改、伪造的攻击

当token足够复杂时，不能被攻击者在测到

我们无法要求运行的程序没有漏洞，所以要使漏洞的攻击方法失败

需要用到加密算法、随机数算法、哈希算法

#### <font color="yellow">007 总结</font>

安全是一门朴素的学问，也是一种平衡的艺术

## <font color="yellow">0x01 客户端脚本安全</font>

### <font color="yellow">01 浏览器安全</font>

#### <font color="yellow">001 同源策略(Same Origin Policy)</font>

是一种约定，它是浏览器最核心、最基本的安全功能，如果缺少了同源策略，浏览器的正常功能可能都会受到影响

可以说，Web是建立在同源策略之上的

浏览器的同源策略限制了来自不同源的document或脚本，对当前document读取或设置某些属性

对于JavaScript来说，不同的URL会被分为同源与不同源`影响原因：host(域名/IP地址)、子域名、端口、协议`

XMLHttpRequest可以访问同源对象的内容，但同样收到同源的约束，使其不能跨越访问资源，在AJAX应用的开发中尤其注意这一点

除了DOM、Cookie、XMLHttpRequest会受到同源策略的限制，浏览器加载的一些第三方插件也有各自的同源策略`最常见的是Flash、Java Applet、Silverlight、Google Gears都有自己的控制策略`

浏览器的同源策略是浏览器安全的基础，许多客户端脚本攻击，都需要遵守这一原则，因此理解同源策略对于客户端脚本攻击有着重要意义，同源策略一旦被出现的漏洞绕过，也将带来非常严重的后果，很多基于同源策略制定的安全方案将失去效果
`同源是指域名、协议、端口相同`

`同源策略，它是由Netscape提出的一个著名的安全策略`

`同源策略是浏览器的行为，是为了保护本地数据不被JavaScript代码获取回来的数据污染，因此拦截的是客户端发出的请求回来的数据接收，即请求发送了，服务器响应了，但是无法被浏览器接收`

#### <font color="yellow">002 浏览器沙箱</font>

在网页中插入一段恶意代码，利用浏览器漏洞执行任意代码的攻击方式，在黑客圈子里被形象地称为挂马

防挂马操作：浏览器密切结合DEP、ASLR、SafeSEH等保护系统
> Google Chrome流程
>   浏览器进程
>   渲染进程`由Sandbox即沙箱隔离`
>   插件进程`e.g.：将Flash、Java、Pdf进行隔离，因此不会相互影响`
>   扩展进程

现在的Sandbox已经成为泛指资源隔离类模块的代名词

Sandbox的设计目的一般是为了让不可信任的代码运行在一定的环境中，限制不可信任的代码访问隔离区之外的资源

现在了浏览器的内部结构文件已经受到Sandbox的保护，但第三方应用却不受Sandbox的管辖，所以被攻克的浏览器往往是第三方应用的安全漏洞

```text
Sandbox是指一种技术，在这种技术中，软件运行在操作系统受限制的环境中
由于该软件在受限制的环境中运行，即使一个闯入该软件的入侵者也不能无限制访问操作系统提供设施
获得该软件控制权的黑客造成的损失也是有限的
如果攻击者要获得对操作系统的完全控制，他们就不得不攻克沙箱限制，Sandbox也提供深度防御
许多PaaS系统都提供了一个实时运行环境，它的核心就是一个沙箱应用程序
如Azu re和Google App Engime
```

#### <font color="yellow">003 恶意网址拦截</font>

工作原理：一般都是浏览器周期性地从服务器获取一份最新的恶意网址黑名单，如果用户上网时访问的网址在黑名单中，浏览器将弹出警告

常见的恶意网址分类
1. 挂马的网站，这些网站通常包含有恶意的脚本，如JavaScript或Flash，通过利用浏览器的漏洞执行shellcode，在用户电脑中植入木马
2. 钓鱼网站，通过模仿知名网站的相似页面来欺骗用户

除了恶意网址黑名单拦截功能外，主流浏览器都开始支持EV SSL(Extended Validation SSL Certificate)证书，以增强对安全网址的识别，`EV SSL证书是全球数字证书颁发机构与浏览器厂商一起打造的增强型证书`，其主要特色是浏览器会给予EV SSL证书特殊的待遇

EV SSL证书也遵循X509标准，并向前兼容普通证书，如果浏览器不支持EV模式，则会把该证书当作普通证书，如果浏览器支持EV模式，则会在地址栏中特别标注，因此在网站使用了EV SSL证书后，可以教育用户识别真实网站在浏览器地址栏中的绿色表现，以对抗钓鱼网站

#### <font color="yellow">004 高速发展的浏览器安全</font>

现在的浏览器还在不断地更新，不断地推出新的安全功能

CSP(Content Security Policy)这一策略是由安全专家Robert Hanson最早提出的

- 做法：由一个服务器返回一个HTTP头，并在其中描述页面应该遵守的安全策略

浏览器加载的插件也是浏览器安全需要考虑的一个问题：扩展与插件的权限到高于页面JavaScript的权限

#### <font color="yellow">005 总结</font>

浏览器是互联网安全的重要接口，在安全攻防中，浏览器的作用也越来越被人们重视

在以往研究攻防时，大家更重视服务器端漏洞，现在，安全研究的范围已经涵盖了所有用户使用互联网的方式，浏览器正是其中最重要的一个部分

加深理解同源策略，才能把握浏览器安全的本质

随着信息技术的发展，恶意网址检测、插件安全等问题都会显得越来越重要

### <font color="yellow">02 跨站脚本攻击(XSS)</font>

#### <font color="yellow">001 转义字符</font>

首先要认识一下`\`，`\`在JavaScript有着特殊的用途，它是转义的符号

e.g.：`\x3C\x73\x63\x72\x69\x70\x74\x3E\x61\x6C\x65\x72\x74\x28\x27\x70\x6F\x72\x75\x69\x6E\x27\x29\x3C\x2F\x73\x63\x72\x69\x70\x74\x3E`

这些就是经过编码后的字符，因为前面的`\`缘故，所以后面的这些字符在JavaScript中都会被还原

接受用户的数据后过滤`<>`，再用JavaScript显示出来，输入经过16进制转换后的字符，这些字符都可以轻松的绕过过滤，完整进入代码中，经过JavaScript还原之后，正确解释出来

#### <font color="yellow">002 UBB标签</font>

UBB标签是目前广泛运用到论坛，留言簿，以及其他网站系统的一种编码标签，类似`[img]url[/img]`这样的，用户在中间输入地址后即可，在发表的时候系统会自动改成`<img src=”url”></img>`，这个URL就是用户输入的图片地址，XSS攻击中，可以利用这个特点来达到无需用户输入`<>`就能执行由用户所输入的代码，我们只要在输入网址的地方输入：`x"/**/οnerrοr="alert(‘poruin’)`，那么经过转换后就变成了`<img src=“x”/**/οnerrοr=“alert(‘poruin’)”>`

> JS中的编码还原函数最常用的就是String.fromCharCode了，这个函数用于ASCII码的还原，一般来说，这个函数都要配合`eval()`来使用才有效果
>
> 在跨站中，String.fromCharCode主要是使到一些已经被列入黑名单的关键字或语句安全通过检测，把关键字或语句转换成为ASCII码，然后再用String.fromCharCode还原，因为大多数的过滤系统都不会把String.fromCharCode加以过滤，例如关键字`alert`被过滤掉，那就可以这么利用：`<img src=“x”/**/οnerrοr=“eval(String.fromCharCode(97,108,101,114,116,40,39,112,111,114,117,105,110,39,41))”>`

#### <font color="yellow">003 绕过</font>

1. 前端过滤
> burp抓包改包绕过
2. 双写绕过
> 用于屏蔽一些对大小写敏感的黑名单匹配e.g.：`?id=1 UnIon SeLeCt user()#`
3. 事件绕过
	- onclick
	- onmousemove
4. 大小写绕过
> 用于屏蔽一些对大小写敏感的黑名单匹配e.g.：`?id=1 UnIon SeLeCt user()#`
5. 注释干扰绕过
> e.g.：`<scri<!--test-->pt>alert(1),<scr<!--teat-->ipt>`
6. 伪协议绕过
>
> `111">a href="javascript:alert(document.domain)">xss</a>`
>
> `<table background="javascript:alert(/xss/)"></table>`
>
> `<img src ="javascript:alert('xss';")>`
7. 0x06空格回车Tab绕过
> 1. 空格
>
> 	`<img src="jav    ascript:alert('xss');">`
>
> 2. Tab
>
> 	`<img src="javasc	ript:alert('xss');">`
>
> 3. 回车
>
> ```text
> <img src="jav
> ascript:
> alert('xss'):">
> ```
8. 编码绕过
> 1. base64编码
> 	`eval("")`eval函数把字符串当作程序执行
> 	atob函数是将base64密文转换为明文
> 	`"><script>eval(atob('YWxlcnQoZG9tYWluKQ=='));</script>`
> 	base64编码多用于如下两种情况
> 		1. `<a herf="可控点">`
> 		2. `<iframe src="可控点">`
> 	
> 	如果过滤了`<`、`>`、`'`、`"`、`script`，可以使用base64编码
> 	
> 	`<a herf="data:text/html;base64,PGItZyBzcmM9eCBvbmVycm9yPWFsCXJ0KDEpPg==">test</a>`
> 	
> 	这样当tast A链接点击时，就会以data协议，页面以`html/test`的方式解析，编码为base64，然后点击a链接时，base64的编码就被还原成原本的`<img src=x onerror=alert(1)>`
> 2. JS编码
> 	a. 八进制
> 
> 	三个八进制数字，如果不够，在前面补0
> 
> 	e.g.：`e = \145`
> 
> 	b. 十六进制
> 
> 	两个十六进制数字，如果不够，在前面补0
> 
> 	e.g.：`e = \x65`
> 
> 	十六进制前面加`\x`可以被JS识别
> 
> 	`<>`被转义时，利用十六进制绕过
> 
> 	`\\x3cscript\\x3ealert(document.domain);\\x3c/script\\x3e`
> 
> 	c. Unicode
> 
> 	四个十六进制数字，如果不够，在前面补0
> 
> 	e.g.：`e = \u0065`
> 
> 	十六进制前面加`\u00`变成可被JS识别的Unicode编码
> 
> 	`\\uoo3cscript\\u003ealert(document.domain);\\u003c/script\\u003e`
> 
> 	对于一些控制字符，使用特殊的C类型的转义风格(`\r`、`\n`)
> 
> 3. HTML实体编码
> 	
> 	a. 字符编码
> 	
> 	十进制、十六进制编码，样式为`"&#数值;"`
> 	
> 	<font color="red">浏览器是不会在html标签里解析js编码的，所以我们在onerror=后面放js中的编码是不会被解析，你放进去是什么，就是什么</font>
> 
> 	b. HTML5新增的实体命名编码
> 	
> 	`&colon; = [:]`
> 	
> 	`&NewLine; = [Line feed]`
> 	
> 	`<a href="javasc&NewLine;ript&colon;alert(1)">click</a>`
> 
> 4. URL编码
> 	
> 进行两次URL前编码
9. CSS
> 1. 利用IE特性绕过
> 
> 	IE中`‘’`可以闭合一个`“`
> 	
> 	`"onmousemove=alert(1)`
> 
> 2. 利用CSS特性绕过
> 
> 	设置background:url，利用JavaScript伪协议执行js
> 	
> 	`background-color:#f00;background:url("javascript:alert(document.domain);");`
> 
> 3. IE中利用CSS出发xss
> 
> 	CSS中的注释`/**/`
> 
> 	`xss:expres/**/sion(if(!window.x){alert(document.domain);window.x=1;})`

#### <font color="yellow">004 XSS简介</font>

XSS(Cross Site Script)跨站脚本攻击

XSS攻击通常指黑客通过HTML注入篡改了网页，插入了恶意脚本，从而在用户浏览网页时，控制用户浏览器的一种攻击

因为在最开始的时候XSS攻击的演示案例首跨域对，所以叫跨站脚本

分类
> 1. 反射型XSS
> 	
> 	简单地把用户输入的数据反射给服务器
> 
> 	黑客需要诱惑用户点击一个恶意链接，才能完成攻击，又称非持久型XSS(Non-persistent XSS)
> 
> 	前端--->后端--->前端
> 
> 2. 存储型XSS
> 
> 	把用户输入的数据存储在服务器端
> 
> 	具有很强的稳定性，又称持久型XSS(Persistent XSS)
> 
> 	前端--->后端--->数据库--->前端
> 
> 3. DOM Based XSS(DOM型XSS)
> 
> 	通过修改页面的DOM节点形成的XSS
> 
> 	前端

#### <font color="yellow">005 XSS攻击进阶</font>

##### <font color="yellow">0001 初探XSS Payload</font>

XSS攻击成功后，攻击者能够对用户当前浏览的页面植入恶意脚本，通过恶意脚本，控制用户的浏览器

这些用以完成各种具体功能的恶意脚本，被称为XSS Payload

XSS Payload实际上就是JavaScript脚本，还可以是Flash或其他富客户端的脚本，所以JavaScript能做到的功能，XSS Payload也能做到

一个最常见的XSS Payload就是通过读取浏览器的Cookie对象，从而发起Cookie劫持的攻击

Cookie中一般加密保存了当前用户的登录凭证，如果Cookie丢失，就意味着用户的登录凭证丢失，攻击者就可以不通过密码，直接进入用户的账户

##### <font color="yellow">0002 强大的XSSPayload</font>

<font color="yellow">a. 构造GET与POST请求</font>

特点(http的特点)
> 基于tcp/ip、一种网络应用层协议、超文本传输协议HyperText Transfer Protocol
> 
> 工作方式：客户端请求服务端应答的模式
> 快速：无状态连接
> 灵活：可以传输任意对象，对象类型由Content-Type标记
> 客户端请求request消息
> 	- 请求行(request line)
> 	- 请求头部(header)
> 	- 空行
> 	- 请求数据
> 
> 服务端响应response由四个部分组成
> 	- 状态行
> 	- 消息报头
> 	- 空行
> 	- 响应正文

请求方法
> http请求可以使用多种请求方法
> 	- HTTP1.0定义了三种请求方法
> 		- GET
> 		- POST
> 		- HEAD
> 	- HTTP1.1新增了五种请求方法
> 		- OPTIONS
> 		- PUT
> 		- DELETE
> 		- TRACE
> 		- CONNECT 
> 	
> 	HTTP2.0 新的二进制格式(Binary Format)，HTTP1.x的解析是基于文本
> 	
> 	基于文本协议的格式解析存在天然缺陷，文本的表现形式有多样性，要做到健壮性考虑的场景必然很多，二进制则不同，只认0和1的组合
> 	
> 	基于这种考虑HTTP2.0的协议解析决定采用二进制格式，实现方便且健壮
> 	
> 	多路复用(MultiPlexing)，即连接共享，即每一个request都是是用作连接共享机制的
> 	
> 	一个request对应一个id，这样一个连接上可以有多个request，每个连接的request可以随机的混杂在一起，接收方可以根据request的id将request再归属到各自不同的服务端请求里面
> 	
> 	header压缩，如上文中所言，对前面提到过HTTP1.x的header带有大量信息，而且每次都要重复发送，HTTP2.0使用encoder来减少需要传输的header大小，通讯双方各自cache一份header fields表，既避免了重复header的传输，又减小了需要传输的大小
> 	
> 	服务端推送(server push)，同SPDY一样，HTTP2.0也具有server push功能
> 	- [https://baike.baidu.com/item/HTTP%202.0/12520156?fr=aladdin](https://baike.baidu.com/item/HTTP%202.0/12520156?fr=aladdin)
> 	- GET请求指定的页面信息，并返回实体主体
> 	- HEAD类似于get请求，只不过返回的响应中没有具体的内容，用于获取报头
> 	- POST向指定资源提交数据进行处理请求(例如提交表单或者上传文件)，数据被包含在请求体中，POST请求可能会导致新的资源的建立和/或已有资源的修改
> 	- PUT从客户端向服务器传送的数据取代指定的文档的内容
> 	- DELETE请求服务器删除指定的页面
> 	- CONNECT HTTP/1.1协议中预留给能够将连接改为管道方式的代理服务器
> 	- OPTIONS允许客户端查看服务器的性能
> 	- TRACE回显服务器收到的请求，主要用于测试或诊断

区别
> http协议最常见的两种方法GET和POST，这几点答案其实有几点并不准确
> -  请求缓存：GET会被缓存，而post不会
> -  收藏书签：GET可以，而POST不能
> -  保留浏览器历史记录：GET可以，而POST不能
> -  用处：get常用于取回数据，post用于提交数据
> -  安全性：post比get安全
> -  请求参数：querystring是url的一部分get、post都可以带上，get的querystring(仅支持urlencode编码)，post的参数是放在body(支持多种编码)
> -  请求参数长度限制：get请求长度最多1024kb，post对请求数据没有限制

误区
> 针对上面常见的区别，如果面试的时候这么说，肯定是有很大的毛病，刚在学校面试的时候也曾经囫囵吞枣地这样说过，现在回过头再想以前的错误认知，又有许多新的认识
> 
> 用处：请求参数，get是querystring(仅支持urlencode编码)，post是放在body(支持多种编码)query参数是URL的一部分，而GET、POST等是请求方法的一种，不管是哪种请求方法，都必须有URL，而URL的query是可选的
> 
> 请求参数长度限制(下面对各种浏览器和服务器的最大处理能力做一些说明)
> -  IE浏览器对URL的最大限制为2083个字符
> -  Firefox(Browser)：对于Firefox浏览器URL的长度限制为65536个字符
> -  Safari(Browser)：URL最大长度限制为80000个字符
> -  Opera(Browser)：URL最大长度限制为190000个字符
> -  Google Chrome：URL最大长度限制为8182个字符
> -  Apache(Server)：能接受最大url长度为8192个字符
> -  Microsoft Internet Information Server(IIS)：能接受最大url的长度为16384个字符
> 
> 	为了符合所有标准，url的最好不好超过最低标准的2083个字符(2k+35)
> 
> 	当然在做客户端程序时，url并不展示给用户，只是个程序调用，这时长度只收web服务器的影响了
> 
> 	最常见的form表单，浏览器默认的form表单，默认的`content-type`是`application/x-www-form-urlencoded`，提交的数据会按照key-value的方式，jquery的ajax默认的也是这种content-type
> 
> 	在post方式中添加querystring一定是可以接收的到，但是在get方式中加body参数就不一定能成功接收到了
> 
> post不比get安全性要高，这里的安全是相对性，并不是真正意义上的安全，通过get提交的数据都将显示到url上，页面会被浏览器缓存，其他人查看历史记录会看到提交的数据，而post不会，另外get提交数据还可能会造成CSRF攻击

http状态码
> - 1xx - 信息提示
> 	- 100 Continue - 继续
> 	- 101 Switching Protocols - 切换协议
> - 2xx - 成功
> 	- 200 OK - 客户端请求已成功
> 	- 201 Created - 已创建
> 	- 202 Accepted - 已接受
> 	- 203 Non-Authoritative Information - 非权威性信息
> 	- 204 No Content - 无内容
> 	- 205 Reset Content - 重置内容
> 	- 206 Partial Content - 部分内容
> - 3xx - 重定向
> 	- 300 Multiple Choices - 多种选择
> 	- 301 Moved Permanently - 对象已永久重定向(对象已永久移走)
> 	- 302 Found - 对象已临时移动
> 	- 303 See Other - 服务器要将浏览器重定向到另一个资源
> 	- 304 Not Modified - 未修改
> 	- 307 Temporary Redirect - 临时重定向
> 	- 308 Permanent Resident - 不允许浏览器将原本为POST的请求重定向到GET请求上
> - 4xx - 客户端错误
> 	- 400 Bad Request - 客户端请求到语法错误，服务器无法理解
> 	- 401 Unauthorized - 请求要求用户的身份认证
> 	- 402 Payment Required - 保留，将来使用
> 	- 403 Forbidden - 服务器理解请求客户端的请求，但是拒绝执行此请求
> 	- 404 Not Found - 服务器无法根据客户端的请求找到资源(网页)
> 	- 405 Method Not Allowed - 客户端请求中的方法被禁止
> 	- 406 Not Acceptable - 服务器无法根据客户端请求的内容特性完成请求
> 	- 407 Proxy Authentication Required - 请求要求代理的身份认证
> 	- 408 Request Time-out - 服务器等待客户端发送的请求时间过长，超时
> 	- 409 Conflict - 服务器完成客户端的 PUT 请求时可能返回此代码，服务器处理请求时发生了冲突
> 	- 410 Gone - 客户端请求的资源已经不存在
> 	- 411 Length Required - 服务器无法处理客户端发送的不带Content-Length的请求信息
> 	- 412 Precondition Failed - 客户端请求信息的先决条件错误
> 	- 413 Request Entity Too Large - 由于请求的实体过大，服务器无法处理，因此拒绝请求，为防止客户端的连续请求，服务器可能会关闭连接
>  	- 414 Request-URL Too Large - 请求的URI过长（URI通常为网址），服务器无法处理
> 	- 415 Unsupported Media Type - 服务器无法处理请求附带的媒体格式
> 	- 416 Requested Range Not Satisfiable - 客户端请求的范围无效
> 	- 417 Expectation Failed - 服务器无法满足Expect的请求头信息
> - 5xx - 服务器错误
> 	- 500 Internal Server Error - 服务器内部错误，无法完成处理
> 	- 501 Not Implemented - 服务器不支持请求的功能，无法完成请求
> 	- 502 Bad Gateway - 作为网关或者代理工作的服务器尝试执行请求时，从远程服务器接受到了一个无效的响应
> 	- 503 Service Unavailable - 由于超载或系统维护，服务器暂时无法处理客户端的请求
> 	- 504 Gateway Time-out - 充当网关或代理的服务器，未能及时从远端服务器获取请求
> 	- 505 HTTP Version Not Supported - 服务器不支持请求的HTTP协议的版本，无法完成处理
> 
> 302：在响应头中加入Location参数，浏览器接受到带有location头的响应时，就会跳转到相应的地址
	
减低服务器流量压力
> 根据HTTP规范，GET用于信息获取，而且应该是安全的和幂等的，所谓安全的意味着该操作用于获取信息而非修改信息，GET请求一般不应产生副作用，幂等的意味着对同一URL的多个请求应该返回同样的结果，完整的定义并不像看起来那样严格，从根本上讲，其目标是当用户打开一个链接时，她可以确信从自身的角度来看没有改变资源

原理区别
> 一般在浏览器中输入网址访问资源都是通过GET方式，在FORM提交中，可以通过Method指定提交方式为GET或者POST，默认为GET提交，http定义了与服务器交互的不同方法，最基本的方法有4种，分别是GET，POST，PUT，DELETE
> 
> URL全称是资源描述符，一个URL地址，它用于描述一个网络上的资源，而HTTP中的GET，POST，PUT，DELETE就对应着对这个资源的查，改，增，删4个操作，GET一般用于获取/查询资源信息，而POST一般用于更新资源信息
> 
> 根据HTTP规范，GET用于信息获取，而且应该是安全的和幂等的
> 
> 所谓安全的意味着该操作用于获取信息而非修改信息，换句话说，GET请求一般不应产生副作用，就是说，它仅仅是获取资源信息，就像数据库查询一样，不会修改，增加数据，不会影响资源的状态，<font color="red">这里安全的含义仅仅是指是非修改信息</font>，幂等的意味着对同一URL的多个请求应该返回同样的结果
> 
> 幂等(idempotent、idempotence)是一个数学或计算机学概念，常见于抽象代数中，对于单目运算，如果一个运算对于在范围内的所有的一个数多次进行该运算所得的结果和进行一次该运算所得的结果是一样的，那么我们就称该运算是幂等的，如绝对值运算就是一个例子，在实数集中，有`abs(a) = abs(abs(a))`，对于双目运算，则要求当参与运算的两个值是等值的情况下，如果满足运算结果与参与运算的两个值相等，则称该运算幂等，如求两个数的最大值的函数，有在实数集中幂等，即`max(x,x) = x`，看完上述解释后，应该可以理解GET幂等的含义了，但在实际应用中，以上2条规定并没有这么严格，根据HTTP规范，POST表示可能修改变服务器上的资源的请求
> 
> 上面大概说了一下HTTP规范中，GET和POST的一些原理性的问题，但在实际的做的时候，很多人却没有按照HTTP规范去做，导致这个问题的原因有很多
> 
> 1. 很多人贪方便，更新资源时用了GET，因为用POST必须要到from(表单)，这样会麻烦一点
> 2. 对资源的增，删，改，查操作，其实都可以通过GET/POST完成，不需要用到PUT和DELETE
> 3. 早期的但是Web MVC框架设计者们并没有有意识地将URL当作抽象的资源来看待和设计，还有一个较为严重的问题是传统的Web MVC框架基本上都只支持GET和POST两种HTTP方法，而不支持PUT和DELETE方法
> 
> <font color="red">MVC本来是存在于Desktop程序中的，M是指数据模型，V是指用户界面，C则是控制器，使用MVC的目的是将M和V的实现代码分离，从而使同一个程序可以使用不同的表现形式</font>

表达式区别
> 
> - //http请求行
> - //http请求消息报头
> - //回车换行
> - []//http请求正文

提交方式区别
> 1. GET提交的数据会在地址栏中显示出来，而POST提交，地址栏不会改变
> 	- GET提交：请求的数据会附在URL之后(就是把数据放置在HTTP协议头中)，以?分割URL和传输数据，多个参数用&连接
> 	- POST提交：把提交的数据放置在是HTTP包的包体中
> 2. HTTP协议没有对传输的数据大小进行限制，HTTP协议规范也没有对URL长度进行限制
> 	- GET：特定浏览器和服务器对URL长度有限制，IE对URL长度的限制是2083字节(2K+35)，对于其他浏览器，如Netscape、FireFox等，理论上没有长度限制，其限制取决于操作系统的支持
> 	- POST：由于不是通过URL传值，理论上数据不受限，但实际各个WEB服务器会规定对post提交数据大小进行限制，Apache、IIS6都有各自的配置
> 3. 安全性
> 	- POST的安全性要比GET的安全性高<font color="red">这里所说的安全性和上面GET提到的安全不是同个概念，上面安全的含义仅仅是不作数据修改，而这里安全的含义是真正的Security的含义</font>
> 4. Http get，post，soap协议都是在http上运行的
> 	- GET：请求参数是作为一个key/value对的序列(查询字符串)附加到URL上的查询字符串的长度受到web浏览器和web服务器的限制(IE最多支持2048个字符)，不适合传输大型数据集同时，它很不安全
> 	- POST：请求参数是在http标题的一个不同部分(名为entitybody传输的)，这一部分用来传输表单信息，因此必须将Content-type设置为`application/x-www-form-urlencoded`，post设计用来支持web窗体上的用户字段，其参数也是作为key/value对传输
> 	- SOAP：是http post的一个专用版本，遵循一种特殊的xml消息格式Content-type设置为，text/xml任何数据都可以xml化
		
- get是从服务器上获取数据，post是向服务器传送数据
> get和post只是一种传递数据的方式，get也可以把数据传到服务器，他们的本质都是发送请求和接收结果
> 
> 只是组织格式和数据量上面有差别，http协议里面有介绍2.get是把参数数据队列加到提交表单的ACTION属性所指的URL中，值和表单内各个字段一一对应，在URL中可以看到
> 
> post是通过HTTPpost机制，将表单内各个字段与其内容放置在HTML HEADER内一起传送到ACTION属性所指的URL地址
> 
> 用户看不到这个过程，因为get设计成传输小数据，而且最好是不修改服务器的数据，所以浏览器一般都在地址栏里面可以看到，但post一般都用来传递大数据，或比较隐私的数据，所以在地址栏看不到，能不能看到不是协议规定，是浏览器规定的
- 对于get方式，服务器端用`Request.QueryString`获取变量的值，对于post方式，服务器端用`Request.Form`获取提交的数据
- get传送的数据量较小，不能大于2KB，post传送的数据量较大，一般被默认为不受限制
> 但理论上，IIS4中最大量为80KB，IIS5中为100KB
> 
> post基本没有限制，我想大家都上传过文件，都是用post方式的，只不过要修改form里面的那个type参数
- get安全性非常低，post安全性较高
> 如果没有加密，他们安全级别都是一样的，随便一个监听器都可以把所有的数据监听到
	
一个网站的应用只需要接受HTTP协议中的GET或POST请求，即可完成所有操作，对于攻击者来说，仅通过JavaScript就可以让浏览器发起这两个请求，所以XSS攻击后，攻击者除了可以实施Cookie劫持外，还能够通过模拟GET、POST请求操作用户的浏览器，这在某些隔离环境中会非常有用，比如Cookie劫持失效时，或者目标用户的网络不能访问互联网等情况

<font color="yellow">b. XSS钓鱼</font>

> 将XSS与钓鱼结合的思路，利用JavaScript在当前界面伪造一个登录框，当用户在登录框中输入用户名与密码后，其密码会发送到黑客的服务器上
> 
> 充分发挥想象力，可以使XSS攻击的威力更加巨大

<font color="yellow">c. 识别用户浏览器</font>

> 在很多时候，攻击者为了获取更大的利益，往往需要准确地手机用户的个人信息
> 
> 但是浏览器的UserAgent是可以伪造的，所以通过JavaScript取出来的这个浏览器对象，信息并不一定准确
> 
> 由于浏览器之间的实现存在差异——不同的浏览器会各自实现一些独特的功能，而同一个浏览器的不同版本之间也可能会有细微的差别
> 
> 所以通过分辨这些浏览器之间的差异，就能准确地判断出浏览器的版本，而几乎不会报错，这种方法比读取UserAgent要准确得多
> 
> [http://www.thespanner.co.uk/2009/01/29/detecting-browsers-javascript-hacks/](http://www.thespanner.co.uk/2009/01/29/detecting-browsers-javascript-hacks/)

<font color="yellow">d. 识别用户安装的软件</font>

> 知道了用户使用的浏览器、操作系统后，进一步可以识别用户安装的软件
> 
> 在IE中，可以通过判断ActiveX控件的classid是否存在，来推测用户是否安装了该软件
> 
> 这种方法很早就被用于挂马攻击——黑客通过判断用户安装的软件，选择对应的浏览器漏洞，最终达到植入木马的目的
> 
> 浏览器的扩展与插件也能被XSS Payload扫描出来

<font color="yellow">e. CSS History Hack</font>

> 通过CSS，可以发现用户曾经访问过的网站
> 
> 这个技巧最早被Jeremiah Grossman发现，其原理是利用style的visited属性，如果用户曾经访问过某个链接，那么这个链接的颜色会变得与众不同

<font color="yellow">f. 获取用户的真实IP地址</font>

> 
> 通过XSS Payload还有办法获得一些客户端的本地IP地址
> 
> 很多时候，用户电脑使用了代理服务器，或者在局域网中隐藏在NAT后面，网站看到的客户端IP地址是内网的出口IP地址，而并非用户的真实IP地址
> 
> JavaScript本身并没有提供获取本地IP地址的能力
> 
> XSS攻击需要借助第三方软件来完成
> 
> 可以借助以上两点结合第三方软件使用，获得用户IP地址[http://decloak.net/decloak.html](http://decloak.net/decloak.html)

<font color="yellow">g. XSS攻击平台</font>

> - Attack API
> 
> 	[http://code.google.com/p/attackapi/](http://code.google.com/p/attackapi/)
> 
> 	由安全研究者pdp所主导的一个项目，它总结了很多能够直接使用XSS Payload，归纳为API的方式
> 
> 	e.g.：获取客户端本地信息的API(3.2.2)
> 
> - BeEF
> 
> 	[http://www.bindshell.net/tools/beef/](http://www.bindshell.net/tools/beef/)
> 
> 	BeEF曾经是最好的XSS演示平台，它演示的是一个完整的XSS攻击过程，BeEF有一个控制后台，攻击者可以在后台控制前端的一切，每一个被XSS攻击的用户都将出现在后台，后台控制者可以控制这些浏览器的行为，并可以通过XSS向这些用户发送命令
> 
> - XSS- Proxy
> 
> 	是一个轻量级的XSS攻击平台，通过嵌套iframe的方式可以实时地远程控制被XSS攻击的浏览器
> 
> 这些XSS攻击平台有助于深入了解XSS的原理及危害

<font color="yellow">h. XSS Worm</font>

> 注：一种蠕虫病毒
> 
> - Samy Worm
> 
> 	用户之间发生交互行为的页面如果存在存储型XSS，则会比较容易发起XSS Worm攻击
> 
> 	[http://namb.la/popular/tech.html](http://namb.la/popular/tech.html)
> 
> - 百度空间蠕虫
> 
> 	[http://security.ctocio.com.cn/securitycomment/57/7792057.shtml](http://security.ctocio.com.cn/securitycomment/57/7792057.shtml)
> 
> 以上两个蠕虫并不是恶意的蠕虫，真正可怕的蠕虫是那些在无声无息地盗取用户的敏感信息的蠕虫，然而这些蠕虫并不会干扰用户的正常使用，非常隐蔽

<font color="yellow">i. 调试JavaScript</font>

> 想写好XSS Payload，需要有很好的JavaScript功底，调试JavaScript也是必不可少的技能
> 
> 工具
> - Firebug：这是最常用的脚本调试工具，前端工程师于Web Hacking必备，被誉为居家旅行的瑞士军刀，Firebug非常强大，它有好几个面板，可以查看页面的DOM节点
> - IE 8 Developer Tools：在IE8中，为开发者内置了一个JavaScript Debugger，可以动态调试JavaScript
> - Fiddler：这是一个本地代理服务器，需要将浏览器设置为使用本地代理服务器上网才可使用，它会监控所有浏览器请求，并有能力在浏览器请求中插入数据，它支持脚本编程，一个强大的Fiddler脚本将非常有助于安全测试[http://www.fidder2.com/fidder2/](http://www.fidder2.com/fidder2/)
> - HttpWatch：这是一个商业软件，它以插件的形式内嵌在浏览器中，它并不能调试JavaScript，它仅仅是一个专业针对Web的Sniffer
> 
> <font color="red">工具只是辅助，并不起关键作用</font>

<font color="yellow">j. XSS构造技巧</font>


利用字符编码
> 百度收藏：将`%c1\`组成新的Unicode字符这样`%c1`把转运符号`\`隐藏起来了，从而绕过了系统的安全检查，实施了XSS攻击

绕过长度限制
> 很多时候，产生XSS的地方会有变量的长度限制，这个限制可能是服务器端逻辑造成的，攻击者可以利用事件(Event)来缩短所需要的字节数，最好的办法是把XSS Payload写到别处，再通过简短的代码加载这段XSS Payload，最常用的一个藏代码的地方，就是location.hash，而且根据HTTP协议，location.hash的内容不会在HTTP包中发送，所以服务器端的Web日志中并不会记录location.hash中的数据，从而也更好地隐藏了黑客真实点意图，因为location.hash的第一个字符是`#`，所以必须去除第一个字符才可运行，location.hash本身没有长度限制，但是浏览器的地址栏是有长度限制的，不过这个长度已经足够用来写很长的XSS Payload了，如果地址栏了长度不够用，还可以再使用加载远程JS的方法，来写更多代码，在某些环境下，可以通过注释符绕过长度限制

使用`<base>`标签
> `<base>`标签并不常用，它的作用是定义页面上的所有使用相对路径标签的hosting地址，需要特别注意的是，在有技术的文档中，提到`<base>`标签只能用在`<head>`标签内，其实这是不对的，`<base>`标签可以出现在HTML脚本的任意位置并作用于位于标签之后的所有标签，所有在设计XSS安全方案时，一定要过滤掉这个非常危险的标签

`window.name`的妙用
> `window.name`对象是一个很神奇的东西，对当前窗口的`window.name`对象赋值，没有特殊的字符限制，因为window对象是浏览器的窗体，而并非document对象，因此很多时候window对象不受同源策略的限制，攻击者利用这个对象，可以实现跨于、跨页面传递数据，在某些环境下，这种特性将变得非常有用，使用`window.name`可以缩短XSS Payload的长度，在同一窗口打开XSS的站点后，只需通过XSS执行相应的代码即可，这个技巧为安全研究者loulou所发现
> 
> [《突破XSS字符数量限制执行任意JS代码》：http://secinn.appspot.com/pstzine/read?issue=3&articleid=4](http://secinn.appspot.com/pstzine/read?issue=3&articleid=4)

Mission Impossible
> 从XSS漏洞利用的角度看，存储型XSS对攻击者的用处比反射型XSS要大，因为存储型XSS在用户访问正常URL时会自动触发，而反射型XSS会修改一个正常的URL，一般要求攻击者将XSS URL发送给用户点击，无形中提高了攻击门槛，有的XSS漏洞被认为只能攻击自己，称之为鸡肋漏洞

Apache Expect Header XSS
> 这个漏洞最早公布于2006年，这个漏洞曾一度被认为是无法利用的所以厂商不认为这是个漏洞，这个漏洞的影响范围是Apache Expect Header版本1.3.34、2.0.57、2.2.1及以下
> 
> 利用过程
> 1. 向服务器提交后返回
> 2. 注意到服务器在出错返回时，会把Expect头的内容未经任何处理便写入到页面中，因此Expect头中的代码就会被浏览器解析执行
> 
> 从攻击过程可以看出，需要在提交请求时向HTTP头中注入恶意数据，才能触发漏洞，但对于XSS攻击来说，JavaScript工作渲染后的浏览器环境中，无法控制用户浏览器发出的HTTP头，因此，这个漏洞曾一度被认为是鸡肋漏洞，后来，安全研究者Amit Klein提出了使用Flash构造请求的方法，成功地利用这个漏洞，变废为宝：在发送Flash中的HTTP请求时，可以自定义大多数的HTTP头

Anehta的回旋镖
> 反射型XSS也有可能像存储型XSS一样利用：将要利用的反射型XSS嵌入一个存储型XSS中
> 
> 这个攻击方法曾经在未知安全研究者实现的一个XSS攻击平台(Anehta)中使用过，他将其命名为回旋镖，因为浏览器同源策略的原因，XSS也受到同源策略的限制(发生在A域上的XSS很难影响B域的用户)
> 
> 思路：如果在B域上存在一个反射型`XSS_B`，在A域上存在一个存储型`XSS_A`，当用户访问A域上的`XSS_A`时，同时嵌入B域上的`XSS_B`，则可达到在A域的XSS攻击B域用户的目的

Flash XSS
> 
> Flash中同样也有可能造成XSS攻击，ActionScript是一种非常强大和灵活的脚本，甚至可以使用它发起网络连接，因此应该尽可能地禁止用户能够上传或加载中定义的Flash文件，如果仅仅是视频文件，则要求转码为flv文件，flv文件是静态文件，不会产生安全隐患，如果是带动态脚本的Flash，则可以通过Flash的配置参数进行限制
> 
> 限制Flash动态脚本的最重要的参数是allowScriptAccress，这个参数定义了Flash能否与HTML页面进行通信
> - always - 对与HTML的通信也就是执行JavaScript不做任何限制
> - sameDomain - 只允许来自于本域的Flash域HTML通信，这是默认值
> - never - 绝对静止Flash域HTML的通信
> 
> 使用always是非常危险的，一般推荐使用never，如果值为sameDomain的话，<font color="red">必须确保Flash文件不是用户上传的</font>
> 
> 除了allowScriptAccress外，allowNetworking也非常关键，这个参数能控制Flash与外部网络进行通信
> - all - 允许使用所有的网络通信，这是默认值
> - internal - Flash不能与浏览器通信，但可以调用其他API
> - none - 禁止任何的网络通信
> 
> 一般建议此值设置为none或internal，设置为all可能带来安全问题
> 
> 除了用户的Flash文件能够实施脚本攻击外，一些Flash也可能会产生XSS漏洞，安全研究者Stefano Di Paola曾经写了一个叫SWFIntruder的工具来检测产生在Flash里的XSS漏洞，通过这个工具可以检测出很多注入Flash变量导致的XSS问题[https://www.owasp.org/index.php/Category:SWFIntruder](https://www.owasp.org/index.php/Category:SWFIntruder)
> 
> Flash XSS往往被开发者所忽视，注入Flash变量的XSS，因为其原因出现在编译后的Flash文件中，一般的扫描工具或者代码审计工具都难以检查，常常使其成为漏网之鱼，OWASP为Flash安全研究设立了一个Wiki页面[https://www.owasp.org/index.php/Category:OWASP_Flash_Security_Project](https://www.owasp.org/index.php/Category:OWASP_Flash_Security_Project)

JavaScript开发框架
> 一般来收成熟的JavaScript开发框架都会注意自身的安全问题，但代码是人写的，高手难免也会犯错，一些JavaScript开发框架也曾暴露过一些XSS漏洞
> 
> - Dojo：Dojo是一个流行的JavaScript开发框架，它曾被发现有XSS漏洞，在Dojo1.4.1中，存在两个DOM型XSS
> - YUI：翻翻YUI的bugtracker也可以看到类似Dojo的问题
> - jQuery：jQuery可能是目前最流行的JavaScript框架，它本身出现的XSS漏洞很少，但开发者该记住的是，JavaScript框架只是对JavaScript语言本身的封装，并不能解决代码逻辑上产生的问题，所以开发者的意识才是安全编码的关键所在

#### <font color="yellow">006 XSS防御</font>

##### <font color="yellow">0001 HttpOnly</font>

HttpOnly是由微软最早提出的并在IE6中实现，至今已经逐渐成为一个标准，浏览器将禁止页面的JavaScript访问带有HttpOnly属性的Cookie

以下浏览器开始支持HttpOnly

- Microsoft IE 6 SP1+
- Mozilla Firefox 2.0.0.5+
- Mozilla Firefox 3.0.0.6+
- Google Chrome
- Apple Safari 4.0+
- Opera9.5+

严格来说，HttpOnly并非为了对抗XSS，它是解决XSS后的Cookie劫持攻击(原理(见前)：如果Cookie设置了HttpOnly，则这种攻击会失败，因为JavaScript读取不到Cookie的值)

一个Cookie的使用过程如下

1. 浏览器想服务器发起请求，这时候没有Cookie
2. 服务器发挥时发送Set- Cookie头，向客户端浏览器写入Cookie
3. 在该Cookie到期前，浏览器访问该域下的所有页面，都将发送该Cookie

<font color="red">服务器可能会设置多个Cookie(多个key-value对)，而HttpOnly可以有选择性地加在任意一个Cookie值上</font>

在某些时候，应用可能需要JavaScript访问某几项Cookie，这种Cookie可以不设置HttpOnly标记，而仅把HttpOnly标记给用于认证的Cookie添加HttpOnly的过程简单，效果明显，有如四两拔千斤，但部署时需要注意如果业务非常复杂，则需要在所有Set-Cookie的地方，给关键Cookie都加上HttpOnly，漏掉了一个地方，都可能是使得这个方案失效

使用HttpOnly有助于缓解XSS攻击，但仍然需要其他能够解决XSS漏洞的方案

##### <font color="yellow">0002 输入检查</font>

常见的Web漏洞如XSS、SQL Injection等，都要求攻击者构造一些特殊字符，这些特殊字符可能是正常用户不会用到的，所以输入检查就有存在的必要了

输入检查在很多时候也被用于格式检查

这些格式检查有一点像白名单，也可以让一些基于特殊字符的攻击失效

输入检查的逻辑，必须放在服务器端代码中实现，如果只是在客户端使用JavaScript进行输入检查，是很容易被攻击者绕过的

目前的Web开发的普遍做法，是同时在客户端使用JavaScript中和服务器端代码中实现相同的输入检查，客户端JavaScript的输入检查可以阻挡大部分误操作的用户，从而节约服务器资源

在XSS防御上，输入检查一般是检查用户输入的数据中是否包含一些特殊字符,如果发现存在特殊字符，则将这些字符过滤或编码

e.g.

- `<`
- `>`
- `'`
- `"`

比较智能的输入检查可能匹配XSS的特征，如`<script>`、`javascript`

这种输入检查的方式被称为XSS Filter，互联网上有很多开源的XSS Filter的实现

XSS Filter在用户提交数据时获取变量，并进行XSS检查，但此时用户数据并没有结合渲染页面的HTML代码，因此XSS Filter对语境的理解并不完整

如果是一个全局性的XSS Filter，则无法看到用户数据的输出语境，而只能看到用户提交了一个URL，就很可能会漏报，大多数情况下，URL是一种合法的用户数据

XSS Filter还有一个问题：其对于`<`、`>`的处理可能会改变用户数据的语义

对于XSS Filter来说，发现敏感字符`<`，如果其不够智能，粗暴地过滤或者替换了`<`，则可能会改变用户原本的意思

输入数据还可能会被展示在多个地方，每个地方的语境可能各不相同，如果使用单一的替换操作，则可能出现问题

e.g.：用户昵称会在很多地方展示，每个界面的语境也可能各不相同如果在输入时做了统一的更改，那么输出时可能有如下的问题

```text
我的偶像是\"hackjacking\"
我的偶像是"hackjacking"
```

然而第一个结果显然是用户不希望看到的

##### <font color="yellow">0003 输出检查</font>

安全编码函数
> 编码分为很多种，针对HTML代码的编码方式是HtmlEncode
> 
> HtmlEncode并非专用名词，它只是一种函数的实现，它的作用是将字符转换成HTML Entities，对应的标准是ISO-8859-1
> 
> 为了对抗XSS，在HtmlEncode中要求至少转换以下字符
> 
> 	- & - &amp
> 	- < - &lt
> 	- " - &quot
> 	- ' - &#x27 或 &apos(不推荐)
> 	- / - &#x2F(包含反斜线是因为它可能会闭合一些HTML entity)
> 
> 在PHP中，有`htmlentities()`和`htmlspecialchars()`两个函数可以满足安全要求
> 
> JavaScript的编码方式可以使用JavascriptEncode
> 
> JavascriptEncode于HtmlEncode的编码方式不同，它需要使用`\`对特殊字符进行转义在对抗XSS时，还要求输出的变量必须在引号内部以避免造成安全问题
> 
> 要求使用JavascriptEncode的变量输出一定要在引号内
> 
> 没有习惯的话，只能用更加严格的JavascriptEncode函数来保证安全
> 
> 	除了数字、字母的所以字符，都使用十六进制`\xHH`的方式进行编码
> 
> 在OWASP ESAPI中有一个安全的JavascriptEncode的实现，非常严格[http://www.owasp.org/index.php/Category:OWASP_Enterprise_Security_API](http://www.owasp.org/index.php/Category:OWASP_Enterprise_Security_API)
> 
> 除了HtmlEncode、JavascriptEncode外，还有许多用于各种情况的编码函数，比如XMLEncode(实现与HtmlEncode相似)，JSONEncode(于JavascriptEncode相似)等
> 
> 在Apache Common Lang的StringEscapeUtils里，提供了许多escape的函数
> 
> 可以在适当的情况下选用适当的函数，但编码后的数据长度可能会发生改变，从而影响某些功能在编码时需要注意这个细节，以免产生不必要的bug

只需要一种编码吗
> XSS攻击主要发生在MVC架构中的View层，大部分的XSS漏洞可以在模板系统中解决
> 
> 在python的开发架构Django自带的模板系统Django Templates中，可以使用escape进行HtmlEncode
> 
> 在正确的地方使用正确的编码方式
> 
> 对于浏览器来说，htmlparser会优先于JavaScript Parser执行，所以解析过程是被HtmlEncode的字符先被解码，然后执行JavaScript事件
> 
> 导致XSS攻击发生的原因是由于没有分清楚输出变量的语境，因此并非用了auto-escape就万事大吉了
> 
> XSS的防御需要区分情况对待

##### <font color="yellow">0004 正确地防御XSS</font>

> XSS的本质还是一种HTML注入，用户的数据被当成了HTML代码的一部分执行，从而混淆了原本的语义，产生了新的语义，如果网站使用了MVC架构，那么XSS就发生在View层——在应用拼接变量到HTML页面时产生，所以在用户提交数据处进行输入检查的方案，其实并不是在真正发生攻击的地方做防御，想要根治XSS问题，可以列出所有XSS可能发生的场景，再一一解决
> 
> 可能存在以下场景
> 
> - 在HTML标签中输出
> 	- 所有在标签中输出的变量，如果未作任何处理，都可能导致直接产生XSS
> 	- 防御方法：对变量使用HtmlEncode
> - 在HTML属性中输出
> 	- 与标签中输出的XSS相似
> 	- 防御方法：对变量使用HtmlEncode，在OWASP EASAPI中推荐了一种更严格的HtmlEncode——除了字母、数字外，其他所有的特殊字符都被编码成HTMLEnities
> - 在`<script>`标签中输出
> 	- 首先应该确保输出的变量在引号中
> 	- 攻击者需要先闭合引号才能实施XSS攻击
> 	- 防御方法：使用JavascriptEncode
> - 在事件中输出
> - 与`<script>`输出类似
> - 防御方法：使用JavascriptEncode
> - 在CSS中输出
> 	- 防御方法：尽可能禁止用户可控制的变量在`<style>`标签、HTML标签的style属性以及CSS文件中输出，如果一定有这样的需求，OWASP ESAPI中推荐了`encodeForCSS()`函数
> 	- 原理：类似`ESAPI.encoder().encodeForJavaScript()`函数，除了字母、数字外的所有字符都被编码成十六进制形式(`\uHH`)
> - 在地址中输出
> 	1. 在URL的path(路径)或者search(参数)中输出
> 
> 		URLEncode会将字符转换为`%HH`形式
> 
> 		e.g.：`空格 - %20`、`< - %3c`
> 
> 		防御方法：使用URLEncode即可
> 
> 	2. 整个URL能够被用户完全控制，这是URL的Protocal和Host部分是不能够使用URLEncode的，否则会改变URl的语义
> 
> 		在Protocal与Host中，如果使用严格的URLEncode函数，则会吧`:`、`/`、`/`、` `、`、`、`.`等都编码掉 
> 
> 		除了javascript作为伪协议可以执行代码外，还有vbscript、dataURI等协议可能导致脚本执行
> 
> 		dataURI这个伪协议是Mozilla所支持的，能够将一段代码写在URL里
> 
> 		防御方法：如果变量是整个URL，则应该先检查是否以http开头(如果不是则自动添加)以保证不会出现伪协议类的XSS攻击，再对变量进行URLEncode

##### <font color="yellow">0005 处理富文本</font>

> 有些时候，网站需要允许用户提交一些自定义的HTML代码，称之为富文本，在处理富文本时，还是要回到输入检查的思路上来，输入检查的主要问题是在检查时还不知道变量的输出语境，但用户提交的富文本数据，其语义是完整的HTML代码，在输出时也不会`\n`，拼凑到某个标签的属性中，因此可以特殊情况特殊处理，在**正确地防御XSS**中，列出了所有在HTML中可能执行脚本的地方，而一个优秀的XSS Filter，也应该能够找出HTML代码中所有可能执行脚本的地方，HTML是一种结构化的语言，比较好分析，通过htmlparser可以解析出HTML代码的标签、标签属性和事件，在过滤富文本时，事件应该被严格禁止，因为富文本的展示需求里不应该包括事件这种动态效果，而一些危险的标签，如`<iframe>`、`<scroipt>`、`<base>`、`<from>`等，也是应该严格禁止的对象，在标签的选择上，<font color="red">应该使用白名单，避免使用黑名单</font>
> 
> e.g.：`<a>`、`<img>`、`<div>`等比较安全的标签
> 
> 在富文本过滤中，处理CSS也是一件麻烦的事情，如果允许用户自定义CSS、style，则也可能导致XSS攻击，因此尽可能禁止用户自定义CSS与style，如果一定要允许用户自定义样式，则只能像过滤富文本一样过滤CSS，有一些比较成熟的开源项目，实现了对富文本的XSS检查，Anti-Samy是OWASP上的一个开源项目，也是目前最好的XSS Filter，最早的时候，它是基于Java的，现在已扩展到.NET等语言，[https://www.owasp.org/index.php/Category:OWASP_AntiSamy_Project](https://www.owasp.org/index.php/Category:OWASP_AntiSamy_Project)，在PHP中，可以使用另外一个广受好评的开源项目：HTMLPurify，[http://htmlpurifier.org/](http://htmlpurifier.org/)

##### <font color="yellow">0006 防御DOM Based XSS</font>

> 在button的onclock事件中，执行了定义的一个函数，将HTML代码写入DOM节点，最后导致XSS的发生，事实上，DOM Based XSS是从JavaScript中输出数据到HTML页面里，而前面提到的方法都是针对从服务器应用直接输出到HTML页面的XSS漏洞，因此并不适用于DOM型XSS
> 
> 防御方法：从JavaScript输出到HTML页面，也相当于一次XSS输出到过程，需要分语境使用不同的编码函数
> 
> 以下几个地方是JavaScript输出到HTML页面的必经之路
> 
> - `document.write()`：页面载入过程中用实时脚本创建页面内容，以及用延时脚本创建本窗口或新窗口的内容，在document被加载完后调用`docuemnt.write`方法时将会自动去触发`document.open()`，在载入页面后，浏览器输出流自动关闭，在此之后，任何一个对当前页面进行操作的`document.write()`方法将打开一个新的输出流，它将清除当前页面内容(包括源文档的任何变量或值)(`document.open()`：打开一个新文档，即打开一个流，并擦除当前文档的内容)
> - `document.writeln()`
> - `xxx.innerHTML = `
> - `xxx.outerHTML = `
> - `innerHTML.replace`：获取或替换html中的内容
> - `document.attachEvent()`
> - `window.attachEvent()`：通过`window.attachEvent()`监听小事件
> - `document.location.replace()`：用一个新文档取代当前文档
> - `document.location.assign()`：加载一个新的文档
> - ......
> 
> 需要重点关注这几个地方的参数是否可以被用户控制
> 
> 除了服务器端直接输出变量到JavaScript外，还有几个地方可能会成为DOM型XSS的输入点，也需要重点关注
> 
> - 页面中所有的inputs框
> - `window.location`(`href`、`hash`等)：用于获得当前页面的地址(URL)，并把浏览器重定向到新的页面
> - `window.name`：当前window的名称
> - `document.referrer`：返回一个url，当前页面就是从这个URI所代表的页面跳转或打开的
> - `document.cookie`
> - `localstorage`：`localstorage`属性允许在浏览器中存储key-value对的数据
> - `XMLHttpRsquest`返回的数据：XMLHttpRsquest是一组API函数集，可被JavaScript、JScript、VBScript以及其它web浏览器内嵌的脚本语言调用，通过HTTP在浏览器和web服务器之间收发XML或其它数据
> - ......
> 
> 安全研究者Stefano Di Paola设立了一个DOM型XSS的cheatsheet[http://code.google.com/p/domxsswiki](http://code.google.com/p/domxsswiki)

##### <font color="yellow">0007 不同角度看XSS的风险</font>

> 一般来说，存储型XSS的风险会高于反射型XSS，因为存储型XSS会保存在服务器上，有可能跨网站存在它不改变url的原有结构，因此有时候还能逃过一些IDS的检测
> 
> 从攻击过程来说，反射型XSS一般要求攻击者诱使用户点击一个包含XSS代码的URL链接，而存储型XSS只需要让用户浏览一个正常的URL链接
> 
> 从风险的角度来看，用户之间有互动的页面，是可能发起XSS Worm攻击的地方，而根据不同页面的PageView高低，也可以分析出哪些页面受XSS攻击后影响会更大

#### <font color="yellow">007 总结</font>

> 理论上，XSS漏洞虽然复杂，但却是可以彻底解决的，在设计XSS解决方案时，应该深入理解XSS攻击的原理，针对不同的场景使用不同的方法，同时有很多开源项目为我们提供了参考
> 
> 过滤输入的数据，包括`'`、`"`、`<`、`>`等特殊字符
> 
> 对输出到页面的数据进行相应的编码转换，包括HTMl实体编码、JavaScript编码等

### <font color="yellow">03 跨站点请求伪造(CSRF)</font>

#### <font color="yellow">001 绕过Referer</font>

##### <font color="yellow">0001 Refere为空条件下</font>

利用`ftp://`、`http://`、`https://`、`file://`、`javascript:`、`data:`这个时候浏览器地址栏是`file://`开头的，如果这个HTML页面向任何http站点提交请求的话，这些请求的Referer都是空的

e.g.
- 利用data协议
- bese64编码
- 解码即可看到代码
- 利用https协议

##### <font color="yellow">0002 判断Referer是某域情况下绕过</font>

比如你找的csrf是xxx.com验证的referer是验证的*.xx.com可以找个二级域名之后`<img "csrf地址">`之后在把文章地址发出去就可以伪造

##### <font color="yellow">0003 判断Referer是否存在某关键词</font>

referer判断存在不存在google.com这个关键词，在网站新建一个google.com目录把CSRF存放在google.com目录,即可绕过

##### <font color="yellow">0004 判断referer是否有某域名</font>

判断了Referer开头是否以126.com以及126子域名不验证根域名为126.com 那么我这里可以构造子域名x.126.com.xxx.com作为蠕虫传播的载体服务器，即可绕过

Referer防御CSRF原理：HTTP Referer是header的一部分，当浏览器向web服务器发送请求的时候，一般会带上Referer，告诉服务器我是从哪个页面链接过来的，服务器基此可以获得一些信息用于处理,当用户点击被构造好的CSRF利用页面，那么在执行用户对应操作时，提交的HTTP请求中就有对应的Referer值，此时服务端判断Referer值是否与服务器的域名信息有关,如果不相关则不执行操作

Referer防御代码编写：在PHP中使用`$_SERVER[‘HTTP_REFERER’]`获取页面提交请求中的Referer值(`<?php if(strpos($_SERVER['HTTP_REFERER'],'xx.com') !== false) { 判断成功 } else { 判断失败 } ?>`)

绕过Referer技巧：如果服务端只判断当前的Referer中是否具有域名，那么直接可以新建文件夹进行绕过

Burpsutie自动生成POC

#### <font color="yellow">002 CSRF简介</font>

CSRF(Cross Site Request Forgery)，跨站点请求伪造，它是一种常见的攻击方式，但很多开发者对它很陌生，CSRF也是Web安全中最容易被忽略的一种攻击方式，甚至很多安全工程师都不理解它的利用条件与危害，因此不给予重视，但CSRF在某些时候却能够产生强大的破坏性

#### <font color="yellow">003 CSRF进阶</font>

##### <font color="yellow">0001 浏览器说Cookie策略</font>

> 攻击者伪造的请求之所以能被搜狐服务器验证通过，是因为用户的浏览器成功发送了Cookie的缘故
> 
> 浏览器所持有的Cookie分为两种
> 
> 1.Session Cookie(又称临时Cookie)：Session Cookie则没有指定Expire时间，所以浏览器关闭后，Session Cookie就失效了
> 2.Third-party Cookie(又称本地Cookie)：Third-party Cookie是服务器在Set-Cookie时指定了Expire时间，只有到了Expire时间后Cookie才会生效，所以这种Cookie会保存在本地
> 
> 如果浏览器从一个域的页面中要加载另一个域的资源，由于安全原因，某些浏览器会组织Third-party Cookie的发送，IE出于安全考虑，默认禁止了浏览器在`<img>`、`<iframe>`、`<script>`、`<link>`等标签中发送第三方Cookie，在Firefox中，默认策略是允许发送第三方Cookie的
> 
> 在当前的主流浏览器中，默认会拦截Third-party Cookie的有：IE6、IE7、IE8、Safari
> 
> 不会拦截的有：Firefox2、Firefox3、Opera、Google Chrome、Android等
> 
> 但若CSRF攻击的目标并不需要使用Cookie，则也不需要顾虑浏览器的Cookie策略了

##### <font color="yellow">0002 P3P头的副作用</font>

> 尽管有些CSRF攻击实施起来不需要认证，不需要发送Cookie，但是不可否认的是，大部分敏感或重要的操作是躲藏在认证之后的，因此浏览器拦截第三方Cookie的发送，在某种程度上来说，降低了CSRF攻击的威力，可是这一情况在P3P头介入后变得复杂起来
> 
> P3P Header(The Platform For Privacy Preferences)是W3C制定的一项关于隐私的标准：隐私偏好平台
> 
> 如果网站返回给浏览器的HTTP头中包含有P3P头，则某种程度上来说，将允许浏览器发送第三方Cookie
> 
> 在网站的业务中，P3P头主要用于类似广告等需要跨域访问的页面，但是，很遗憾的是，P3P头设置后对于Cookie的影响将扩大到整个域中的所有页面，因为Cookie是以域和path为单位的，这并不符合最小权限原则
> 
> P3P的策略看起来似乎很难懂，但其实语法很简单，都是一一对应的关系，可以查询W3C标准
> 
> e.g.
> 
> `CP - Compact Policy`
> 
> `CURa - <current/>`
> 
> `a - always`
> 
> [http://www.w3.org/TR/P3P/](http://www.w3.org/TR/P3P/)
> 
> P3P头也可以直接引用一个XML策略文件
> 
> 正因为P3P头目前在网站的应用中被广泛应用，因此在CSRF的防御中不能依赖于浏览器对第三方Cookie的拦截策略，不能心存侥幸

##### <font color="yellow">0003 GET/POST</font>

> 在CSRF攻击流行之初，许多人认为CSRF攻击只能有GET请求发起，因此很多开发者都认为只要把重要的操作改成只允许POST请求，就能防止CSRF
> 
> 形成错误观点的原因主要在于大多数CSRF攻击发起时，使用的HTML标签都是`<img>`、`<iframe>`、`<script>`等带src属性的标签，这类标签只能发起一次GET请求，但不能发起POST请求
> 
> 在禁止GET请求时的攻击方法
> 
> 1.在页面中构造好一个from表单，然后使用JavaScript自动提交这个表单
> 
> 2.将这个页面隐藏在一个看不见的iframe窗口中，那么整个自动提交表单的过程对于用户来说也是看不见的
> 
> 3.安全研究者pdp展示了一个Gmail CSRF漏洞攻击过程，用户登录Gmail账户，一边浏览器获得Gmail的临时Cookie，诱使用户访问一个恶意页面，在这个恶意页面中，隐藏了一个iframe，该iframe的地址指向pdp写的CSRF构造页面，这个链接实际就是把参数生成一个POST的表单，并自动提交，由于浏览器中已经存在Gmail的临时Cookie，所有用户在iframe中对Gmail发起的这次请求会成功，此时，邮箱的Filter中会新创建一条规则，将所有带附件的邮件都转发到攻击者的邮箱中

##### <font color="yellow">0004 Flash CSRF</font>

> Flash中也有很多种方式能够发起网络请求，包括POST，除了URLRequest外，在Flash中还可以使用getURL，loadVars等方式发起请求，在IE6、IE7中，Flash发送的网络请求均可以带上本地Cookie，但IE8起，Flash发起的网络请求已经不再发送本地Cookie了

##### <font color="yellow">0005 CSRF Worm</font>

> 国内的安全组织80sec公布了一个百度的CSRF Worm，漏洞出现在百度用户中心的发送短消息功能中，只需要修改参数sn，即可对指定用户发送短消息，然而百度的另一个接口则能查询出某个用户的所有好友，将两者结合起来，可以组成一个CSRF Worm，让一个百度用户查看一个恶意页面后，将给他的所有好友发送一条短消息，这条短消息中包含一张图片，其地址在次指向CSRF页面，使得这些好友再次将消息发送给他的好友
> 
> - 模拟服务器端取得request的参数：定义蠕虫页面服务器地址，取得？、&符号后的字符串，从URL中提取感染蠕虫的用户名和感染者好友的用户名
> - 好友json数据的动态获取：通过CSRF漏洞从远程加载受害者的好友json数据，根据该接口的json数据格式，提取好友数据为蠕虫的传播流程做准备
> - 感染信息输出和消息发送的核心部分：将感染者的用户名和需要传播的好友用户名放到入错那个链接内，输出短信息
> 
> 这个蠕虫很好地展示了CSRF的破坏性，即使没有XSS漏洞，仅仅依靠CSRF，也是能够发起

#### <font color="yellow">004 CSRF防御</font>

##### <font color="yellow">0001 验证码</font>

> CSRF攻击的过程往往是在用户不知情的情况下构造了网络请求，然而验证码则强制用户必须与应用进行交互，才能完成最终请求，验证码只能作为防御CSRF攻击的一种辅助手段，而不能作为最主要的解决方案

##### <font color="yellow">0002 Referer Check</font>

> Referer Check在互联网中最常见的应用就是防止图片盗链，同理，Referer Check也可以被用于检查请求是否来自合法的源，常见的互联网应用，页面与页面之间都具有一定的逻辑关系，这就使得每个正常请求的Referer具有一定的规律，即使我们能够通过检查Referer是否合法来检查用户是否被CSRF攻击，也仅仅是满足了防御的充分条件，<font color="red">Referer Check的缺陷在于服务器并非什么时候都能取到Referer</font>，在Flash的一些版本中，曾经可以发送自定义的Referer头，虽然Flash在新版本中已经加强了安全限制，不再允许发送自定义的Referer头，但是难免不会有别的客户端插件允许这种操作，出于以上种种原因，我们还是无法依赖于Referer Check作为防御CSRF的主要手段，但是通过Referer Check来监控CSRF的发生却是一种可行的方案

##### <font color="yellow">0003 Anti CSRF Token</font>

> CSRF攻击成功的原因：<font color="red">重要操作的所有参数都是可以被攻击者猜测到的</font>
> 
> 攻击者只有预测出URL的所有参数与参数值，才能成功地构造一个伪造的请求，反之，攻击者将无法完成攻击，出于以上原因，可以想到一个解决方案：把参数加密，或者使用一些随机数，从而让攻击者无法猜测到参数值(不可预测性原则)，在攻击者不知道salt的情况下，是无法构造出这个URL的，因此也就无法发起CSRF攻击了，对于服务器来说，可以从Session或Cookie中取得`username = name`的值，再结合salt对整个请求进行验证，正常请求会被认为是合法的，但这个方法也有其对应的问题
> 
> - 加密后的URL对用户不友好
> - 加随机数后的URL用户不能收藏
> - 普通参数加密后，数据分析会非常困难
> 
> 因此我们需要一个更加通用的解决方案——Anti CSRF Token
> 
> 要Token足够随机，必须使用足够安全的随机数生成算法，或者采用真随机数生成器(物理随机)，Token因该作为一个秘密，为用户与服务器所共同持有，不能被第三方知晓，在实际应用时，Token可以放在用户的Session中，或者浏览器的Cookie中，Token需要同时放在表单与Session，在提交请求时，只需验证两个Token是否一致，如果不一致(包括空Token)，则有可能发生CSRF攻击

##### <font color="yellow">Token的使用原则</font>

> 防御CSRF攻击的Token是根据不可预测性原则设计的方案，所以Token的生成一定要足够随机，需要使用安全的随机数生成器生成Token，如果Token保存在Cookie中，那么如果用户同时打开多个页面同时操作时，当某个页面消耗点Token时，其他页面的Token还是原先被消耗的Token，就会产生差错
> 
> 解决方法：同时生成多个Token，一对一，更放心
> 
> 如果Token出现在某个页面的URL中，则可能会通过Referer的方式泄露，如果页面包含了一张攻击者能指定地址的图片，则该请求地址会作为HTTP请求的Referer发送到evil.com的服务器上，从而导致Token泄露，因此在使用Token时，因该尽量把Token放在表单中把敏感操作由GET改为POST以from表单(或者AJAX)到形式提交，可以避免Token泄露，还有一些其他途径可能导致Token泄露，如XSS及跨域漏洞，都可以让攻击者盗取Token的值，CSRF的Token只适用于防范CSRF攻击，当网站中还有XSS漏洞时，这个方案就会变的无效，因为XSS乐意模拟客户端浏览器执行任意操作，在XSS攻击下，攻击者完全可以请求页面后，读出页面里的Token值，然后构造一个合法的请求，此过程称之为XSRF，用以与CSRF进行区分，XSS带来的问题，因该使用XSS的防御方案给予解决，否则CSRF的Token防御就是空中楼阁，安全防御的体系是相辅相成、缺一不可的

#### <font color="yellow">005 总结</font>

> CSRF攻击是攻击者利用用户的身份操作用户账户的一种攻击方式，设计CSRF的防御方案必须先理解CSRF攻击的原理和本质，根据不可预测性原则，我们通常使用Anti CSRF Token来防御CSRF攻击，在使用Token时，要注意Token的保密性和随机性











































































































