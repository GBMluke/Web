# 原文
[传送门](https://blog.csdn.net/qq_41770175/article/details/93486383?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522164586929616780274123451%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fall.%2522%257D&request_id=164586929616780274123451&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~all~first_rank_ecpm_v1~rank_v31_ecpm-1-93486383.pc_search_result_cache&utm_term=%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1&spm=1018.2226.3001.4187)

# 0x00 审计方法总结

主要代码审计方法是跟踪用户输入数据和敏感函数参数回溯

跟踪用户输入的数据，判断数据进入的每一个代码逻辑是否有可利用的点，此处的代码逻辑可以是一个函数，或者是条小小的条件判断语句

敏感函数参数回溯，根据敏感函数，逆向追踪参数传递的过程，这个方法是最高效、最常用的方法，大多数漏洞的产生是因为函数的使用不当导致的，只要找到这些函数，就能够快速挖掘想要的漏洞

以下是基于关键词审计的技巧总结

在搜索时要注意是否为整个单词，以及小写敏感这些设置

|漏洞名称|关键词|
|-|-|
|密码硬编码、密码明文存储|password、pass、jdbc|
|XSS|getParamter、<%=、param|
|SQL|Select、Dao、from、delete、update、insert|
|任意文件下载|download、fileName、filePath、write、getFile、getWriter|
|任意文件删除|Delete、deleteFile、filePath|
|文件上传|Upload、write、fileName、filePath|
|命令注入|getRuntime、exec、cmd、shell|
|缓冲区溢出|strcpy、strcat、scanf、memcpy、memmove、memeccpy、Getc()、fgetc()、getchar、read、printf|
|XML注入|DocumentBuilder、XMLStreamReader、SAXBuilder、SAXParser、SAXReader、XMLReader、SAXSource、TransformerFactory、SAXTransformerFactory、SchemaFactory|
|反序列化漏洞|ObjectInputStream.readObject、ObjectInputStream.readUnshared、XMLDecoder.readObjectYaml.load、XStream.fromXML、ObjectMapper.readValue、JSON.parseObject|
|URL跳转|sendRedirect、setHeader、forward|
|不安全组件暴露|activity、Broadcast Receiver、Content Provider、Service、inter-filter|
|日志记录敏感信息|log log.info logger.info|
|代码执行|eval、system、exec|

# 0x01可基于关键词审计的漏洞

## 001.密码硬编码

***审计方法***

密码硬编码最容易找，直接用Sublime Text打开项目目录，然后按Ctrl + Shift + F进行全局搜索password关键词

![image](https://img-blog.csdnimg.cn/20190624144753801.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

## 002.反射性XSS

***审计方法***

反射性XSS一般fortify一般都能扫描出来

如果是手动找，可以全局搜索以下关键词
> getParamter
> 
> <%=
> 
> param

***漏洞代码示例***

1. EL表达式输出请求参数

![image](https://img-blog.csdnimg.cn/20190624144753807.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

代码在170行和305行处获取请求参数中的groupld值，在未经检查参数合法性的情况下输出在JavaScript代码中，存在反射性XSS漏洞

2. 输出getParamter获取的参数

![image](https://img-blog.csdnimg.cn/20190624144753779.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

然后在224行打印到如下的js代码中

![image](https://img-blog.csdnimg.cn/20190624144753784.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

## 003.存储型XSS

***审计方法***

1. 全局搜索数据库的插入语句(关键词:insert，save，update)，然后找到该插入语句所属的方法名如(insertUser())，然后全局搜索该方法在哪里被调用，一层层地跟踪，直到getParamter()方法获取请求参数的地方停止，如果没有全局XSS过滤器，跟踪的整个流程都没有对获取的参数过滤，则存在存储型XSS

![image](https://img-blog.csdnimg.cn/20190624145016766.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

2. 从getParamer关键词开始，跟踪请求参数，直到插入数据库的语句，如果中间没有过滤参数，则存在存储型XSS

![image](https://img-blog.csdnimg.cn/20190624145016811.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

代码中45行和46行获取usertype和name的值，然后在56行存进数据库由于没有过滤传进来的函数，所以会在显示时出来触发XSS

## 004.SQL注入注入

***审计方法***

SQL注入一般fortify一般都能扫描出来

手动找的话，一般直接搜索select、update、delete、insert关键词就会有收获

如果SQL注入语句中有出现+ append、$ () #等字眼，如果没有配置SQL过滤文件，则判断存在SQL注入注入漏洞

![image](https://img-blog.csdnimg.cn/20190624145016831.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

当找到某个变量关键词有 SQL 注入漏洞时，还可以直接全局搜索那个关键词找出类似漏洞的文件，上面中可以直接全局搜索tableName关键词

![image](https://img-blog.csdnimg.cn/20190624145016845.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

要查找那个页面调用到含有漏洞的代码，就要跟踪方法的调用栈。以上面的注入点tableName为例

双击打开该文件，然后查看该变量所在函数

![image](https://img-blog.csdnimg.cn/20190624145016877.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

发现该函数对应的URL为/lookOverCubeFile，对应的功能为查看模型任务生成的文件

## 005.任意文件下载

***审计方法***

全局搜索以下关键词fileName、filePath、getFile、getWriter

***漏洞示例***

![image](https://img-blog.csdnimg.cn/20190624145219544.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

代码在downloadFile()函数中获取请求参数中的affixalName的值，然后赋值给FileName变量，接着在196行处通过拼接字符串赋值给downPath变量，然后在198行处调用download函数并把 downPath的值传进函数，download函数的代码如下

![image](https://img-blog.csdnimg.cn/20190624145219565.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

！[image](https://img-blog.csdnimg.cn/20190624145219576.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

download函数把filePath处的文件写到http相应中，在整个流程中并没有对文件名的合法性进行检查，存在任意文件下载漏洞，如通过affixalName的值设置为../../../WEB-INF/web.xml可以下载网站的web.xml文件

## 006.任意文件删除

***审计方法***

任意文件删除漏洞搜索以下关键词可以找到delete、deleteFile、fileName、filePath

***漏洞示例***

![image](https://img-blog.csdnimg.cn/20190624145219593.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

代码在41行获取fileName的值，在44行处调用ds.deleteFile()函数删除文件，该函数的代码如下

![image](https://img-blog.csdnimg.cn/20190624145219589.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

在整个流程中并没有对文件名的合法性进行检查，存在任意文件删除漏洞，如通过把fileName的值设置为../WEB-INF/web.xml可以删除网站的web.xml文件

## 007.文件上传

***审计方法***

文件上传可以搜索以下关键词(需注意有没有配置文件上传白名单)upload、write、fileName、filePath

在查看时，主要判断是否有检查后缀名，同时要查看配置文件是否有设置白名单或者黑名单，像下面这种是检查了的

![image](https://img-blog.csdnimg.cn/20190624145219597.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

下面的这种没检查

```java
List<FileItem> fileItems = servletFileUpload.parseRequest(request); for (int i = 0; i < fileItems.size(); ++i) {
FileItem fi = (FileItem) fileItems.get(i); String strFileName = fi.getName();

if (strFileName != null && !"".endsWith(strFileName)) { String fileName = opId + "_" + getTimeSequence() + "."

+ getFileNameExtension(strFileName);

String diskFileName = path + fileName; File file = new File(diskFileName); if (file.exists()) {
file.delete();

}

fi.write(new File(diskFileName)); resultArrayNode.add(fileName);

......

private String getFileNameExtension(String fullFileName) { if (fullFileName == null) {
return null;

}

int pos = fullFileName.lastIndexOf(".");

if (pos != -1) {
return fullFileName.substring(pos + 1, fullFileName.length());

} else {
return null;

}
```

## 008.命令注入

***审计方法***

可以搜索以下关键词getRuntime、exec、cmd、shell

![image](https://img-blog.csdnimg.cn/20190624145219606.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

在第205行中，通过拼接传过来的ip值来执行命令

如果ip值通过外部传入，则可以构造以下的ip值来执行net user命令

127.0.0.1&&net user

## 009.缓冲区溢出

***审计方法***

主要通过搜索关键词定位，再分析上下文

可搜索以下关键词strcpy、strcat、scanf、memcpy、memmove、memeccpy Getc()、fgetc()、getchar;read、printf

***漏洞示例***

文件\kt\frame\public\tool\socket_repeater\mysocket.h中第177行，这里的的参数hostname拷贝到m_hostname，具体如下图所示

![image](https://img-blog.csdnimg.cn/20190624145219632.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

m_hostname的大小为MAXNAME

![image](https://img-blog.csdnimg.cn/20190624145219982.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

继续看，可以看到大小为255

![image](https://img-blog.csdnimg.cn/20190624145219991.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

如果传入的长度比255要大，就会造成缓冲区溢出

## 010.XML注入

***审计方法***

XML解析一般导入配置、数据传输接口等场景可能会用到，可通过搜索一下关键字定位

DocumentBuilder、XMLStreamReader、SAXBuilder、SAXParser、SAXReader、XMLReader、SAXSource、TransformerFactory、SAXTransformerFactory、SchemaFactory

涉及到XML文件处理的场景可留意下XML解析器是否禁用外部实体，从而判断是否存在XXE

***漏洞示例***

在代码6行处、获取DOM解析器，解析XML文档的输入流，得到一个Document

![image](https://img-blog.csdnimg.cn/2019062414522011.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

如果没有禁用DTD则存在XXE漏洞，以下代码为XXE防御代码

![image](https://img-blog.csdnimg.cn/2019062414522012.jpeg)

## 011.日志记录敏感信息

***审计方法***

通过搜索关键词log.info、logger.info来进行定位

在STFtpOperate.java文件中，代码134行处，直接将用户名密码记录在日志中

## 012.URL转载

***审计方法***

通过搜索一下关键词定位

sendRedirect、setHeader、forward

需注意有没有配置url跳转白名单

***漏洞示例***

以下代码中40行处只判断site只是否为空，没有对url进行判断是否为本站url，导致了url跳转漏洞

![image](https://img-blog.csdnimg.cn/20190624145628317.jpeg)

## 013.敏感信息泄露及错误处理

***审计方法***

查看配置文件是否配置统一错误页面，如果有则不存在此漏洞，如果没有再通过搜索以下关键词搜索定位

Getmessage、exception

***漏洞示例***

在以下文件中代码89行处打印出程序发生异常时的具体信息

![image](https://img-blog.csdnimg.cn/20190624145628316.jpeg)

## 014.反序列化漏洞

***审计方法***

Java程序使用ObjectInputStream对象的readObject方法将反序列化数据转换为java对象

但当输入的反序列化的数据可被用户控制，那么攻击者即可通过构造恶意输入，让反序列化产生非预期的对象，在此过程中执行构造的任意代码

反序列化操作一般在导入模版文件、网络通信、数据传输、日志格式化存储、对象数据落磁盘或DB存储等业务场景，在代码审计时可重点关注一些反序列化操作函数并判断输入是否可控，如下

ObjectInputStream.readObject、ObjectInputStream.readUnshared、XMLDecoder.readObject、Yaml.load、XStream.fromXML、ObjectMapper.readValue、JSON.parseObject

***漏洞示例***

以下代码中，程序读取输入流并将其反序列化为对象，此时可查看项目工程中是否引入可利用的commons-collections 3.1、commons-fileupload 1.3.1等第三方库，即可构造特定反序列化对象实现任意代码执行

![image](https://img-blog.csdnimg.cn/20190624145628338.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

## 015.不安全组件暴露

***审计方法***

通过查看配置文件AndroidManifest.XML，查看<inter-filter>属性有没有配置false

***漏洞示例***

AndriodManifest.xml文件中，代码24行处activity组件添加<intent-filter>属性，没有配置false默认组件可被导出

![image](https://img-blog.csdnimg.cn/20190624145628341.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

# 0x02 其他漏洞审计方法

## 001.CSRF

***审计方法***

通过查看配置文件有没有配置csrf全局过滤器，如果没有则重点看每个操作前有没有添加token的防护机制在Smpkpiappealcontroller.java中200处，直接用用ids控制删除操作，而没有添加防csrf的随机token验证检查，存在csrf漏洞

![image](https://img-blog.csdnimg.cn/20190624145628335.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

Java/main/com/venustech/tsoc/cupid/smp/kpi/dao/smpkpideclardao.java中517行，对传入的ids进行删除操作

![image](https://img-blog.csdnimg.cn/20190624145628366.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

## 002.Struts2远程代码执行漏洞

***审计方法***

查看struts插件的版本信息是否为漏洞版本

[漏洞版本查询网址](https://www.exploit-db.com/)

## 003.越权操作

***审计方法***

重点关注用户操作请求时查看是否有对当前登陆用户权限做校验从而确定是否存在漏洞，有些厂商会使用一些主流的权限框架，例如shiro，spring security等框架，那么需要重点关注框架的配置文件以及实现方法

***漏洞示例***

在以下文件中采用了shiro框架进行权限控制，在代码58-72行处为控制访问路径的权限设置，51-55行处为对admin路径下访问限制，只有SysyUserFilter设置了isAccessAllowed方法，其他过滤均没有

![image](https://img-blog.csdnimg.cn/20190624145628382.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

SysUserFilter中isAccessAllowed具体实现方法如下，90-93行处没有对是否为当前用户进行判断，导致了越权

![image](https://img-blog.csdnimg.cn/20190624145628386.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

其他过滤文件均只设置了onAccessDaniad()方法

![image](https://img-blog.csdnimg.cn/20190624145628401.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

如果没有使用框架的话，就要注意每个操作是否有权限代码7行处获取session里的username，只判断了username是不是为空，如果在截取数据包的时候将username再重新赋一个值就有可能造成越权漏洞

![image](https://img-blog.csdnimg.cn/20190624145628411.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

以这个年度服务费用编制功能为例，测试一下，代码如图所示

![image](https://img-blog.csdnimg.cn/20190624145628396.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

![image](https://img-blog.csdnimg.cn/20190624145628437.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)

## 004.会话超时设置

***审计方法***

Javaweb应用会话超时设置一般有两种方法

1. 在配置文件web.xml设置

![image](https://img-blog.csdnimg.cn/20190624145628407.jpeg)

2. 通过java代码设置

![image](https://img-blog.csdnimg.cn/20190624145628423.jpeg)

## 005.敏感数据弱加密

***审计方法***

敏感数据弱加密主要看数据传输中的加密方法，一般写在工具类util中以下文件中为base64编码方法

![image](https://img-blog.csdnimg.cn/20190624145628440.jpeg?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQxNzcwMTc1,size_16,color_FFFFFF,t_70)
