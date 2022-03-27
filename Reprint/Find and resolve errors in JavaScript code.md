# 原文
[传送门](https://developer.mozilla.org/zh-CN/docs/Learn/JavaScript/First_steps/What_went_wrong)

# 查找并解决JavaScript代码的错误

|目标|预备知识|
|-|-|
|获得独立修复简单问题的能力和信心|计算机基础知识，初步理解HTML和CSS，了解JavaScript|

## 错误类型

一般来说，代码错误主要分为两种

1. 语法错误

> 代码中错在拼写错误，将导致程序完全或部分不能运行，通常你会收到一些出错信息
> 
> 只要熟悉语言并了解出错信息的含义，你就能够顺利修复它们

2. 逻辑错误

> 有些代码语法虽正确，但执行结果和预期相悖，这里便存在着逻辑错误
> 
> 这意味着程序虽能执行，但会给出错误的结果
> 
> 由于一般你不会收到来自这些错误的提示，他们通常比语法错误更难修复

事情远没有你想的那么简单，随着探究的深入，会有更多差异因素浮出水面，但在变成生涯的初级阶段，上述分类方法已经足够了

## 出错的示例

让我们来到猜数字游戏，这次我们将故意引入一些错误

[下载链接](https://github.com/roy-tian/learning-area/blob/master/javascript/introduction-to-js-1/troubleshooting/number-game-errors.html)，[在线运行](https://roy-tian.github.io/learning-area/javascript/introduction-to-js-1/troubleshooting/number-game-errors.html)

请分别在你的文本编辑器和浏览器中打开刚下载的文件

先试玩游戏，你会发现在点击确定按钮时，游戏并没有响应

首先查看开发者控制台，看是否存在语法错误，然后尝试修复

## 语法错误：第一轮

[以前的课程](https://developer.mozilla.org/zh-CN/docs/Learn/Common_questions/What_are_browser_developer_tools)中，你学会了在开发工具JavaScript控制台中输入一些简单的JavaScript命令(如果你忘记了如何在浏览器中打开它，可以直接打开上面的链接)

更实用的是，当JavaScript代码进入浏览器的JavaScript引擎时，如果存在语法错误，控制台会提供出错信息现在我们去看一看

打开number-game-errors.html所在的标签页，然后打开JavaScript控制台，你将看到以下出错信息

![image](https://media.prod.mdn.mozit.cloud/attachments/2018/10/17/16256/d8b459e669e7b1c1de765cf377e61d81/%E5%B1%8F%E5%B9%95%E5%BF%AB%E7%85%A7_2018-10-17_20.27.08.png)

这个错误很容易跟踪，浏览器为你提供了几条有用的信息(截图来自Firefox，其他浏览器也提供类似信息)从左到右依次为

1. 红色`!`表示这是一个错误

2. 一条出错信息，表示问题出在哪儿`TypeError：guessSubmit.addeventListener is not a function`(类型错误:guessSubmit.addeventListener不是函数)

3. 点击`[详细了解]`将跳转到一个MDN页面，其中包含了此类错误超详细的解释

4. JavaScript文件名，点击将跳转到开发者工具的`调试器`标签页，如果你按照这个链接，你会看到错误突出显示的确切行

5. 出错的行，以及导致错误的首个字符号，这里错误来自86行，第3个字符

我们在代码编辑器中找到第86行

```javascript
guessSubmit.addeventListener('click', checkGuess);
```

出错信息显示`guessSubmit.addeventListener不是一个函数`，说明这里可能存在拼写错误，如果你不确定某语法的拼写是否正确，可以到MDN上去查找，目前最简便的方法就是去你喜欢的搜索引擎搜索`MDN 语言特性`，就本文当前内容你可以点击：[addEventListener()](https://developer.mozilla.org/zh-CN/docs/Web/API/EventTarget/addEventListener)

因此这里错误显然是我们把函数名写错造成的，请记住，JavaScript区分大小写，所以任何轻微的不同或大小写问题都会导致出错，将`addeventListener`改为`addEventListener`便可解决

[更多信息](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Errors/Not_a_function)

## 语法错误：第二轮

保存页面并刷新，可以看到出错信息不见了

现在，如果尝试输入一个数字并按确定按钮，你会看到...另一个错误

此次出错信息为`TypeError：lowOrHi is null`(类型错误：lowOrHi为null)，在第78行

```
注：Null是一个特殊值，意思是“什么也没有”，或者“没有值”，这表示lowOrHi已声明并初始化，但没有任何有意义的值，可以说它没有类型没有值
注：这条错误没有在页面加载时立即发生，是因为它发生在函数内部(checkGuess() { ... }块中)，函数内部的代码运行于一个外部代码相互独立的域内，后面函数的文章中将更详细地讲解，此时此刻，只有当代码运行至86行并调用checkGuess()函数时，代码才会抛出出错信息
```

请观察第 78 行代码

```
lowOrHi.textContent = '你猜高了！';
```

该行试图将`lowOrHi`变量中的`textContent`属性设置为一个字符串，但是失败了，这是因为`lowOrHi`并不包含预期的内容，为了一探究竟，你可以在代码中查找一下该变量的的其他实例，`lowOrHi`最早出现于第48行

```
const lowOrHi = document.querySelector('lowOrHi');
```

此处，我们试图让该变量包含一个指向文档HTML中特定元素的引用，我们来检查一下在该行代码执行后变量的值是否为`null`，在第49行添加以下代码

```
console.log(lowOrHi);
```

```
注：console.log()是一个非常实用的调试功能，它可以把值打印到控制台，因此我们将其置于代码第48行时，它会将lowOrHi的值打印至控制台
```

[console.log()](https://developer.mozilla.org/zh-CN/docs/Web/API/Console/log)

![image](https://mdn.mozillademos.org/files/16275/%E5%B1%8F%E5%B9%95%E5%BF%AB%E7%85%A7_2018-10-18_16.43.40.png)

显然，此处`lowOrHi`的值为`null`，所以第48行肯定有问题

我们来思考问题有哪些可能，第48行使用[document.querySelector()](https://developer.mozilla.org/zh-CN/docs/Web/API/Document/querySelector)方法和一个CSS选择器来取得一个元素的引用

进一步查看我们的文件，我们可以找到有问题的段落

```
<p class="lowOrHi"></p>
```

这里我们需要一个类选择器，它应以一个点开头(.)，但被传递到第48行的`querySelector()`方法中的选择器没有点，这可能是问题所在，尝试将第48行中的`lowOrHi`改成`.lowOrHi`

再次保存并刷新，此时`console.log()`语句应该返回我们想要的`<p>`元素，终于把错误搞定了，此时你可以把`console.log()`一行删除，或保留它以便随后参考，选择权在你

[更多信息](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Errors/Unexpected_type)

## 语法错误：第三轮

现在，如果你再次试玩，你离成功更进了一步，游戏过程按部就班，直到猜测正确或机会用完，游戏结束

此时如果点击“开始新游戏”，游戏将再次出错，抛出与开始时同样的错误——`TypeError：resetButton.addeventListener is not a function`，这次它来自第94行

查看第94行，很容易看到我们犯了同样的错误，我们只需要再次将`addeventListener`改为`addEventListener`，现在就改吧

## 逻辑错误

此时，游戏应该可以顺利进行了，但经过几次试玩后你一定会注意到要猜的随机数不是0就是1，这可不是我们期望的

游戏的逻辑肯定是哪里出现了问题，因为游戏并没有返回错误，只是不能正确运行

寻找`randomNumber`变量和首次设定随机数的代码，保存着游戏开始时玩家要猜的随机数的实例大约在44行

```
let randomNumber = Math.floor(Math.random()) + 1;
```

重新开始游戏产生随机数的设定语句大约在113行

```
randomNumber = Math.floor(Math.random()) + 1;
```

为了检查问题是否来自这两行，我们要再次转到我们的朋友-控制台：在两行代码之后各插入下面的代码

```
console.log(randomNumber);
```

保存并刷新，然后试玩，你会看到在控制台显示的随机数总是等于1

## 修正逻辑错误

为了解决这个问题，让我们来思考这行代码如何工作，首先，我们调用[Math.random()](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/Math/random)它生成一个在0和1之间的十进制随机数，例如0.5675493843

```
Math.random()
```

接下来，我们把调用`Math.random()`的结果作为参数传递给[Math.floor()](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/Math/floor)，它会舍弃小数部分返回与之最接近的整数，然后我们给这个结果加上1

```
Math.floor(Math.random()) + 1
```

由于将一个0和1之间的随机小数的小数部分舍弃，返回的整数一定为0，因此在此基础上加1之后返回值一定为1，要在舍弃小数部分之前将它乘以100，便可得到0到99之间的随机数

```
Math.floor(Math.random() * 100);
```

然后再加1，便可得到一个100以内随机的自然数

```
Math.floor(Math.random() * 100) + 1;
```

将上述两行内容替换为此，然后保存刷新，游戏终于如期运行了

## 其他常见错误

代码中还会遇到其他常见错误，本节将指出其中的大部分

### 001.SyntaxError: missing ; before statement(语法错误：语句缺少分号)

这个错误通常意味着你漏写了一行代码最后的分号，但是此类错误有时候会更加隐蔽，例如如果我们把`checkGuess()`函数中的这一行

```
let userGuess = Number(guessField.value);
```

改为

```
let userGuess === Number(guessField.value);
```

将抛出一个错误，因为系统认为你在做其他事情，请不要把赋值运算符(`=`，为一个变量赋值)和严格等于运算符(`===`，比较两个值是否相等，返回 `true`/`false`)弄混淆

[更多信息](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Statements)

### 002.不过输入什么程序总说"你猜对了"

这是混淆赋值和严格等于运算符的又一症状，例如我们把`checkGuess()`里的

```
if (userGuess === randomNumber) {
```

改为

```
if (userGuess = randomNumber) {
```

因为条件永远返回true，使得程序报告你猜对了

### 003.SyntaxError: missing ) after argument list(语法错误：参数表末尾缺少括号)

这个很简单，通常意味着函数/方法调用后的结束括号忘写了

[更多信息](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Errors/Missing_parenthesis_after_argument_list)

### 004.SyntaxError: missing : after property id(语法错误：属性ID后缺少冒号)

JavaScript对象的形式有错时通常会导致此类错误，如果把

```
function checkGuess() {
```

写成了

```
function checkGuess( {
```

浏览器会认为我们试图将函数的内容当作参数传回函数。写圆括号时要小心

### 005.SystaxError: missing } after function body(语法错误：函数体末尾缺少花括号)

这个简单，通常意味着函数或条件结构中丢失了一个花括号，如果我们将`checkGuess()`函数末尾的花括号删除，就会得到这个错误

### 006.SyntaxError: expected expression, got 'string'(语法错误：得到一个 'string' 而非表达式)<br>007.SyntaxError: unterminated string literal(语法错误：字符串字面量未正常结束)

这个错误通常意味着字符串两端的引号漏写了一个，如果你漏写了字符串开始的引号，将得到第一条出错信息，这里的'string'将被替换为浏览器发现的意外字符，如果漏写了末尾的引号将得到第二条

对于所有的这些错误，想想我们在实例中是如何逐步解决的，错误出现时，转到错误所在的行观察是否能发现问题所在，记住，错误不一定在那一行，错误的原因也可能和我们在上面所说的不同

[更多信息](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Errors/Unexpected_token)
[更多信息](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Errors/Unterminated_string_literal)

# 小结

我们有了能够在简单的JavaScript程序中除错的基础知识，解决代码中的错误并不总是那么简单，但至少本节内容可以为刚刚踏上学习之路的你节省出几个小时来补觉，同时让问题更快速得到解决
