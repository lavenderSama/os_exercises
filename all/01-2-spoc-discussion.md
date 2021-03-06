# 操作系统概述思考题

## 个人思考题

---

分析你所认识的操作系统（Windows、Linux、FreeBSD、Android、iOS）所具有的独特和共性的功能？
>  操作系统均具有并发性、资源共享、逻辑抽象和异步处理请求的特性。同时，操作系统提供进程、内存、文件、设备和通信的管理功能。
> > iOS是基于手机的操作系统，其在并发处理上进行了限制，提高了与用户交互的能力，并大幅改善了图形界面。
> > Linux系统将用户的自由度发挥至最大，其系统功能可有用户本身进行最大程度的调节。

请总结你认为操作系统应该具有的特征有什么？并对其特征进行简要阐述。
> - 并发性：允许多个程序同时执行
> - 共享：并发执行的线程间可以共享资源
> - 虚拟：将物理实体分为若干个逻辑上的对应物，例如虚存、虚处理器等
> - 异步性：可以自动处理与外设相关的请求，保证外设工作的连续性

请给出你觉得的更准确的操作系统的定义？
>   一套运行与计算机上，提供进程管理、内存管理、文件管理、通讯管理和设备管理功能的，可与用户进行交互的，确保计算机能在执行用户请求的同时，协调、高效和可靠工作的系统。

你希望从操作系统课学到什么知识？
>   现有操作系统（如windows、ubuntu、mac OS）的运行原理，以及如何实现一个属于自己的操作系统。

---

## 小组讨论题

---

目前的台式PC机标准配置和价格？
> - CPU	Intel 酷睿i5 4430（盒） 1140
> - 主板	微星H87M-G43	599
> - 内存	金士顿4GB DDR3 1600 240
> - 硬盘	西部数据1TB 7200转 32MB SATA2（WD10EALS）340
> - 固态硬盘	金士顿V300系列 120GB（SV300S37A/120G）399
> - 显卡	微星GTX 960 2GD5T OC 1499
> - 机箱	至睿极光AR51精英版 278
> - 电源	海韵S12II-430铜牌 299
> - 合计金额：5034 元

你理解的命令行接口和GUI接口具有哪些共性和不同的特征？
> - 共性：不论何种接口，其实现的基本功能是相同的，都是用于用户
> - 命令行接口提供比GUI接口更加丰富、直接的功能，适合大批量的相同操作，适用于高级用户使用
> - GUI接口对用户更加友好，适用于普通用户

为什么现在的操作系统基本上用C语言来实现？
> - 历史上开发的操作系统程序基本是使用C语言写的，因此现在为沿用之前的代码也采用了C语言
> - C语言更加贴近汇编语言，能更好的翻译为机器语言，用于实现底层逻辑不算复杂，且效率高
> - C语言编写操作系统相关工具链成熟，很大程度避免从头二次开发

为什么没有人用python，java来实现操作系统？
> - Python需要使用解释器，解释器的运行本身需要操作系统
> - Java需要JVM，JVM也是运行在操作系统上的
> - 即使可以把它们编译成汇编，代价高，效率低下
> - 即使可以把它们编译成高效的汇编，语言的模式（例如动态性）使得操作系统的可靠性降低，同时语言缺乏操作底层的能力，难以手动管理内存（两者都有垃圾回收）

请评价用C++来实现操作系统的利弊？
> - 使用C++实现操作系统使得开发者可以采用特定的设计模式，从而减少扩展、维护操作系统代码的成本
> - 但随着设计模式的采用，其语言的执行效率会下降，这将导致操作系统运行效率的下降

---

## 开放思考题

---

请评价微内核、单体内核、外核（exo-kernel）架构的操作系统的利弊？
- [x]  

>  

请评价用LISP,OCcaml, GO, D，RUST等实现操作系统的利弊？
- [x]  

>  

进程切换的可能实现思路？
> - 设定一个计时器，每当计时器归零时，激活内核
> - 内核保存当前各寄存器的信息和已缓存的内存地址，并将cache同步至实际内存中
> - 内核根据之前保存的将要执行的新进程的信息恢复寄存器和cache
> - 内核将执行语句的地址指向新进程的代码，并置计时器与一个固定的时间

计算机与终端间通过串口通信的可能实现思路？
> - 一个进程提出访问串口的请求
> - 处理机检测要访问的串口是否可用，若可用，则将该串口的使用权交给进程，否则强制进程等待，执行下一个进程
> - 进程使用完串口后通知处理器，处理器至对应串口状态为空闲

为什么微软的Windows没有在手机终端领域取得领先地位？
- [x]  

>  

你认为未来（10年内）的操作系统应该具有什么样的特征和功能？
- [x]  

>  

---
