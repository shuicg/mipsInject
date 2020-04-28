# mipsInject
    mips系统注入代码，仿照arm注入实现，由于能力有限，只能注入进待注入进程中已导入libdl**.so动态库的进程。  
    为什么是必须进程中已经导入libdl**.so的才能注入呢，因为注入过程中需要用到dlopen，dlsym等一系列函数，  
    写好的函数是在这个so里面的，如果没有导入这个so，需要自己实现一下dlopen，dlsym等函数，  
    在看雪中得到了malokch大神的指点，但是还是没弄出来，需要用到ld-uClibc.so的dl_load_shared_library  
    来实现加载so。 有弄出来还望分享一下。  
    mips注入需要注意的是  
    1. pc值的修改  
        设置pc值，ptrace(PT_WRITE_U, pid, (void*)(unsigned long int)PC, regs->MIPS_pc)  
        读取pc值，regs->MIPS_pc = ptrace(PT_READ_U, pid, (void*)(unsigned long int)PC, 0);  
    2. 设置函数调用参数  
        参数超过4个之后，v0要写入参数个数，并且超过4个的参数写入sp，sp的前4个参数还得保持是0，第五个参数开始写入真正的第五个参数。  
