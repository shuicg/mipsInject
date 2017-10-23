#include "inject.h"


void show_regs(struct mips_regswithpc *regs, const char* logFlag)
{
    return;
    int i = 0;
    printf("%s show_regs:\n", logFlag);
    /*
    for(;i < 32;++i)
    {
        printf("regs[%d]=%08x\n", i, regs->general_regs.regs[i]);
    }
    */
    printf("MIPS_v0=0x%08x\t", (int)regs->MIPS_v0);
    printf("MIPS_v1=0x%08x\n", (int)regs->MIPS_v1);
    printf("MIPS_a0=0x%08x\t", (int)regs->MIPS_a0);
    printf("MIPS_a1=0x%08x\t", (int)regs->MIPS_a1);
    printf("MIPS_a2=0x%08x\t", (int)regs->MIPS_a2);
    printf("MIPS_a3=0x%08x\n", (int)regs->MIPS_a3);
    printf("MIPS_sp=0x%08x\t", (int)regs->MIPS_sp);
    printf("MIPS_ra=0x%08x\t", (int)regs->MIPS_ra);
    printf("MIPS_pc=0x%08x\n\n", (int)regs->MIPS_pc);
}

int ptrace_getregs(pid_t pid, struct mips_regswithpc *regs)
{
    if(ptrace(PTRACE_GETREGS, pid, NULL, regs->general_regs.regs) < 0)
    {
        perror("ptrace_getregs: Can not get register values");
        return -1;
    }

    regs->MIPS_pc = ptrace(PT_READ_U, pid, (void*)(unsigned long int)PC, 0);
    if(regs->MIPS_pc < 0)
    {
        perror("ptrace_getregs: Can not get PC values");
        return -1;
    }

    show_regs(regs, __func__);
    return 0;
}

int ptrace_setregs(pid_t pid, struct mips_regswithpc *regs)
{
    show_regs(regs, __func__);
    if(ptrace(PTRACE_SETREGS, pid, NULL, regs->general_regs.regs) < 0)
    {
        perror("ptrace_setregs: Can not set register values");
        return -1;
    }

    if(ptrace(PT_WRITE_U, pid, (void*)(unsigned long int)PC, regs->MIPS_pc) < 0)
    {
        perror("ptrace_setregs: Can not set PC values");
        return -1;
    }

    return 0;
}

int ptrace_continue(pid_t pid)
{
    printf("--start ptrace_continue\n");
    if(ptrace(PTRACE_CONT, pid, NULL, 0) < 0)
    {
        perror("ptrace_cont");
        return -1;
    }

    return 0;
}

int ptrace_attach(pid_t pid)
{
    if(ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0)
    {
        perror("ptrace_attach");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status , WUNTRACED);

    return 0;
}

int ptrace_detach(pid_t pid)
{
    if(ptrace(PTRACE_DETACH, pid, NULL, 0) < 0)
    {
        perror("ptrace_detach");
        return -1;
    }

    return 0;
}


int ptrace_readdata(pid_t pid, uint8_t *src, uint8_t *buf, size_t size)
{
//    uint32_t i, j, remain;
//    uint8_t *laddr;
    uint32_t i = 0;
    uint32_t j = size / 4;
    uint32_t remain = size % 4;

    uint8_t * laddr = buf;

    union Uunion d;
    for(; i < j; ++i)
    {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, 4);
        src += 4;
        laddr += 4;
    }

    if(remain > 0)
    {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, src, 0);
        memcpy(laddr, d.chars, remain);
    }

    return 0;
}

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)
{
    //uint32_t i, j, remain;
    //uint8_t *laddr;

    union Uunion d;
    uint32_t i;
    uint32_t j = size / 4;
    uint32_t remain = size % 4;

    uint8_t *laddr = data;

    for(i = 0; i < j; ++i)
    {
        memcpy(d.chars, laddr, 4);
        ptrace(PTRACE_POKETEXT, pid, dest, (void*)d.val);

        dest += 4;
        laddr += 4;
    }

    if(remain > 0)
    {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for(i = 0; i < remain; i ++)
        {
            d.chars[i] = *laddr ++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, (void*)d.val);
    }

    return 0;
}

int ptrace_call(pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct mips_regswithpc* regs)
{
    long parm[9];
    memset(parm, 0, sizeof(parm));

    uint32_t i;

    for(i = 0; i < num_params && i < 4; ++i)
    {
        //regs[4-7] args
        regs->general_regs.regs[i+4] = params[i];
    }

    //
    // push remained params onto stack
    //
    if(i < num_params)
    {
        regs->MIPS_v0 = num_params;

        regs->MIPS_sp -= num_params * sizeof(long);
        long sp = regs->MIPS_sp;
        ptrace_writedata(pid, (uint8_t *)sp, (uint8_t *)&parm[0], 4 * sizeof(long));
        ptrace_writedata(pid, (uint8_t *)(sp+16), (uint8_t *)&params[4], (num_params-4) * sizeof(long));

        //
        ptrace_readdata(pid, (uint8_t *)sp, (uint8_t *)&parm[4], (num_params-4) * sizeof(long));
        for(i = 0; i < num_params; ++i)
        {
            printf("parm[%d]=%ld\n", i, parm[i]);
        }
    }

    regs->MIPS_pc = addr;
    regs->MIPS_t9 = addr;

    regs->MIPS_ra = 0;
    if(ptrace_setregs(pid, (struct mips_regswithpc *)regs) == -1 || ptrace_continue(pid) == -1)
    {
        DEBUG_PRINT("error\n");
        return -1;
    }

    i = 0;
    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    printf("stat = %08x\n", stat, stat);
    while(stat != 0xb7f)
    {
        i++;
        if(i == 10) break;
        printf("stat = %08x\n", stat, stat);

        if(ptrace_continue(pid) == -1)
        {
            DEBUG_PRINT("error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }

    return 0;
}

void *get_module_base(pid_t pid, const char *module_name)
{
    unsigned long addr = 0;

//    char filename[32];
//    char line[1024];

    char filename[32] = "";
    if(pid < 0)
    {
        /* self process */
        snprintf(filename, sizeof(filename), "/proc/self/maps", pid);
    }
    else
    {
        snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
    }

    FILE *fp = fopen(filename, "r");

    if(fp != NULL)
    {
        char line[1024] = "";
        while(fgets(line, sizeof(line), fp))
        {
            if(strstr(line, module_name))
            {
                char *pch = strtok(line, "-");
                addr = strtoul(pch, NULL, 16);

                if(addr == 0x8000)
                {
                    addr = 0;
                }
                break;
            }
        }

        fclose(fp) ;
    }

    return (void *)addr;
}

void *get_remote_addr(pid_t target_pid, const char *module_name, void *local_addr)
{
    void *local_handle = get_module_base(-1, module_name);
    void *remote_handle = get_module_base(target_pid, module_name);

    DEBUG_PRINT("[+] name:%s, local_addr:[%x], get_remote_addr: local[%x], remote[%x]\n", module_name, local_addr, local_handle, remote_handle);

    void *ret_addr = (void *)((uint32_t)local_addr + (uint32_t)remote_handle - (uint32_t)local_handle);
    printf("offset=%08x\n", (uint32_t)local_addr - (uint32_t)local_handle);

    //void *ret_addr = (void *)(0x0004F640 + (uint32_t)remote_handle);
    return ret_addr;
}

int find_pid_of(const char *process_name)
{
    pid_t pid = -1;

    if(process_name == NULL)
    {
        return -1;
    }

    DIR *dir = opendir("/proc");
    if(dir == NULL)
    {
        return -1;
    }

    struct dirent *entry = NULL;
    while((entry = readdir(dir)) != NULL)
    {
        int id = atoi(entry->d_name);
        if(id != 0)
        {
                char filename[32] = "";
            sprintf(filename, "/proc/%d/cmdline", id);
            FILE *fp = fopen(filename, "r");
            if(fp)
            {
                char cmdline[256] = "";
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);

                if(strcmp(process_name, cmdline) == 0)
                {
                    // process found
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}

long ptrace_retval(struct mips_regswithpc * regs)
{
    return regs->MIPS_v0;
}

long ptrace_ip(struct mips_regswithpc * regs)
{
    return regs->MIPS_pc;
}

int ptrace_call_wrapper(pid_t target_pid, const char *func_name, void *func_addr, long *parameters, int param_num, struct mips_regswithpc *regs)
{
    DEBUG_PRINT("[+] Calling %s in target process.\n", func_name);
    if(ptrace_call(target_pid, (uint32_t)func_addr, parameters, param_num, regs) == -1)
    {
        return -1;
    }

    if(ptrace_getregs(target_pid, regs) == -1)
    {
        return -1;
    }

    DEBUG_PRINT("[+] Target process returned from %s, return value=%x, pc=%x \n",
            func_name, ptrace_retval(regs), ptrace_ip(regs));
    return 0;
}

int inject_remote_process(pid_t target_pid, const char *library_path, const char *function_name, const char *param, size_t param_size)
{
    DEBUG_PRINT("[+] Injecting process: %d\n", target_pid);

    if(ptrace_attach(target_pid) == -1)
    {
        DEBUG_PRINT("[+] ptrace_attach fail: %d\n", target_pid);
        return -1;
    }

    struct mips_regswithpc regs;
    if(ptrace_getregs(target_pid, &regs) == -1)
    {
        DEBUG_PRINT("[+] ptrace_getregs fail: %d\n", target_pid);
        return -2;
    }

    // save original registers
    struct mips_regswithpc original_regs;
    memcpy(&original_regs, &regs, sizeof(regs));

    void *mmap_addr = get_remote_addr(target_pid, libc_path, (void *)mmap);
    DEBUG_PRINT("[+] Remote mmap address: %x\n", mmap_addr);

    // call mmap
    long parameters[10] = {0};
    parameters[0] = 0;  // addr
    parameters[1] = 0x4000; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset

    if(ptrace_call_wrapper(target_pid, "mmap", mmap_addr, parameters, 6, &regs) == -1)
    {
          DEBUG_PRINT("[+] ptrace_call_wrapper fail: %d\n", target_pid);
          return -3;
    }

    uint8_t *map_base = (uint8_t*)ptrace_retval(&regs);

    void *dlopen_addr = get_remote_addr(target_pid, linker_path, (void *)dlopen);
    void *dlsym_addr = get_remote_addr(target_pid, linker_path, (void *)dlsym);
    void *dlclose_addr = get_remote_addr(target_pid, linker_path, (void *)dlclose);
    void *dlerror_addr = get_remote_addr(target_pid, linker_path, (void *)dlerror);

    DEBUG_PRINT("[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x, dlerror: %x\n",
            dlopen_addr, dlsym_addr, dlclose_addr, dlerror_addr);

    DEBUG_PRINT("library path = %s\n", library_path);
    ptrace_writedata(target_pid, map_base, (uint8_t*)library_path, strlen(library_path) + 1);

    parameters[0] = (long int)map_base;
    parameters[1] = RTLD_NOW | RTLD_GLOBAL;

    if(ptrace_call_wrapper(target_pid, "dlopen", dlopen_addr, parameters, 2, &regs) == -1)
    {
        return -4;
    }

    void *sohandle = (void*)ptrace_retval(&regs);
    if(NULL == sohandle)
    {
        if(ptrace_call_wrapper(target_pid, "dlerror", dlerror_addr, parameters, 0, &regs) == -1)
        {
                return -5;
        }

        char *errstr = (char*)ptrace_retval(&regs);
        uint8_t buf[1024] = {0};
        ptrace_readdata(target_pid, (uint8_t*)errstr, (uint8_t*)buf, 256);
        DEBUG_PRINT("[+] dlopen return error: %s\n", buf);
    }

    const int FUNCTION_NAME_ADDR_OFFSET = 0x100;
    ptrace_writedata(target_pid, map_base + FUNCTION_NAME_ADDR_OFFSET, (uint8_t*)function_name, strlen(function_name) + 1);
    parameters[0] = (long)sohandle;
    parameters[1] = (long)map_base + FUNCTION_NAME_ADDR_OFFSET;

    if(ptrace_call_wrapper(target_pid, "dlsym", dlsym_addr, parameters, 2, &regs) == -1)
    {
        return -6;
    }

    void *hook_entry_addr = (void*)ptrace_retval(&regs);
    DEBUG_PRINT("hook_entry_addr = %p\n", hook_entry_addr);
    if(hook_entry_addr == NULL)
    {
        return -66;
    }

    const int FUNCTION_PARAM_ADDR_OFFSET = 0x200;
    ptrace_writedata(target_pid, map_base + FUNCTION_PARAM_ADDR_OFFSET, (uint8_t*)param, strlen(param) + 1);
    parameters[0] = (long)map_base + FUNCTION_PARAM_ADDR_OFFSET;
    //if(ptrace_call_wrapper(target_pid, function_name, hook_entry_addr, parameters, 1, &regs) == -1)
    if(ptrace_call_wrapper(target_pid, function_name, hook_entry_addr, parameters, 1, &regs) == -1)
    {
        return -7;
    }

    DEBUG_PRINT("Press enter to detach\n");

    // restore
    ptrace_setregs(target_pid, &original_regs);
    ptrace_detach(target_pid);

    return 0;
}

int main(int argc, char *argv[])
{
        if(argc != 3)
        {
                printf("usage: exe hookprocessid so\n");
                return -1;
        }

        pid_t target_pid = find_pid_of(argv[1]);

        if (-1 == target_pid)
        {
                DEBUG_PRINT("Can't find the process\n");
                return -1;
        }

        //pid_t target_pid = atoi(argv[1]);
        DEBUG_PRINT("find the pid = %d\n", target_pid);
        //inject_remote_process(target_pid, argv[2], "_Z6dohookv", "", 0);
        //inject_remote_process(target_pid, argv[2], "dohook", "", 0);
        inject_remote_process(target_pid, argv[2], "dohook", argv[1], 0);
        return 0;
}
