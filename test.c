//#include <iostream>
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <math.h>

//using namespace std;

int add(int a, int b)
{
    int sum = a + b;
    return sum;
}

int main()
{
    //cout << "sizeof(long)=" << sizeof(long) << endl;

    printf("dlopen addr=%08x\n", dlopen);
    printf("dlsym addr=%08x\n", dlsym);
    printf("dlclose addr=%08x\n", dlclose);
    printf("dlerror addr=%08x\n", dlerror);

    int sum = 0;
    while(1)
    {
        sum += add(1, 2);
        //cout << "sum:" << sum << endl;
        printf("sum=%d\n", abs(sum));
        sleep(1);
        //if(sum > 200) break;
    }
    //sleep(-1);
    return 0;
}

