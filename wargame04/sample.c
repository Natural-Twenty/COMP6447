#include <stdint.h>

#define XXX __asm__("nop");
int main(int arg1, int arg2) {
    XXX;
    int add = arg1 + arg2;
    XXX;
    float mul = arg1 * arg2;
    XXX;
    int div = arg1/arg2;
    XXX;
    int sub = arg1 - arg2;
    XXX;
    int comp = div * mul;
    XXX;
    int comp2 = add * mul/div;
    XXX;
    int mod = arg1 % arg2;
    XXX;
    int modcomp = arg1 + (comp % div);
    XXX;
    return mul;
    XXX;
}