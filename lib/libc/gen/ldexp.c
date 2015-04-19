#include <math.h>

double ldexp(double fr, int exp)
{
    int neg;
    int i;

    neg = 0;
    if (fr < 0) {
        fr = -fr;
        neg = 1;
    }
    fr = frexp(fr, &i);
    while (fr < 0.5) {
        fr = 2 * fr;
        i = i - 1;
    }
    exp = exp + i;
    if (exp > 127) {
        const double huge = 1.701411834604692293e38;
        if (neg)
            return -huge;
        else
            return huge;
        }
    if (exp < -127)
        return 0;
    while (exp > 30) {
        fr = fr * (1L << 30);
        exp = exp - 30;
    }
    while (exp < -30) {
        fr = fr / (1L << 30);
        exp = exp + 30;
    }
    if (exp > 0)
        fr = fr * (1L << exp);
    if (exp < 0)
        fr = fr / (1L << -exp);
    if (neg)
            fr = -fr;
    return fr;
}
