/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */
double
fabs(double arg)
{
    return arg < 0 ? -arg : arg;
}
