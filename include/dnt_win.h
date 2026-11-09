#ifndef DNT_WIN_H
#define DNT_WIN_H
#ifdef _WIN32
#include <stdio.h>
#include "dnt_syscall.h"
const dnt_host_ops *dnt_win_host_ops(void);
void dnt_win_set_verbose(FILE *f);
int  dnt_win_is_exiting(void);
unsigned long dnt_win_exit_code(void);
#endif
#endif
