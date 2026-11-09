#ifndef DNT_CPU_H
#define DNT_CPU_H
#include <stdint.h>

typedef struct {
    uint64_t x[31];      /* x0..x30; x31 (sp/zr) handled contextually */
    uint64_t sp;
    uint64_t pc;
    uint32_t nzcv;
    int      halt;           /* 0 = running, else DNT_HALT_* */
    int      exit_code;
    int      syscall_error;  /* set by trap() for the SVC handler */
    char     halt_detail[160];
    uint64_t image_base;
    uint64_t image_size;
    void *bind;              /* dnt_bind*, NULL for static images */
} dnt_cpu;

enum {
    DNT_HALT_NONE = 0,
    DNT_HALT_EXIT,
    DNT_HALT_FAULT,
    DNT_HALT_ILLEGAL,
    DNT_HALT_STEP_LIMIT,
    DNT_HALT_SYSCALL,
};

void dnt_cpu_reset(dnt_cpu *c, uint64_t entry, uint64_t sp,
                   uint64_t image_base, uint64_t image_size);
int  dnt_cpu_run(dnt_cpu *c, uint64_t max_instructions);
uint64_t dnt_cpu_sp(dnt_cpu *c);
void dnt_cpu_set_binding(dnt_cpu *c, void *b);

#endif
