/* ARM64 execution core.
 *
 * This is an interpreter for the instruction subset a linked Darwin binary
 * actually executes on entry: register moves/immediates, PC-relative address
 * formation (ADRP/ADD), loads/stores, arithmetic, compares and branches. It is
 * not a full ARM64 emulator -- reaching an instruction it does not implement
 * halts with a named error instead of guessing, so gaps stay visible.
 *
 * The trap: SVC #0x80 on Darwin encodes the syscall number in x16 and returns
 * in x0 with the carry flag set on error (C on failure, x0 = errno). That
 * convention is implemented here, once, in trap().
 */
#include "dnt_cpu.h"
#include "dnt_syscall.h"
#include "dnt_bind.h"
#include "dnt_abi.h"
#include "dnt_errno.h"
#include "generated/syscalls.h"

#include <stdio.h>

#include <string.h>

/* ---- flag bits ---- */
#define F_N  (1u << 31)
#define F_Z  (1u << 30)
#define F_C  (1u << 29)
#define F_V  (1u << 28)

static void set_nz(dnt_cpu *c, uint64_t v, int width)
{
    c->nzcv &= ~(F_N | F_Z);
    if (width == 64) {
        if (v >> 63) c->nzcv |= F_N;
        if (v == 0)  c->nzcv |= F_Z;
    } else {
        uint32_t v32 = (uint32_t)v;
        if (v32 >> 31) c->nzcv |= F_N;
        if (v32 == 0)  c->nzcv |= F_Z;
    }
}

/* Extended register read: reg 31 means SP in some contexts, XZR in others. */
static uint64_t reg(dnt_cpu *c, int n) { return c->x[n & 31]; }
static void setreg(dnt_cpu *c, int n, uint64_t v) { c->x[n & 31] = v; }

uint64_t dnt_cpu_sp(dnt_cpu *c) { return c->sp; }

/* ---- helpers ---- */
static uint64_t rd64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static uint32_t rd32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }

/* Sign-extend a bitfield. */
static int64_t sext(uint64_t v, int bits)
{
    if (bits >= 64)
        return (int64_t)v;
    uint64_t m = 1ull << (bits - 1);
    v &= (bits == 64) ? ~0ull : ((1ull << bits) - 1);
    return (int64_t)((v ^ m) - m);
}

static int cond_holds(dnt_cpu *c, unsigned cond)
{
    int n = (c->nzcv & F_N) != 0;
    int z = (c->nzcv & F_Z) != 0;
    int cy = (c->nzcv & F_C) != 0;
    int v = (c->nzcv & F_V) != 0;
    switch (cond >> 1) {
    case 0: return z;                 /* EQ */
    case 1: return !z;                /* NE */
    case 2: return cy;                /* CS */
    case 3: return !cy;               /* CC */
    case 4: return n;                 /* MI */
    case 5: return !n;                /* PL */
    case 6: return v;                 /* VS */
    case 7: return !v;                /* VC */
    case 8: return cy && !z;          /* HI */
    case 9: return !cy || z;          /* LS */
    case 10: return n == v;           /* GE */
    case 11: return n != v;           /* LT */
    case 12: return !z && n == v;     /* GT */
    case 13: return z || n != v;      /* LE */
    default: return 1;                /* AL */
    }
}

/* ---- trap ---- */
static void trap(dnt_cpu *c)
{
    uint32_t nr = (uint32_t)(c->x[16] & 0xFFFFFFFF);
    /* Capture the argument before the call: exit's code arrives in x0 and the
     * dispatcher overwrites x0 with its (success) return value. */
    uint64_t exit_arg = c->x[0];
    int failed = 0;
    /* exit must stop the machine BEFORE the dispatcher is called: the host
     * exit hook terminates the process on Win32, so letting it run first means
     * the CPU never observes the halt, the stack is never freed, and the CLI
     * cannot return the guest's code. Handle it entirely here. */
    if (nr == DSYS_EXIT) {
        c->halt = DNT_HALT_EXIT;
        c->exit_code = (int)(exit_arg & 0xFF);
        c->x[0] = 0;
        return;
    }

    uint64_t r = dnt_syscall_ex(nr, c->x[0], c->x[1], c->x[2],
                                c->x[3], c->x[4], c->x[5], &failed);
    /* Darwin's convention: x0 = result, carry flag = failure (x0 then holds
     * the errno). The failure bit comes from the dispatcher, never inferred
     * from the value. */
    c->x[0] = r;
    if (failed)
        c->nzcv |= F_C;
    else
        c->nzcv &= ~F_C;
    c->syscall_error = failed;

}

/* ---- main loop ---- */
int dnt_cpu_run(dnt_cpu *c, uint64_t max_instructions)
{
    for (uint64_t steps = 0; steps < max_instructions; steps++) {
        uint64_t pc = c->pc;

        /* A jump to a trampoline address is a call to a bound libSystem
         * function. It is dispatched here rather than executed, because the
         * bytes at that address live in our own allocation, not the image. */
        if (c->bind) {
            int idx = dnt_bind_trampoline_index((dnt_bind *)c->bind, pc);
            if (idx >= 0) {
                uint32_t nr = dnt_bind_syscall((dnt_bind *)c->bind, idx);
                int failed = 0;
                uint64_t r = dnt_syscall_ex(nr, c->x[0], c->x[1], c->x[2],
                                            c->x[3], c->x[4], c->x[5], &failed);
                c->x[0] = r;
                if (failed) c->nzcv |= F_C; else c->nzcv &= ~F_C;
                if (nr == DSYS_EXIT) {
                    c->halt = DNT_HALT_EXIT;
                    c->exit_code = (int)(c->x[0] & 0xFF);
                    return 0;
                }
                /* return to caller: the stub used bl, so x30 holds it */
                c->pc = c->x[30];
                continue;
            }
        }

        /* The binder is only reached when a slot still points at it, i.e. an
         * import we could not resolve. Say which one instead of faulting. */
        if (c->bind && pc == ((dnt_bind *)c->bind)->binder_addr) {
            c->halt = DNT_HALT_SYSCALL;
            snprintf(c->halt_detail, sizeof(c->halt_detail),
                     "unresolved import reached dyld_stub_binder");
            return -1;
        }

        if (pc < c->image_base || pc + 4 > c->image_base + c->image_size) {
            c->halt = DNT_HALT_FAULT;
            snprintf(c->halt_detail, sizeof(c->halt_detail),
                     "pc 0x%llx outside image [0x%llx,0x%llx)",
                     (unsigned long long)pc,
                     (unsigned long long)c->image_base,
                     (unsigned long long)(c->image_base + c->image_size));
            return -1;
        }
        uint32_t insn = rd32((const uint8_t *)pc);
        c->pc = pc + 4;

        /* ---- SVC ---- */
        if ((insn & 0xFFE0001F) == 0xD4000001) {
            trap(c);
            if (c->halt)
                return 0;
            continue;
        }

        /* ---- B / BL ---- */
        if ((insn & 0x7C000000) == 0x14000000) {
            int64_t off = sext((int64_t)(insn & 0x03FFFFFF), 26) << 2;
            if (insn & 0x80000000)
                c->x[30] = c->pc;          /* BL */
            c->pc = pc + off;
            continue;
        }

        /* ---- B.cond ---- */
        if ((insn & 0xFF000000) == 0x54000000) {
            if (cond_holds(c, insn & 0xF)) {
                int64_t off = sext((insn >> 5) & 0x7FFFF, 19) << 2;
                c->pc = pc + off;
            }
            continue;
        }

        /* ---- CBZ / CBNZ ---- */
        if ((insn & 0x7E000000) == 0x34000000) {
            int sf = (insn >> 31) & 1;
            int op = (insn >> 24) & 1;
            int rt = insn & 31;
            uint64_t v = reg(c, rt);
            if (!sf) v &= 0xFFFFFFFF;
            int iszero = (v == 0);
            if (iszero != op) {   /* CBZ: jump if zero; CBNZ: jump if nonzero */
                int64_t off = sext((insn >> 5) & 0x7FFFF, 19) << 2;
                c->pc = pc + off;
            }
            continue;
        }

        /* ---- TBZ / TBNZ ---- */
        if ((insn & 0x7E000000) == 0x36000000) {
            int rt = insn & 31;
            int bit = ((insn >> 31) & 1) * 32 + ((insn >> 19) & 31);
            int op = (insn >> 24) & 1;
            int set = (reg(c, rt) >> bit) & 1;
            if (set == op) {
                int64_t off = sext((insn >> 5) & 0x3FFF, 14) << 2;
                c->pc = pc + off;
            }
            continue;
        }

        /* ---- BR / BLR / RET ---- */
        if ((insn & 0xFFFFFC1F) == 0xD61F0000) {
            int rn = (insn >> 5) & 31;
            int opc = (insn >> 21) & 3;
            uint64_t target = reg(c, rn);
            if (opc == 1)
                c->x[30] = c->pc;          /* BLR */
            if (opc == 2) {                /* RET */
                c->halt = DNT_HALT_EXIT;
                c->exit_code = c->x[0] & 0xFF;
                return 0;
            }
            c->pc = target;
            continue;
        }

        /* ---- ADR / ADRP ---- */
        if ((insn & 0x1F000000) == 0x10000000) {
            int rd = insn & 31;
            int64_t immlo = (insn >> 29) & 3;
            int64_t immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (insn & 0x80000000) {                 /* ADRP */
                imm = sext(imm, 21);
                uint64_t base = pc & ~0xFFFull;
                setreg(c, rd, (uint64_t)((int64_t)base + (imm << 12)));
            } else {                                  /* ADR */
                setreg(c, rd, (uint64_t)((int64_t)pc + sext(imm, 21)));
            }
            continue;
        }

        /* ---- MOVZ / MOVN / MOVK (wide immediate) ---- */
        if ((insn & 0x1F800000) == 0x12800000) {
            int sf = (insn >> 31) & 1;
            int opc = (insn >> 29) & 3;
            int hw = (insn >> 21) & 3;
            uint16_t imm16 = (uint16_t)((insn >> 5) & 0xFFFF);
            int rd = insn & 31;
            uint64_t v = (uint64_t)imm16 << (hw * 16);
            if (opc == 0) {          /* MOVN */
                v = ~v;
            } else if (opc == 3) {   /* MOVK: merge into current */
                uint64_t cur = reg(c, rd);
                uint64_t mask = 0xFFFFull << (hw * 16);
                v = (cur & ~mask) | v;
            }
            if (!sf)
                v &= 0xFFFFFFFF;
            setreg(c, rd, v);
            continue;
        }

        /* ---- ADD/SUB immediate (incl. MOV alias to/from SP) ---- */
        if ((insn & 0x1F000000) == 0x11000000) {
            int sf = (insn >> 31) & 1;
            int op = (insn >> 30) & 1;      /* 0=add 1=sub */
            int s  = (insn >> 29) & 1;      /* set flags */
            int shift = (insn >> 22) & 1;
            uint64_t imm = (insn >> 10) & 0xFFF;
            int rn = (insn >> 5) & 31;
            int rd = insn & 31;
            if (shift)
                imm <<= 12;
            uint64_t a = (rn == 31) ? c->sp : reg(c, rn);
            if (!sf) { a &= 0xFFFFFFFF; }
            uint64_t b = imm;
            uint64_t res = op ? (a - b) : (a + b);
            if (!sf) res &= 0xFFFFFFFF;
            if (s) {
                set_nz(c, res, sf ? 64 : 32);
                if (op) {
                    if (a >= b) c->nzcv |= F_C;
                    int64_t sa = (int64_t)a, sb = (int64_t)b;
                    if (sf ? ((sa - sb) != (int64_t)res) : 0) c->nzcv |= F_V;
                }
            }
            if (rd == 31) {
                if (s) { /* CMP: no writeback */ }
                else c->sp = res;
            } else {
                setreg(c, rd, res);
            }
            continue;
        }

        /* ---- ORR/AND/EOR/MOV shifted register (incl. MOV Xd, Xm) ---- */
        if ((insn & 0x1F000000) == 0x0A000000) {
            int sf = (insn >> 31) & 1;
            int opc = (insn >> 29) & 3;
            int nbit = (insn >> 21) & 1;
            int rm = (insn >> 16) & 31;
            int rn = (insn >> 5) & 31;
            int rd = insn & 31;
            int shift_type = (insn >> 22) & 3;
            int amount = (insn >> 10) & 63;
            /* opc/nbit: 00,0 = AND; 01,0 = ORR; 10,0 = EOR; 01,1 = ORN */
            uint64_t a = reg(c, rn);
            uint64_t b = reg(c, rm);
            if (shift_type == 0) b <<= amount;
            else if (shift_type == 1) b >>= amount;
            else if (shift_type == 2) b = (uint64_t)((int64_t)b >> amount);
            else b = (amount ? ((b >> amount) | (b << (64 - amount))) : b);
            uint64_t res;
            if (nbit) b = ~b;
            if (opc == 0) res = a & b;
            else if (opc == 1) res = a | b;
            else if (opc == 2) res = a ^ b;
            else { /* ANDS: set flags */ res = a & b; }
            if (!sf) res &= 0xFFFFFFFF;
            if (opc == 3) set_nz(c, res, sf ? 64 : 32);
            setreg(c, rd, res);
            continue;
        }

        /* ---- LDR (literal): loads a pointer from the image --------------
         * This is how a lazy stub reaches its symbol pointer:
         *     ldr x16, label@PAGE-ish ; b <stub>
         * Without it every dynamically linked call stalls at the stub. */
        if ((insn & 0x3B000000) == 0x18000000) {
            int rt = insn & 31;
            int64_t imm19 = (int64_t)((insn >> 5) & 0x7FFFF);
            if (imm19 & (1 << 18))
                imm19 -= (1 << 19);
            uint64_t ea = pc + (uint64_t)(imm19 << 2);
            if (ea + 8 > c->image_base + c->image_size) {
                c->halt = DNT_HALT_FAULT;
                snprintf(c->halt_detail, sizeof(c->halt_detail),
                         "ldr literal target 0x%llx outside image",
                         (unsigned long long)ea);
                return -1;
            }
            setreg(c, rt, rd64((const uint8_t *)ea));
            continue;
        }

        /* ---- LDP/STP (signed offset, 64-bit) ---- */
        if ((insn & 0x7A000000) == 0x28000000) {
            int opc = (insn >> 30) & 3;
            int is_load = (opc == 2 || opc == 3) && ((insn & 0x00400000) != 0);
            int64_t imm = sext((insn >> 15) & 0x7F, 7) << 3;
            int rt = insn & 31;
            int rt2 = (insn >> 10) & 31;
            int rn = (insn >> 5) & 31;
            uint64_t addr = (rn == 31 ? c->sp : reg(c, rn));
            uint64_t ea = addr + (uint64_t)imm;
            if (ea + 16 > c->image_base + c->image_size && ea < c->image_base) {
                c->halt = DNT_HALT_FAULT;
                return -1;
            }
            if (is_load) {
                setreg(c, rt, rd64((const uint8_t *)ea));
                setreg(c, rt2, rd64((const uint8_t *)(ea + 8)));
            } else {
                memcpy((void *)(uintptr_t)ea, &c->x[rt & 31], 8);
                memcpy((void *)(uintptr_t)(ea + 8), &c->x[rt2 & 31], 8);
            }
            continue;
        }

        /* ---- LDR/STR (unsigned offset, 64/32-bit) ---- */
        if ((insn & 0x3B000000) == 0x39000000) {
            int size = (insn >> 30) & 3;
            int is_load = (insn >> 22) & 1;
            uint64_t imm = ((uint64_t)((insn >> 10) & 0xFFF)) << size;
            int rn = (insn >> 5) & 31;
            int rt = insn & 31;
            uint64_t ea = (rn == 31 ? c->sp : reg(c, rn)) + imm;
            if (is_load) {
                uint64_t v = 0;
                if (size == 3) v = rd64((const uint8_t *)ea);
                else if (size == 2) v = rd32((const uint8_t *)ea);
                else if (size == 1) v = *(const uint8_t *)ea | 0;
                else { uint16_t h; memcpy(&h, (const void *)ea, 2); v = h; }
                setreg(c, rt, v);
            } else {
                if (size == 3) { uint64_t v = reg(c, rt); memcpy((void *)ea, &v, 8); }
                else if (size == 2) { uint32_t v = (uint32_t)reg(c, rt); memcpy((void *)ea, &v, 4); }
                else if (size == 1) { uint8_t v = (uint8_t)reg(c, rt); memcpy((void *)ea, &v, 1); }
                else { uint16_t v = (uint16_t)reg(c, rt); memcpy((void *)ea, &v, 2); }
            }
            continue;
        }

        /* ---- Unimplemented ---- */
        c->halt = DNT_HALT_ILLEGAL;
        snprintf(c->halt_detail, sizeof(c->halt_detail),
                 "unimplemented instruction 0x%08x at 0x%llx",
                 insn, (unsigned long long)pc);
        return -1;
    }

    c->halt = DNT_HALT_STEP_LIMIT;
    snprintf(c->halt_detail, sizeof(c->halt_detail),
             "instruction budget of %llu exhausted",
             (unsigned long long)max_instructions);
    return -1;
}

void dnt_cpu_set_binding(dnt_cpu *c, void *b) { c->bind = b; }

void dnt_cpu_reset(dnt_cpu *c, uint64_t entry, uint64_t sp,
                   uint64_t image_base, uint64_t image_size)
{
    memset(c, 0, sizeof(*c));
    c->pc = entry;
    c->sp = sp;
    c->image_base = image_base;
    c->image_size = image_size;
    c->halt = DNT_HALT_NONE;
}
