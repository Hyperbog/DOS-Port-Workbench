// For DOSBox 0.74-3's normal real-mode core, immediately after its main LOADIP.
#include "dos_inc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct DpwPoint {
    unsigned cs, ip;
    char mode[8], label[48];
};

static void dpw_observe_instruction() {
    static const char *profile = getenv("DPW_PROFILE"), *output = getenv("DPW_TRACE");
    static bool loaded, identified, started, finished;
    static unsigned entry_cs, entry_ip, sig_offset, signature, base, count, seq;
    static DpwPoint points[128];
    static FILE *log;
    if (!profile || !output || finished) return;
    if (!loaded) {
        FILE *f = fopen(profile, "r");
        if (!f) { perror("DPW_PROFILE"); exit(2); }
        char line[200];
        if (!fgets(line, sizeof(line), f) ||
            sscanf(line, "image %4x:%4x %4x %8x", &entry_cs, &entry_ip, &sig_offset, &signature) != 4) {
            fprintf(stderr, "Expected image entry, signature offset and little-endian dword\n"); exit(2);
        }
        unsigned starts = 0, stops = 0;
        while (fgets(line, sizeof(line), f)) {
            if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
            if (count == sizeof(points)/sizeof(points[0])) { fprintf(stderr, "Too many points\n"); exit(2); }
            DpwPoint &p = points[count++];
            if (sscanf(line, "%7s %4x:%4x %47s", p.mode, &p.cs, &p.ip, p.label) != 4) {
                fprintf(stderr, "Invalid profile point: %s", line); exit(2);
            }
            if (!strcmp(p.mode, "start")) ++starts;
            else if (!strcmp(p.mode, "stop")) ++stops;
            else if (strcmp(p.mode, "watch")) { fprintf(stderr, "Invalid point type: %s\n", p.mode); exit(2); }
        }
        fclose(f);
        if (starts != 1 || stops != 1) { fprintf(stderr, "Expected one start and one stop\n"); exit(2); }
        loaded = true;
    }
    const unsigned seg = SegValue(cs), ip = reg_ip;
    if (!identified) {
        const unsigned candidate = (dos.psp() + 0x10u) & 0xffff;
        if (ip != entry_ip || seg != ((candidate + entry_cs) & 0xffff) ||
            real_readd(seg, sig_offset) != signature) return;
        base = candidate;
        identified = true;
    }
    const unsigned rel = (seg - base) & 0xffff, stack_seg = SegValue(ss);
    for (unsigned i = 0; i < count; ++i) {
        const DpwPoint &p = points[i];
        if (p.cs != rel || p.ip != ip) continue;
        if (!started) {
            if (strcmp(p.mode, "start")) return;
            log = fopen(output, "w");
            if (!log) { perror("DPW_TRACE"); exit(2); }
            setvbuf(log, NULL, _IOLBF, 0);
            fputs("event,point,image_cs_ip,guest_cs_ip,ax,bx,cx,dx,si,di,bp,ss,sp,ds,es,"
                  "stack0,stack1,stack2,stack3,stack4,es_di_dword,ds_si_dword\n", log);
            started = true;
        }
        fprintf(log, "%u,%s,%04X:%04X,%04X:%04X,%04X,%04X,%04X,%04X,%04X,%04X,%04X,%04X,%04X,%04X,%04X",
                ++seq, p.label, rel, ip, seg, ip, (unsigned)reg_ax, (unsigned)reg_bx, (unsigned)reg_cx,
                (unsigned)reg_dx, (unsigned)reg_si, (unsigned)reg_di, (unsigned)reg_bp,
                stack_seg, (unsigned)reg_sp, (unsigned)SegValue(ds), (unsigned)SegValue(es));
        for (unsigned j = 0; j < 5; ++j)
            fprintf(log, ",%04X", (unsigned)real_readw(stack_seg, (Bit16u)(reg_sp + 2*j)));
        fprintf(log, ",%08X,%08X\n", (unsigned)real_readd(SegValue(es), reg_di),
                (unsigned)real_readd(SegValue(ds), reg_si));
        if (!strcmp(p.mode, "stop")) { fclose(log); finished = true; }
        return;
    }
}
