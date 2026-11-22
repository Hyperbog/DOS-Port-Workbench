// DOSBox 0.74-3 normal core. Call dh_trace_instruction() after LOADIP in its main loop.
#include "dos_inc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void dh_trace_instruction() {
    static const char *log_path = getenv("DH_VM_TRACE");
    static FILE *log;
    static unsigned base, entries, n, target_cs, target_ip;
    static bool awaiting_target, done;
    if (!log_path || done) return;
    const unsigned cs_ = SegValue(cs), ip = reg_ip, ss_ = SegValue(ss);
    const unsigned ds_ = SegValue(ds), es_ = SegValue(es);
    if (!base) {
        if (ip != 0 || cs_ != (unsigned)dos.psp()+0x10) return;
        if (real_readb(cs_, 0) != 0xba || real_readd(cs_, 3) != 0x9116892e ||
            real_readd(cs_, 8) != 0x21cd30b4) return;
        base = cs_;
        log = fopen(log_path, "w");
        if (!log) { perror("DH_VM_TRACE"); exit(87); }
        setvbuf(log, NULL, _IOLBF, 0);
        fprintf(log, "event,kind,guest_cs_ip,ghidra_cs_ip,detail\n");
    }
    const unsigned seg = (cs_ - base + 0x1000) & 0xffff;
    if (seg != 0x1000 && seg != 0x1668 && seg != 0x1b62 && seg != 0x20f5 && !awaiting_target) return;
    const char *kind = NULL;
    char detail[256] = {};
    if (awaiting_target && cs_ == target_cs && ip == target_ip) {
        kind = "native_entry";
        sprintf(detail, "return=%04X:%04X argc=%u argument=%08X",
                real_readw(ss_,reg_sp+2),real_readw(ss_,reg_sp),real_readw(ss_,reg_sp+4),
                (unsigned)real_readd(ss_,reg_sp+6));
        done = true;
    } else if (seg == 0x1000 && ip == 0 && !n) {
        kind = "image_entry";
        sprintf(detail, "psp=%04X image=%04X",dos.psp(),base);
    } else if (seg == 0x1668 && ip == 0x03cc) {
        kind = "name_lookup";
        char name[64] = {};
        MEM_StrCopy(((unsigned)real_readw(ss_,reg_sp+4)<<4)+real_readw(ss_,reg_sp+2),name,63);
        sprintf(detail, "name=%s",name);
    } else if (seg == 0x1668 && ip == 0x041d) {
        kind = "create_program";
        sprintf(detail, "slot=%u class=%u",(unsigned)real_readd(ss_,reg_sp+2),
                (unsigned)real_readd(ss_,reg_sp+6));
    } else if (seg == 0x1b62 && ip == 0x0071) {
        kind = "send_site";
        sprintf(detail, "receiver=%u message=%u selector=%04X",
                real_readw(ss_,reg_sp),real_readw(ss_,reg_sp+2),real_readw(ss_,reg_sp+4));
    } else if (seg == 0x20f5 && ip == 0x08f2) {
        kind = "dispatch_entry";
        sprintf(detail, "ordinal=%u receiver=%u message=%u selector=%04X return=%04X:%04X",
                ++entries,real_readw(ss_,reg_sp+4),real_readw(ss_,reg_sp+6),real_readw(ss_,reg_sp+8),
                real_readw(ss_,reg_sp+2),real_readw(ss_,reg_sp));
    } else if (seg == 0x20f5 && ip == 0x0991) {
        kind = "handler_match";
        sprintf(detail, "message=%u header=%04X",real_readw(ds_,reg_si),real_readw(ds_,reg_si+2));
    } else if (seg == 0x20f5 && ip == 0x09d5) {
        kind = "handler_frame";
        sprintf(detail, "bytecode=%04X:%04X auto_bytes=%u",ds_,reg_si,real_readw(ds_,reg_si));
        const char *path = getenv("DH_VM_IMAGE");
        if (path && entries == 1) {
            unsigned char data[1121];
            MEM_BlockRead((unsigned)ds_<<4,data,sizeof(data));
            FILE *f = fopen(path,"wb");
            if (!f || fwrite(data,1,sizeof(data),f)!=sizeof(data) || fclose(f)) exit(88);
        }
    } else if (seg == 0x20f5 && entries &&
               real_readd(cs_,ip)==0x03461c8a && real_readd(cs_,ip+4)==0xa7ff2edb &&
               real_readw(cs_,ip+8)==0x0641) {
        kind = "opcode_fetch";
        unsigned op = real_readb(ds_,reg_si);
        sprintf(detail, "bytecode=%04X:%04X op=%02X native_ip=%04X",
                ds_,reg_si,op,real_readw(cs_,0x0641+2*op));
    } else if (seg == 0x20f5 && ip == 0x0d79 && entries) {
        kind = "constant_op";
        sprintf(detail, "operand=%u",real_readb(ds_,reg_si));
    } else if (seg == 0x20f5 && ip == 0x131a && entries) {
        kind = "static_written";
        sprintf(detail, "address=%04X:%04X value=%02X",ds_,reg_bx,real_readb(ds_,reg_bx));
    } else if (seg == 0x20f5 && ip == 0x0e3f && entries) {
        kind = "native_call";
        target_cs=real_readw(es_,reg_di+2);
        target_ip=real_readw(es_,reg_di);
        awaiting_target=true;
        sprintf(detail, "target=%04X:%04X argc=%u argument=%08X",target_cs,target_ip,
                real_readw(ss_,reg_sp),(unsigned)real_readd(ss_,reg_sp+2));
    }
    if (kind) fprintf(log,"%u,%s,%04X:%04X,%04X:%04X,%s\n",++n,kind,cs_,ip,seg,ip,detail);
    if (n == 256 || done) { fclose(log); done=true; }
}
