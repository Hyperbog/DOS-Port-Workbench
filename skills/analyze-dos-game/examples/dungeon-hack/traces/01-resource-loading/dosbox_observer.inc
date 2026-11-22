// Include immediately before DOS_21Handler in DOSBox 0.74-3 src/dos/dos.cpp.
// Construct ArchiveCall once at the start of that handler.
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
static FILE *trace_log, *trace_reads;
struct TraceFile {
    const char *name;
    int handle;
    unsigned owner, position;
};
static TraceFile trace_files[]={{"HACK.RES",-1,0,0},{"HACK.TBL",-1,0,0}};
static unsigned trace_event;
class ArchiveCall {
    Bit16u ax, bx, cx, dx, ds_, ss_, sp, bp, psp;
    TraceFile *file;
    char path[256];
    Bit16u stackw(unsigned off) const { return real_readw(ss_,(Bit16u)off); }
public:
    ArchiveCall() : ax(reg_ax), bx(reg_bx), cx(reg_cx), dx(reg_dx),
        ds_(SegValue(ds)), ss_(SegValue(ss)), sp(reg_sp), bp(reg_bp), psp(dos.psp()), file(NULL) {
        unsigned ah=ax>>8;
        if (ah==0x3d) {
            MEM_StrCopy(SegPhys(ds)+dx,path,sizeof(path)-1);
            path[sizeof(path)-1]=0;
            const char *base=path;
            for (const char *s=path;*s;++s) if (*s=='\\'||*s=='/'||*s==':') base=s+1;
            for (unsigned i=0;i<2;++i) if (!strcasecmp(base,trace_files[i].name)) file=&trace_files[i];
        } else if (ah==0x3e || ah==0x3f || ah==0x40 || ah==0x42) {
            for (unsigned i=0;i<2;++i)
                if (psp==trace_files[i].owner && bx==trace_files[i].handle) file=&trace_files[i];
        }
    }
    ~ArchiveCall() {
        if (!file || trace_event>=500) return;
        if (!trace_log) {
            const char *log=getenv("DH_IO_LOG"), *raw=getenv("DH_READS");
            if (!log || !raw) return;
            trace_log=fopen(log,"w"); trace_reads=fopen(raw,"wb");
            if (!trace_log || !trace_reads) exit(87);
        }
        unsigned ah=ax>>8, cf=stackw(sp+4)&1, event=++trace_event;
        unsigned cs_=stackw(sp+2), ip=(stackw(sp)-2)&65535;
        if (ah==0x3d && !cf) {
            file->handle=reg_ax; file->owner=psp; file->position=0;
        }
        fprintf(trace_log,"E %u %s %04x %04x %04x %04x %04x %04x %04x %04x %04x %04x %u %u %04x %04x %s\n",
            event,file->name,psp,cs_,ip,ax,bx,cx,dx,ds_,reg_ax,reg_dx,cf,
            file->position,ss_,bp,ah==0x3d ? path : "-");
        unsigned frame=bp;
        fprintf(trace_log,"F %u",event);
        for (unsigned j=0;j<12 && frame<0xffe0;++j) {
            unsigned next=stackw(frame);
            fprintf(trace_log," %04x,%04x,%04x,%04x",frame,next,stackw(frame+2),stackw(frame+4));
            if ((next&0xfffe)<=frame) break;
            frame=next&0xfffe;
        }
        fprintf(trace_log,"\n");
        if (!cf && ah==0x3f) {
            unsigned char data[65536];
            MEM_BlockRead(((unsigned)ds_<<4)+dx,data,reg_ax);
            if (fwrite(data,1,reg_ax,trace_reads)!=reg_ax) exit(89);
            fflush(trace_reads);
            file->position+=reg_ax;
        } else if (!cf && ah==0x42) {
            file->position=((unsigned)reg_dx<<16)|reg_ax;
        } else if (!cf && ah==0x3e) {
            file->handle=-1;
        } else if (!cf && ah==0x40) {
            file->position+=reg_ax;
        }
        fflush(trace_log);
    }
};
