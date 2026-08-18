#include "../cfs.h"
#include "../cfs_format.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Forward declarations for create helpers */
extern CFS *cfs_create(const char *path);
extern int  cfs_add_file(CFS *c, const char *vpath, const void *buf, size_t size);
extern int  cfs_finalise(CFS *c);

static int failed=0;
#define CHK(c,m) do{if(!(c)){failed++;fprintf(stderr,"  FAIL: %s\n",m);}else{fprintf(stderr,"  OK %s\n",m);}}while(0)

int main(void) {
    const char *path = "/tmp/test_libcfs.cfs";
    unlink(path);

    /* Step 1: create container with 3 files */
    {
        CFS *c = cfs_create(path);
        CHK(c!=NULL,"create"); if(!c) return 1;

        uint8_t d1[256]; for(int i=0;i<256;i++) d1[i]=(i*1000003+17)&0xFF;
        uint8_t d2[1024]; for(int i=0;i<1024;i++) d2[i]=i&0xFF;
        uint8_t d3[4096]; memset(d3,0x42,4096);

        CHK(cfs_add_file(c,"file1.bin",d1,256)==0,"add file1");
        CHK(cfs_add_file(c,"file2.txt",d2,1024)==0,"add file2");
        CHK(cfs_add_file(c,"file3.dat",d3,4096)==0,"add file3");
        CHK(cfs_finalise(c)==0,"finalise");
        cfs_close(c);
    }

    /* Step 2: read back */
    {
        CFS *c = cfs_open(path, CFS_RDONLY);
        CHK(c!=NULL,"open"); if(!c) return 1;

        /* Stats */
        CfsStats st; cfs_stats(c,&st);
        printf("  files=%u orig=%llu comp=%llu ratio=%.2fx\n",
            st.file_count, (unsigned long long)st.total_orig_size,
            (unsigned long long)st.total_compressed_size, st.compress_ratio);
        CHK(st.file_count==3,"file_count=3");

        /* LS */
        CfsDirEntry ents[8];
        int n = cfs_ls(c, "", ents, 8);
        CHK(n==3,"ls count=3");
        for(int i=0;i<n;i++) printf("  ls[%d]: %s %lluB\n", i, ents[i].name, (unsigned long long)ents[i].size);

        /* Read all and verify */
        void *b1=cfs_read_all(c,"file1.bin",NULL);
        void *b2=cfs_read_all(c,"file2.txt",NULL);
        void *b3=cfs_read_all(c,"file3.dat",NULL);

        uint8_t e1[256]; for(int i=0;i<256;i++) e1[i]=(i*1000003+17)&0xFF;
        uint8_t e2[1024]; for(int i=0;i<1024;i++) e2[i]=i&0xFF;
        uint8_t e3[4096]; memset(e3,0x42,4096);

        CHK(b1&&!memcmp(b1,e1,256),"file1 match");
        CHK(b2&&!memcmp(b2,e2,1024),"file2 match");
        CHK(b3&&!memcmp(b3,e3,4096),"file3 match");

        /* Partial read */
        uint8_t part[64];
        ssize_t r = cfs_read(c, "file3.dat", part, 64, 100);
        CHK(r==64&&!memcmp(part,e3+100,64),"partial read");

        /* Stat */
        CfsStat fst;
        CHK(cfs_stat(c,"file1.bin",&fst)==0,"stat");
        CHK(fst.size==256,"stat.size");

        free(b1);free(b2);free(b3);
        cfs_close(c);
    }

    unlink(path);
    printf("\n=== %d failures ===\n", failed);
    return failed?1:0;
}
