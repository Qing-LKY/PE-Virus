#include <Windows.h>
#include <winnt.h>
#include <minwindef.h>

#include <stdio.h>
#include <string.h>

#define BUF_SIZE (1 << 20)

char target[100];
unsigned char buf[BUF_SIZE];

int main(int argc, char *argv[]) {
    // get
    FILE *fp;
    if(argc == 1) {
        scanf("%s", target);
        fp = fopen(target, "rb");
    } else {
        fp = fopen(argv[1], "rb");
    }
    fread(buf, 1, 1 << 20, fp);
    // calc
    int n = BUF_SIZE, jmp_off = 0;
    while(buf[n - 1] == 0) n--;
    for(int i = 0; i < n - 4; i++) {
        DWORD now = *(DWORD *)(buf + i);
        if(now == 0x11223344) {
            jmp_off = i;
            break;
        }
    }
    // output
    printf("#define CODE_SIZE %d\n", n);
    printf("#define JMP_POINT_OFFSET %d\n", jmp_off);
    printf("BYTE shellCode[CODE_SIZE] = ");
    printf("{");
    for(int i = 0; i < n; i++) {
        printf("%#02x", buf[i]);
        if(i != n - 1) printf(", ");
    }
    printf("};\n");
    return 0;
}