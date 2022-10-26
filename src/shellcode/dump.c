#include <stdio.h>
#include <string.h>

const char TARGET[] = ".tiny";

unsigned char buf[1 << 20];

int main() {
    FILE *fp = fopen(TARGET, "rb");
    fread(buf, 1, 1 << 20, fp);
    int n = 0x26;
    printf("{");
    for(int i = 0; i < n; i++) {
        printf("%#02x", buf[i]);
        if(i != n - 1) printf(", ");
    }
    printf("}");
    return 0;
}