#include <stdio.h>

char s[105];

int main() {
    int n, i;
    scanf("%s", s);
    n = strlen(s);
    printf("%d:\n", n);
    printf("{");
    for(i = 0; i < n; i++) {
        printf("%#02x", (unsigned char)s[i]);
        if(i != n - 1) printf(", ");
    }
    printf("}\n");
    printf("{");
    for(i = 0; i < n; i++) {
        printf("L\'%c\'", s[i]);
        if(i != n - 1) printf(", ");
    }
    printf("}\n");
    return 0;
}