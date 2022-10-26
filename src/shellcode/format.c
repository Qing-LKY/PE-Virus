#include <stdio.h>

char s[105];

int main() {
    int n, i;
    scanf("%s", s);
    n = strlen(s);
    printf("%d(+1: %d):\n", n, n + 1);
    printf("{");
    for(i = 0; i < n; i++) {
        printf("%#02x", (unsigned char)s[i]);
        printf(", ");
    }
    printf("0}\n");
    printf("{");
    for(i = 0; i < n; i++) {
        printf("L\'%c\'", s[i]);
        printf(", ");
    }
    printf("0}\n");
    printf("{");
    for(i = 0; i < n; i++) {
        printf("\'%c\'", s[i]);
        printf(", ");
    }
    printf("0}\n");
    return 0;
}