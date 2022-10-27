#include <stdio.h>

__forceinline int _strcmp(const char *s1, const char *s2) {
    while(*s1 || *s2) {
        if(*s1 != *s2) return *s1 < *s2 ? -1 : 1;
        s1++, s2++;
    }
    return 0;
}

int main() {
    char *s1 = "hello";
    char *s2 = "hello";
    printf("%d", _strcmp(s1, s2));
    return 0;
}