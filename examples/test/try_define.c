#include <stdio.h>

#ifndef DEBUG
#define puts myputs
#endif

void myputs(const char *s) {
    return;
}

int main() {
    puts("Hello");
    return 0;
}