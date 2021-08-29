#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void check_f(uint8_t* buf)
{
    if (*buf == 'r') {
        *((int*)0) = 0;
    }
}

void check_e(uint8_t* buf)
{
    if (*buf == 'a') {
        check_f(buf+1);
    }
}

void check_d(uint8_t* buf)
{
    if (*buf == 'b') {
        check_e(buf+1);
    }
}

void check_c(uint8_t* buf)
{
    if (*buf == 'o') {
        check_d(buf+1);
    }
}

void check_b(uint8_t* buf)
{
    if (*buf == 'o') {
        check_c(buf+1);
    }
}

void check_a(uint8_t* buf)
{
    if (*buf == 'f') {
        check_b(buf+1);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return -1;
    }

    FILE *fp;
    fp = fopen(argv[1], "r");

    if (fp == NULL) {
        printf("Could not open file: %s\n", argv[1]);
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    rewind(fp);

    if (sz < 6) {
        return -1;
    }

    uint8_t* buf = (uint8_t *)malloc(sz * sizeof(uint8_t));
    fread(buf, sizeof(uint8_t), sz, fp);

    fclose(fp);

    check_a(buf);

    return 0;
}