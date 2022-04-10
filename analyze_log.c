#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *f = fopen("log", "r");
    int n_dropped[10] = {0}, n_passed[10] = {0};
    int packet_id = -1;
    while (!feof(f)) {
        int c = getc(f);
        if (c == '\n')
            packet_id = -1;
        else if (packet_id == -1 && '0' <= c && c <= '9')
            packet_id = c - '0';
        else if (packet_id != -1 && c == 'm' && getc(f) == 's')
            n_passed[packet_id]++;
        else if (packet_id != -1 && c == '*')
            n_dropped[packet_id]++;
    }
    for (size_t i = 0; i < 5; i++) {
        printf("Host %lu: dropped %d / %d\n", i, n_dropped[i], n_dropped[i] + n_passed[i]);
    }
}
