#ifndef TIMER_H_
#define TIMER_H_

#include <time.h>

static clock_t LAST_TIME;
static void start_timer() {
    LAST_TIME = clock();
}

static void print_timer(char *name) {
    clock_t delta = clock() - LAST_TIME;
    printf("[TIMER] (%s) Milliseconds: %4lu\n", name, (delta * 1000) / CLOCKS_PER_SEC);
}

static void print_restart_timer(char *name) {
    print_timer(name);
    start_timer();
}

#endif // TIMER_H_
