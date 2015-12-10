#ifndef SHA_HEADER

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

void sha3_benchmark(char *file_name, int number_runs);
void sha2_serial(bool run_benchmark, char *file_name, int number_runs);

#endif