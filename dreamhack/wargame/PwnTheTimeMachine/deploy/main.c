#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main() {
  time_t time = (time_t)0x63b04f05;
  struct tm *gtime = gmtime(&time);
  printf("year: %x\n", gtime->tm_year);
  printf("mon: %x\n", gtime->tm_mon);
  printf("day: %x\n", gtime->tm_mday);
  printf("hour: %x\n", gtime->tm_hour);
  printf("min: %x\n", gtime->tm_min);
  printf("sec: %x\n", gtime->tm_sec);
  return 0;
}
