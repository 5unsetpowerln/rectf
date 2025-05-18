#include <stdint.h>
#include <stdio.h>

int main() {
  for (uint32_t i = 0; i < UINT32_MAX; i++) {
    int32_t i_i32 = (int32_t)i;
    int32_t i_i32_p1 = i_i32 + 1;

    uint32_t i_u32 = (uint32_t)i_i32;
    uint32_t i_u32_p1 = (uint32_t)i_i32_p1;

    if (i_i32_p1 - i_u32 != 1) {
      printf("i: %x\n", i);
      printf("diff: %x\n", i_u32_p1 - i_u32);
    }
  }

  return 0;
}
