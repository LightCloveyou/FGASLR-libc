#include "libc_layout_policy.h"
#include <stdio.h>

FG_POLICY_WHITELIST();
FG_ALLOW(puts);
FG_DENY(system);

int main(void) {
  puts("hello, protected app");
  return 0;
}
