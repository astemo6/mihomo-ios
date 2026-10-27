/* fix/nc-tcp0: arc4random for hosts whose libc lacks it (test-only; lwIP uses it for ports / ISNs). */
#include <stdint.h>
#include <stdlib.h>
uint32_t arc4random(void) { return (uint32_t)rand(); }
