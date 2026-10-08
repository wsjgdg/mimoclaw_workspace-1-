#include <stdio.h>
#include <string.h>
#include <stdint.h>
int uninstall_context_menu(char *err, size_t ne);
int _NSGetExecutablePath(char *b, uint32_t *s){ snprintf(b,*s,"/fake/filelock"); *s=(uint32_t)strlen(b); return 0; }
int main(void){ char e[512]=""; int ok=uninstall_context_menu(e,sizeof e); printf("uninstall=%d err=%s\n", ok, e); return ok?0:1; }
