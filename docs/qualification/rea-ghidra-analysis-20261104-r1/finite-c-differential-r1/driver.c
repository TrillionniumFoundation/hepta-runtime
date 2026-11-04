#include <stdio.h>
#include <stdlib.h>
int hepta_leaf(int);
int main(int argc,char **argv) { for(int i=1;i<argc;i++) printf("%d\n",hepta_leaf(atoi(argv[i]))); return 0; }
