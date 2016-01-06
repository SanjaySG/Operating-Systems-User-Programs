#include <stdio.h>
#include <syscall.h>

int
main (int argc, char **argv)
{
  int i;

  	printf("No arguments passed\n %d", argc);	

  for (i = 0; i < argc; i++)
    printf ("\n %s \t Line no: %d", argv[i],i);
  printf ("\n");

  printf("Reaches here");

  return EXIT_SUCCESS;
}
