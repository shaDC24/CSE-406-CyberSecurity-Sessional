#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// IMPORTANT: Replace <LAST_3_DIGITS_OF_YOUR_ID> below with
// the last 3 digits of your Student ID without any leading zeroes
// For example, if your ID is 2105061, use 61
// ============================================================
#define STUDENT_ID 123

#define USERNAME_SZ  (60 + STUDENT_ID % 40)
#define PROFILE_SZ   64
#define ACCESS_SZ    32
#define READ_SZ      400
#define CANARY_VAL   (0xDEAD0000 + STUDENT_ID + 16)

char username[USERNAME_SZ];
int canary_guard;
char profile[PROFILE_SZ];
char access_code[ACCESS_SZ];

int main() {
    char str[READ_SZ];
    FILE *badfile;

    canary_guard = CANARY_VAL;

    badfile = fopen("badfile", "r");
    if (!badfile) {
        printf("Error: Cannot open badfile\n");
        return 1;
    }

    printf("Authenticating user...\n");

    if (fgets(str, READ_SZ, badfile)) {
        str[strcspn(str, "\n")] = '\0';
        strcpy(username, str);
    }

    if (fgets(str, READ_SZ, badfile)) {
        str[strcspn(str, "\n")] = '\0';
        strcpy(access_code, str);
    }

    fclose(badfile);

    if (canary_guard != CANARY_VAL) {
        printf("Intrusion detected! Memory corruption guard triggered!\n");
        exit(1);
    }

    if (strncmp(username, "admin", 5) == 0 &&
        strncmp(access_code, "UNLOCK", 6) == 0) {
        printf("Access Granted - Welcome, Administrator!\n");
        system("/bin/sh");
    } else {
        printf("Authentication Failed!\n");
        if (strncmp(username, "admin", 5) != 0) {
            printf("  Reason: Invalid username\n");
        }
        if (strncmp(access_code, "UNLOCK", 6) != 0) {
            printf("  Reason: Invalid access code\n");
        }
    }

    return 0;
}
