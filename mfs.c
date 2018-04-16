#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Parsing input code taken from Trevor Bakker
#define WHITESPACE " \t\n"
#define MAX_COMMAND_SIZE 255
#define MAX_NUM_ARGUMENTS 5

// FILE ptr
FILE *fp = NULL;

// FILE essentials
int16_t BPB_BytsPerSec;
int8_t BPB_SecPerClus;
int16_t BPB_RsvdSecCnt;
int8_t BPB_NumFATS;
int32_t BPB_FATSz32;

// directory ptrs
int32_t cwd;

// directory struct
struct __attribute__((__packed__)) DirectoryEntry
{
  char DIR_Name[11];
  uint8_t DIR_attr;
  uint8_t Unused[8];
  uint16_t DIR_FirstClusterHigh;
  uint8_t Unused2[4];
  uint16_t DIR_FirstClusterLow;
  uint32_t DIR_Filesize;
};

struct DirectoryEntry dir[16];

// Logical Block Address to Offset
int LBAToOffset(int32_t sector)
{
  return ((sector - 2) * BPB_BytsPerSec) + (BPB_BytsPerSec * BPB_RsvdSecCnt) + (BPB_BytsPerSec * BPB_NumFATS * BPB_FATSz32);
}

// Next logical block address
int16_t NextLB(int32_t sector)
{
  int32_t FATAddress = (BPB_BytsPerSec * BPB_RsvdSecCnt) + (sector * 4);
  int16_t val;
  fseek(fp, FATAddress, SEEK_SET);
  fread(&val, 2, 1, fp);
  return val;
}

// read directory function
void readDir(int32_t sector)
{
  fseek(fp, LBAToOffset(sector), SEEK_SET);
  fread(dir, 16, sizeof(struct DirectoryEntry), fp);
}

// returns a searchable string from user input
char *parseName(char *input)
{
  char *temp = (char *)calloc(12, sizeof(char));
  memset(temp, ' ', 11);
  int i = 0;

  for (; i <= 8; i++)
  {
    if (input[i] == '.' || input[i] == 0)
    {

      // copy extension
      if (input[i] == '.')
      {
        temp[8] = toupper(input[i + 1]);
        temp[9] = toupper(input[i + 2]);
        temp[10] = toupper(input[i + 3]);
      }
      else
        input[i] = 0;
      break;
    }
    temp[i] = toupper(input[i]);
  }

  return temp;
}

void cd(char *dir_name)
{

  char *name = parseName(dir_name);
  int cluster;
  int found = 0;

  int i;
  for (i = 0; i < 16; i++)
  {
    char *str = (char *)malloc(12 * sizeof(char));
    memset(str, 0, 12);
    strncpy(str, dir[i].DIR_Name, 11);

    if (strcmp(str, name) == 0)
    {
      cluster = dir[i].DIR_FirstClusterLow;
      cwd = cluster;
      readDir(cwd);
      found = 1;

      free(str);
      break;
    }
  }

  // didn't found folder
  if (!found)
    printf("\nError: Folder not found.\n\n");

  free(name);
}

int main()
{
  char *cmd_str = (char *)malloc(MAX_COMMAND_SIZE); //holds input
  int isOpen = 0;

  while (1)
  {
    // print out prompt
    printf("mfs> ");
    while (!fgets(cmd_str, MAX_COMMAND_SIZE, stdin))
      ;

    /* Parse input */
    char *token[MAX_NUM_ARGUMENTS];
    int token_count = 0;

    // Pointer to point to the token parsed by strsep
    char *arg_ptr;
    char *working_str = strdup(cmd_str);
    char *working_root = working_str;

    // Tokenize the input stringswith whitespace used as the delimiter
    while (((arg_ptr = strsep(&working_str, WHITESPACE)) != NULL) &&
           (token_count < MAX_NUM_ARGUMENTS))
    {
      token[token_count] = strndup(arg_ptr, MAX_COMMAND_SIZE);
      if (strlen(token[token_count]) == 0)
      {
        token[token_count] = NULL;
      }
      token_count++;
    }

    // blank input case
    if (token[0] == NULL)
      continue;

    // termination cases
    if (strcmp(token[0], "exit") == 0 || strcmp(token[0], "quit") == 0)
      exit(0);

    // command handling if-else
    if (strcmp(token[0], "open") == 0)
    {
      if (isOpen)
      {
        printf("Error: File system image already open.\n\n");
      }
      else
      {
        fp = fopen(token[1], "r");
        if (!fp)
        {
          // error
          printf("Error: File system image not found.\n\n");
        }
        else
        {
          isOpen = 1;

          // read in info
          fseek(fp, 11, SEEK_SET);
          fread(&BPB_BytsPerSec, 1, 2, fp);

          fseek(fp, 13, SEEK_SET);
          fread(&BPB_SecPerClus, 1, 1, fp);

          fseek(fp, 14, SEEK_SET);
          fread(&BPB_RsvdSecCnt, 1, 2, fp);

          fseek(fp, 16, SEEK_SET);
          fread(&BPB_NumFATS, 1, 1, fp);

          fseek(fp, 36, SEEK_SET);
          fread(&BPB_FATSz32, 1, 4, fp);

          // set root dir
          cwd = 2;

          readDir(cwd);
        }
      }
    }
    else if (strcmp(token[0], "close") == 0)
    {
      if (!isOpen)
      {
        // error
        printf("Error: File system not open.\n\n");
      }
      else
      {
        // close
        if (fclose(fp) != 0)
        {
          // error
          printf("Error: File image couldn't be closed.\n\n");
        }
        else
          isOpen = 0;
      }
    }
    else if (strcmp(token[0], "info") == 0)
    {
      if (isOpen)
      {
        printf("\nBPB_BytsPerSec: %d \tHex: 0x%X\n", BPB_BytsPerSec, BPB_BytsPerSec);
        printf("BPB_SecPerClus: %d \tHex: 0x%X\n", BPB_SecPerClus, BPB_SecPerClus);
        printf("BPB_RsvdSecCnt: %d \tHex: 0x%X\n", BPB_RsvdSecCnt, BPB_RsvdSecCnt);
        printf("BPB_NumFATS:    %d \tHex: 0x%X\n", BPB_NumFATS, BPB_NumFATS);
        printf("BPB_FATSz32:    %d \tHex: 0x%X\n\n", BPB_FATSz32, BPB_FATSz32);
      }
      else
        printf("Error: File system image must be opened first.\n\n");
    }
    else if (strcmp(token[0], "stat") == 0)
    {
      if (isOpen)
      {
        if (token[1] == NULL || token[1] == " " || token[1] == "\n")
        {
          printf("\nError: Invalid input.\n\n");
          continue;
        }

        int found = 0;
        char *name = parseName(token[1]);
        int i = 0;

        for (; i < 16; i++)
        {
          if (dir[i].DIR_attr != 1 && dir[i].DIR_attr != 16 && dir[i].DIR_attr != 32)
            continue;

          char *str = (char *)malloc(12 * sizeof(char));
          memset(str, 0, 12);
          strncpy(str, dir[i].DIR_Name, 11);

          if (str[0] != -27 && strcmp(name, str) == 0)
          { // if not deleated
            printf("\nName: %s\tAttribute: %d\tSize: %d",
                   str, dir[i].DIR_attr, dir[i].DIR_Filesize);

            printf("\nFirstClusterHigh: %d\tFirstClusterLow: %d\n\n",
                   dir[i].DIR_FirstClusterHigh, dir[i].DIR_FirstClusterLow);

            found = 1;
          }

          free(str);
        }

        if (!found)
          printf("\nError: File not found.\n\n");

        free(name);
      }
      else
        printf("Error: File system image must be opened first.\n\n");
    }
    else if (strcmp(token[0], "get") == 0)
    {
      if (isOpen)
      {
        char *name = parseName(token[1]);
        readDir(cwd);
        int found = 0;

        int i;
        for (; i < 16; i++)
        {
          // check if it's a file
          if (dir[i].DIR_attr != 1 && dir[i].DIR_attr != 32)
            continue;

          char *str = (char *)malloc(12 * sizeof(char));
          memset(str, 0, 12);
          strncpy(str, dir[i].DIR_Name, 11);

          if (strcmp(name, str) == 0)
          {
            found = 1;
            break; // found directory entry
          }

          free(str);
        }

        if (found)
        {
          FILE *out = fopen(token[1], "w");
          int readPoint = dir[i].DIR_FirstClusterLow;

          char byte;
          while (readPoint != -1)
          {
            // seek to read point
            fseek(fp, LBAToOffset(readPoint), SEEK_SET);

            // read and write the sector byte by byte
            int j = 0;
            for (; j < BPB_BytsPerSec; j++)
            {
              fread(&byte, 1, 1, fp);
              fwrite(&byte, 1, 1, out);
            }

            // find next logical point
            readPoint = NextLB(readPoint);
          }
          fclose(out);
        }
        free(name);
      }
      else
        printf("Error: File system image must be opened first.\n\n");
    }
    else if (strcmp(token[0], "cd") == 0)
    {
      if (isOpen)
      {
        if (token[1] == NULL || token[1] == " " || token[1] == "\n")
        {
          // set cluster to root
          readDir(2);
          cwd = 2;
          continue;
        }

        if (strcmp(token[1], "..") == 0)
        {
          if (cwd != 2)
          {
            // parent cluster is saved in second dir entry
            int cluster = dir[1].DIR_FirstClusterLow;

            // special root folder case
            if (cluster == 0)
            {
              cwd = 2;
              readDir(cwd);
            }
            else
            {
              cwd = cluster;
              readDir(cwd);
            }
          }
          continue;
        }
        cd(token[1]);
      }
      else
        printf("Error: File system image must be opened first.\n\n");
    }
    else if (strcmp(token[0], "ls") == 0)
    {
      if (isOpen)
      {
        readDir(cwd);
        printf(".\n");

        int i = 0;
        for (; i < 16; i++)
        {

          if (dir[i].DIR_attr != 1 && dir[i].DIR_attr != 16 && dir[i].DIR_attr != 32)
            continue;

          char *str = (char *)malloc(12 * sizeof(char));
          memset(str, 0, 12);
          strncpy(str, dir[i].DIR_Name, 11);

          if (str[0] != -27) // if not deleated
            printf("%s %d\n", str, dir[i].DIR_Filesize);

          free(str);
        }
      }
      else
        printf("Error: File system image must be opened first.\n\n");
    }
    else if (strcmp(token[0], "read") == 0)
    {
      if (isOpen)
      {
      }
      else
        printf("Error: File system image must be opened first.\n\n");
    }
    else if (strcmp(token[0], "volume") == 0)
    {
      if (isOpen)
      {
        char volume[12];
        fseek(fp, 71, SEEK_SET);
        fread(&volume, 1, 11, fp);

        // null terminate volume str
        volume[11] = 0;

        if (strcmp(volume, "") == 0 || strcmp(volume, "            "))
        {
          printf("Error: volume name not found.\n\n");
        }
        else
          printf("Volume name: %s\n", volume);
      }
      else
        printf("Error: File system image must be opened first.\n\n");
    }
    else
    {
      printf("%s: Commnad not supported.\n\n", token[0]);
    }

    // freeing allocated vars
    free(working_root);
  }

  return 0;
}