/*
 * Author: Brian Bowden
 * Date: 5/12/14
 *
 * Creates a file with random messages filled with random messages.
 */
 
#include <stdlib.h>
#include <stdio.h>
#include <time.h> 

void generate_file(char *file_name, int num_messages, int length)
{
	FILE *f;
	if(!(f = fopen(file_name, "w")))
	{
		printf("Error opening file %s.\n", file_name);
        exit(EXIT_FAILURE);
	}
	srand(time(NULL));
	
	char *output;
	for (int i = 0; i < num_messages; i++)
	{
		output = malloc((length + 1) * sizeof(char));
		for (int j = 0; j < length; j++)
		{
			output[j] = (rand() % 94) + 32;
		}
		output[length] = '\0';
		
		fprintf(f, "%s\n", output);
		free(output);
	}

	fclose(f);
}

int main(int argc, char** argv)
{
	if (argc != 4)
	{
		generate_file("messages.txt", 10000, 6);
	}
	else
	{
	    generate_file(argv[1], atoi(argv[2]), atoi(argv[3]));
	}
	return EXIT_SUCCESS;
}