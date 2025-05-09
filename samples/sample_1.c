#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	// === 1. setenv() ===
	setenv("MY_VAR", "HelloWorld", 1); // Overwrites if already exists
	printf("MY_VAR = %s\n", getenv("MY_VAR"));
	// === 2. strcmp() ===
	char command[] = "list";
	if (strcmp(command, "list") == 0) {
		printf("You typed 'list'\n");
	}
	// === 3. chdir() ===
	char *new_dir = "/tmp";
	if (chdir(new_dir) == 0) {
		printf("Changed directory to %s\n", new_dir);
	}
	// === 4. pipe(), dup2(), close() ===
	int fds[2];
	pipe(fds);
	pid_t pid = fork();
	if (pid == 0) {
		// Child writes to pipe
		close(fds[0]);               // Close read end
		dup2(fds[1], STDOUT_FILENO); // Redirect stdout to pipe
		close(fds[1]);               // Close original write end
		// === 5. execvp() ===
		char *args[] = {"echo", "This is from execvp!", NULL};
		execvp("echo", args);    // Executes 'echo'
		perror("execvp failed"); // Will only run if exec fails
		exit(1);
	} else {
		// Parent reads from pipe
		close(fds[1]); // Close write end
		char buffer[100];
		int n = read(fds[0], buffer, sizeof(buffer) - 1);
		buffer[n] = '\0';
		printf("Parent read: %s", buffer);
		close(fds[0]); // Close read end
	}
	return 0;
}