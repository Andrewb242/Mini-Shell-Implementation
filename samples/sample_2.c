#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void perform_file_operations()
{
	// Demonstrate file operations
	// fd the value of the file descriptor
	int fd = open("example.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd == -1) {
		perror("Failed to open file");
		exit(1);
	}

	const char *message = "Hello, Building a mini shell is FUN!!\n";
	ssize_t bytes_written = write(fd, message, 44);
	if (bytes_written == -1) {
		perror("Failed to write to file");
		close(fd);
		exit(1);
	}

	if (close(fd) == -1) {
		perror("Failed to close file");
		exit(1);
	}
}

int main()
{
	pid_t pid;
	int status;

	// Perform some file operations before forking
	perform_file_operations();

	// Fork a child process,
	pid = fork();

	if (pid < 0) {
		// Fork failed
		perror("Fork failed");
		return 1;
	} else if (pid == 0) {
		// Child process
		printf("Child process (PID: %d) is executing\n", getpid());

		// Prepare arguments for execvp
		char *args[] = {
			"ls",   // command to execute
			"-l",   // option for long format
			"/tmp", // directory to list
			NULL    // must be NULL-terminated
		};

		// Execute the ls command
		if (execvp(args[0], args) == -1) {
			perror("execvp failed");
			exit(1);
		}

		// This line will never be reached if execvp succeeds
		exit(0);
	} else {
		// Parent process
		printf("Parent process (PID: %d) waiting for child (PID: %d)\n",
			   getpid(), pid);

		// Wait for the specific child process
		pid_t waited_pid = waitpid(pid, &status, 0);

		if (waited_pid == -1) {
			perror("waitpid failed");
			return 1;
		}

		// Check how the child process exited
		if (WIFEXITED(status)) {
			printf("Child process exited normally with status: %d\n",
				   WEXITSTATUS(status));
		} else if (WIFSIGNALED(status)) {
			printf("Child process terminated by signal: %d\n",
				   WTERMSIG(status));
		}
	}

	return 0;
}