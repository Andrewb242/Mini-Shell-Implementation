// SPDX-License-Identifier: BSD-3-Clause

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "cmd.h"
#include "utils.h"

#define READ		0
#define WRITE		1

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir)
{
	/* Execute cd. */

	const char *path;

	if (!dir || !dir->string) {
		path = getenv("HOME");
		if (!path) {
			fprintf(stderr, "cd: HOME not set\n");
			return 1;
		}
	} else {
		path = get_word(dir);
	}

	if (chdir(path) != 0) {
		fprintf(stderr, "cd: ");
		perror(path);
		return 1;
	}

	return 0;
}

typedef struct ptr {
	char* ptr;
	struct ptr* next;
} ptr_t;

static ptr_t* first_ptr = NULL;

/**
 * Internal exit/quit command.
 */
static int shell_exit(void)
{
	/* Execute exit/quit. */

	// Free environment variable pointers
	ptr_t* cur = first_ptr;
	ptr_t* next = NULL;

	while (cur) {
		next = cur->next;
		free(cur->ptr);
		free(cur);
		cur = next;	
	}

	first_ptr = NULL;
	return SHELL_EXIT; 
}


/**
 * Handle redirections
 */

void handle_redirections(simple_command_t *cmd) {

	// Input
	if (cmd->in) {
		
		const char* infile = get_word(cmd->in);
		int fd = open(infile, O_RDONLY);
		if (fd < 0) {
			perror("open input");
			exit(1);
		}
		dup2(fd, STDIN_FILENO);
		close(fd);
	}

	// Both Error and Output &>
	if ((cmd->out && cmd->err) && (cmd->out == cmd->err)) {

		const char* bothfile = get_word(cmd->out);
		int flags = O_WRONLY | O_CREAT | O_CLOEXEC;

		if (cmd->io_flags & IO_OUT_APPEND || cmd->io_flags & IO_ERR_APPEND) {
			flags |= O_APPEND;
		} else {
			flags |= O_TRUNC;
		}
		
		int fd = open(bothfile, flags, 0666); 
		if (fd < 0) {
			perror("open &> file");
			exit(1);
		}

		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
		return;
	}

	// Output >
	if (cmd->out) {

		const char* outfile = get_word(cmd->out);
		int flags = O_WRONLY | O_CREAT | O_CLOEXEC;
		if (cmd->io_flags & IO_OUT_APPEND) {
			flags |= O_APPEND;
		} else {
			flags |= O_TRUNC;
		}

		int fd = open(outfile, flags, 0666);
		if (fd < 0) {
			perror("open output");
			exit(1);
		}

		dup2(fd, STDOUT_FILENO);
		close(fd);
	}

	// Errror 2>
	if (cmd->err) {
		const char* errfile = get_word(cmd->err);
		int flags = O_WRONLY | O_CREAT | O_CLOEXEC;
		if (cmd->io_flags & IO_ERR_APPEND) {
			flags |= O_APPEND;
		} else {
			flags |= O_TRUNC;
		}

		int fd = open(errfile, flags, 0666);
		if (fd < 0) {
			perror("open error");
			exit(1);
		}
		dup2(fd, STDERR_FILENO);
		close(fd);
	}
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	/* Sanity checks. */
	if (!s || !s->verb) return 1;


	const char* cmd = get_word(s->verb);

	/* If builtin command, execute the command. */

	if (s->params && strcmp(s->verb->string, "cd") == 0) {

		int saved_stdout = dup(STDOUT_FILENO);
		int saved_stderr = dup(STDERR_FILENO);

		handle_redirections(s);
		int r0 = shell_cd(s->params);

		dup2(saved_stdout, STDOUT_FILENO);
		dup2(saved_stderr, STDERR_FILENO);
		close(saved_stdout);
		close(saved_stderr);

		return r0;
	}

	else if (!s->params && (strcmp(s->verb->string, "exit") == 0 || strcmp(s->verb->string, "quit") == 0)) {
		return shell_exit();
	}

	/* If variable assignment, execute the assignment and return
	 * the exit status.
	 */

	else if (s->verb->next_part && strcmp(s->verb->next_part->string, "=") == 0) {

		// Environment variable data structure for freeing upon exit

		ptr_t* env_ptr = (ptr_t*)malloc(sizeof(ptr_t));
		if (!env_ptr) return 1;
		env_ptr->ptr = (char*)malloc(1024);
		if (!env_ptr->ptr) return 1;

		env_ptr->next = NULL;

		if (!first_ptr) {
			first_ptr = env_ptr;
		} else {
			ptr_t* cur = first_ptr;
			while (cur->next) {
				cur = cur->next;
			}
			cur->next = env_ptr;
		}

		word_t* part = s->verb;

		// Handle the assignment variable so it isn't replaced when overwriting
		strcat(env_ptr->ptr, part->string);
		part = part->next_part;

		char* var = NULL;
		while (part) {
			var = getenv(part->string);
			if (var) {
				strcat(env_ptr->ptr, var);
			} else {
				strcat(env_ptr->ptr, part->string);
			}
			part = part->next_part;
		}

		// Set environment variable
		if (putenv(env_ptr->ptr) != 0) return 1;

		return 0;
	}

	/* If external command:
	 *   1. Fork new process
	 *     2c. Perform redirections in child
	 *     3c. Load executable in child
	 *   2. Wait for child
	 *   3. Return exit status
	 */

	else {
		pid_t pid = fork();	

		if (pid < 0) {
			perror("fork");
			return 1;
		} else if (pid == 0) {
			handle_redirections(s);

			int count = 1;
			word_t* part = s->params;
			while (part) {
				count++;
				part = part->next_part;
			}

			char** argv = get_argv(s, &count);
			execvp(cmd, argv);
			fprintf(stderr, "Execution failed for '%s'\n", s->verb->string);
			exit(1);
		} else {
			int status;
			waitpid(pid, &status, 0);
			return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
		}
	}
}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* Execute cmd1 and cmd2 simultaneously. */

	pid_t pid_1, pid_2;
	int status_1, status_2;

	// First command
	pid_1 = fork();

	if (pid_1 < 0) {
		perror("fork failed");
		return false;
	}

	else if (pid_1 == 0) {
		parse_command(cmd1, level + 1, father);
		exit(0);
	}

	// Second command
	pid_2 = fork();

	if (pid_2 < 0) {
		perror("fork failed");
		return false;
	}

	else if (pid_2 == 0) {
		parse_command(cmd2, level + 1, father);
		exit(0);
	}

	waitpid(pid_1, &status_1, 0);
	waitpid(pid_2, &status_2, 0);

	// Check the exit statuses of both children
	if (WIFEXITED(status_1) && WIFEXITED(status_2)) {
		// Both children terminated normally, return a successful status
		if (WEXITSTATUS(status_1) == 0 && WEXITSTATUS(status_2) == 0) {
			return true;
		}
	}

	return false; /* Replace with actual exit status. */
}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2).
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* Redirect the output of cmd1 to the input of cmd2. */

	int pipefd[2];
	pid_t pid_1, pid_2;
	int status_1, status_2;

	if (pipe(pipefd) == -1) {
		perror("pipe failed");
		return false;
	}

	// First command
	pid_1 = fork();

	if (pid_1 < 0) {
		perror("fork failed");
		return false;
	}

	else if (pid_1 == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[1]);

		int ret1 = parse_command(cmd1, level + 1, father);
		exit(ret1);
	}

	// Second command
	pid_2 = fork();

	if (pid_2 < 0) {
		perror("fork failed");
		return false;
	}

	else if (pid_2 == 0) {
		close(pipefd[1]);
		dup2(pipefd[0], STDIN_FILENO);
		close(pipefd[0]);

		int ret2 = parse_command(cmd2, level + 1, father);
		exit(ret2);
	}

	close(pipefd[0]);
	close(pipefd[1]);

	waitpid(pid_1, &status_1, 0);
	waitpid(pid_2, &status_2, 0);

	return WIFEXITED(status_2) && WEXITSTATUS(status_2) != 0;

}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{
	/* sanity checks */

	if (c->op == OP_NONE) {
		/* Execute a simple command. */
		return parse_simple(c->scmd, level, c);
	}

	switch (c->op) {
	case OP_SEQUENTIAL:
		/* Execute the commands one after the other. */
		parse_command(c->cmd1, level + 1, c);
		return parse_command(c->cmd2, level + 1, c);

	case OP_PARALLEL:
		/* Execute the commands simultaneously. */
		return run_in_parallel(c->cmd1, c->cmd2, level, c);
		

	case OP_CONDITIONAL_NZERO:
		/* Execute the second command only if the first one
		 * returns non zero.
		 */
		int r1 = parse_command(c->cmd1, level + 1, c);
		if (r1 != 0) {
			return parse_command(c->cmd2, level + 1, c);
		}
		return r1;

	case OP_CONDITIONAL_ZERO:
		/* Execute the second command only if the first one
		 * returns zero.
		 */
		int r2 = parse_command(c->cmd1, level + 1, c);
		if (r2 == 0) {
			return parse_command(c->cmd2, level + 1, c);
		}
		return r2;

	case OP_PIPE:
		/*  Redirect the output of the first command to the
		 * input of the second.
		 */
		return run_on_pipe(c->cmd1, c->cmd2, level, c);

	default:
		return SHELL_EXIT;
	}

	return 1; /*  Replace with actual exit code of command. */
}
