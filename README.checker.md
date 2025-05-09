# Using the Checker

Use the automated infrastructure to check and grade the assignment.
This uses a Docker container to build the solution and to build and run the tests.
Using a Docker container provides two benefits:

1. it uses a given stable setup;
   no need to worry about different versions

1. it provides an isolated environment that can be easily created and destroyed

The Docker container and the checking can be done:

- **locally**, through the use of the `local.sh` script
- **remote** using GitLab pipelines, by doing a push in the remote repository

Entries in the repository:

- `checker/`: the high-level checker script (`checker.sh`)
- `tests/`: actual tests used to grade the assignment, called by `checker.sh`
- `src/`: initial assignment skeleton that is to be filled with the solution
- `Dockerfile`: used to construct the container used to build and test the assignment
- `local.sh`: script for local management of the Docker container, also for pushing it to the remote registry
- `CPPLINT.cfg`, `.shellcheckrc`, `.checkpatch.conf`: linter configuration files

Full instructions on using the checker are part of the [VMChecker Student Handbook](https://github.com/systems-cs-pub-ro/vmchecker-next/wiki/Student-Handbook).

## Working on the Assignment

To work on the assignment follow the instructions in `README.md`.
You need to enter the `src/` directory and update the source code files.

While working on the assignment, run the checker to see if certain tests work, and they are graded.

Do frequent Git commits with your changes to make sure you have a history of your work.

## Local Checker

For a local run, you need to have Docker installed.
See instructions [here](https://docs.docker.com/engine/install/).

To run the checker locally inside a Docker container, use the `local.sh` script.

First, build the container:

```console
$ ./local.sh docker build
[2023-03-28T19:59:52] [INFO] Building Docker image...
[...]
Successfully tagged gitlab.cs.pub.ro:5050/operating-systems/assignment-[...]:latest
```

And now run the checker inside the container:

```console
./local.sh checker
```

Note that checking typically consists of two steps:

1. Run the actual tests in the `tests/` directory and grade the assignment.

1. Run linter steps on the solution (and tests) and provide an output.
   For maximum grade, assignments must remove all warnings and errors from linters.
