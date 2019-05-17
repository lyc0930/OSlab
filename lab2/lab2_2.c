#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
int main()
{
	char CommandLine[256];
	char *Command, *CommandDivider = NULL;
	char *Argv[20], *ArgvDivider;
	char *SubCommand[2], *PipeDivider = NULL;
	int CommandNumber = 0;
	int i;
	int status;
	pid_t pid;
	while (1)
	{
		printf("OSLab2->");
		//读取一行字符串并根据“;”将其划分成若干个子命令
		fgets(CommandLine, 256, stdin);
		*(strchr(CommandLine, '\n')) = ';';
		for (Command = strtok_r(CommandLine, ";", &CommandDivider); Command; Command = strtok_r(NULL, ";", &CommandDivider))
		{
			// printf("%s\n", Command);
			if (strchr(Command, '|')) //处理包含一个管道符号“|”的情况,利用popen处理命令的输入输出转换
			{
				SubCommand[0] = strtok_r(CommandLine, "|", &PipeDivider);
				SubCommand[1] = strtok_r(NULL, "|", &PipeDivider);
				FILE *Fp_0 = popen(SubCommand[0], "r");
				FILE *Fp_1 = popen(SubCommand[1], "w");
				char buffer[256];
				while (fgets(buffer, 256, Fp_0))
				{
					if (fputs(buffer, Fp_1) == EOF)
						printf("Output ERROR!");
				}
				pclose(Fp_0);
				pclose(Fp_1);
			}
			else //通常的情况,利用fork创建子进程并执行命令
			{
				for (; *Command == ' '; Command++)
					;
				for (i = 0, Argv[0] = strtok_r(Command, " ", &ArgvDivider); Argv[i]; Argv[++i] = strtok_r(NULL, " ", &ArgvDivider))
					;
				if ((pid = fork()) < 0)
				{
					printf("Fork ERROR!\n");
					return (-1);
				}
				else if (pid == 0)
				{
					execvp(Argv[0], Argv);
					exit(0);
				}
				if (waitpid(pid, &status, 0) == -1)
					printf("Wait ERROR!\n");
				// else if (WIFEXITED(status))
				// 	return (WEXITSTATUS(status));
			}
		}
	}
	return (0);
}