#define PARSE_INT(var)				\
	tok = strtok(NULL, " ");		\
	if (!tok)				\
		goto invalid_command;		\
	if (!sscanf(tok, "%d ", &var))		\
		goto invalid_command;

#define PARSE_UINT(var)				\
	tok = strtok(NULL, " ");		\
	if (!tok)				\
		goto invalid_command;		\
	if (!sscanf(tok, "%u ", &var))		\
		goto invalid_command;

#define PARSE_STR(var)				\
	tok = strtok(NULL, " ");		\
	if (!tok)				\
		goto invalid_command;		\
	var = tok;
