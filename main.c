#define SOL_DEF
#include "../solh/sol.h"

#define DBG_INFO
#define pr_impl(t, ...)                                                        \
({                                                                             \
	print("[%s %s] ", #t, __FUNCTION__); println(__VA_ARGS__);             \
})

#ifdef DBG_INFO
#define pr_err(...)  pr_impl(ERR,  __VA_ARGS__)
#define pr_info(...) pr_impl(INFO, __VA_ARGS__)
#elif DBG_ERR
#define pr_err(...) pr_impl(ERR,  __VA_ARGS__)
#define pr_info(...)
#else
#define pr_err(...)
#define pr_info(...)
#endif


string test_ptns[] = {
	{.cstr = "h*llo", .len = strlen("h*llo")},
	{.cstr = "h*", .len = strlen("h*")},
	{.cstr = "h*o", .len = strlen("h*o")},
	{.cstr = "*o", .len = strlen("*o")},
	{.cstr = "*llo", .len = strlen("*llo")},
};

string test_strs[] = {
	{.cstr = "hello", .len = strlen("hello")},
};

struct {
	int          pos; // These will be arrays of len THREAD_COUNT
	string       ptn;
	string_array fnd;
	allocator    alloc;
} ctx;

#define INITBUFLEN 5136
#define INITARRLEN 256

int init_ctx(string *ptn)
{
	if (!ptn) {
		pr_err("invalid pattern");
		return -1;
	}
	pr_info("pattern %s", ptn->cstr);
	memset(&ctx, 0, sizeof(ctx));
	memcpy(&ctx.ptn, ptn, sizeof(*ptn));
	ctx.fnd = new_strarr(INITBUFLEN, INITARRLEN, &ctx.alloc);
	return 0;
}

void free_ctx(void)
{
	free_strarr(&ctx.fnd);
}

bool match_any(string *str, int *pos)
{
	if (++ctx.pos >= ctx.ptn.len)
		return true;
	while(*pos < str->len)
		if (str->cstr[(*pos)++] == ctx.ptn.cstr[ctx.pos]) {
			ctx.pos++;
			return true;
		}
	pr_info("false - '%c', %i", str->cstr[*pos-1], *pos-1);
	return false;
}

bool match_char(string *str, int *pos)
{
	pr_info("pattern char '%c', string char '%c'",
		str->cstr[*pos], ctx.ptn.cstr[ctx.pos]);
	return str->cstr[(*pos)++] == ctx.ptn.cstr[ctx.pos++];
}

bool parse(string *str)
{
	int pos = 0;

	pr_info("%s", str->cstr);
	while(ctx.pos < ctx.ptn.len && pos < str->len) {
		pr_info("pattern pos %i, string pos %i", ctx.pos, pos);
		switch(ctx.ptn.cstr[ctx.pos]) {
		case '\\':
			pr_info("backslash"); 
			if (!match_char(str, &pos))
				return false;
			break;
		case '*':
			pr_info("asterisk"); 
			if (!match_any(str, &pos))
				return false;
			break;
		default:
			pr_info("default");
			if (!match_char(str, &pos))
				return false;
			break;
		}
	}

	return true;
}

int main() {
	for(int i=0; i < carrlen(test_ptns); ++i) {
		init_ctx(&test_ptns[i]);
		for(int i=0; i < carrlen(test_strs); ++i)
			if (parse(&test_strs[i]))
				strarr_add(&ctx.fnd, &test_strs[i]);
		for(int i=0; i < strarr_len(&ctx.fnd); ++i)
			print_count_chars_ln(strarr_get(&ctx.fnd, i).cstr,
					     strarr_get(&ctx.fnd, i).len);
		free_ctx();
	}
	return 0;
}
