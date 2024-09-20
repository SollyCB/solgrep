#define SOL_DEF
#include "../solh/sol.h"

#define DBG_INFO
#define pr_impl(t, ...)                                                        \
({                                                                             \
	print("[%s %s] ", #t, __FUNCTION__);                                   \
	println(__VA_ARGS__);                                                  \
})

#define pr_if_impl(e, t, ...)                                                  \
({                                                                             \
	if (e) {                                                               \
		print("[%s %s] ", #t, __FUNCTION__);                           \
 		println(__VA_ARGS__);                                          \
	}                                                                      \
})

#ifdef DBG_INFO
#define pr_err(...)        pr_impl(ERR,  __VA_ARGS__)
#define pr_info(...)       pr_impl(INFO, __VA_ARGS__)
#define pr_err_if(e, ...)  pr_if_impl(e, ERR,  __VA_ARGS__)
#define pr_info_if(e, ...) pr_if_impl(e, INFO, __VA_ARGS__)
#elif DBG_ERR
#define pr_err(...)        pr_impl(ERR,  __VA_ARGS__)
#define pr_err_if(e, ...)  pr_if_impl(e, ERR,  __VA_ARGS__)
#define pr_info(...)
#define pr_info_if(e, ...)
#else
#define pr_err(...)
#define pr_info(...)
#define pr_err_if(e, ...)
#define pr_info_if(e, ...)
#endif


string test_ptns[] = {
	{.cstr = "h*llo",  .len = strlen("h*llo")},
	{.cstr = "h*",     .len = strlen("h*")},
	{.cstr = "h*o",    .len = strlen("h*o")},
	{.cstr = "*o",     .len = strlen("*o")},
	{.cstr = "*llo",   .len = strlen("*llo")},
	{.cstr = ".*llo",  .len = strlen(".*llo")},
	{.cstr = "he.+o",  .len = strlen("he.+o")},
	{.cstr = "he.*o",  .len = strlen("he.*o")},
	{.cstr = ".e.*o",  .len = strlen(".e.*o")},
	{.cstr = "...*.",  .len = strlen("...*.")},
	{.cstr = "...*",   .len = strlen("...*")},

	/* I am actually not sure what is correct for a patterns like these */
	{.cstr = "...*..",  .len = strlen("...*..")},
	{.cstr = "...*.o", .len = strlen("...*.o")},
	{.cstr = "...*...",  .len = strlen("...*...")},
};

string test_strs[] = {
	{.cstr = "hello", .len = strlen("hello")},
};

typedef struct set { long s[2]; } set_t;

struct context {
	int          pos;
	string       str;
	string_array fnd;
	allocator    alloc;
} ptn;

struct match {
	set_t set;
	int   min;
	int   max;
} mtc;

static inline int getmask(char c)
{
	return c >> 6;
}

static inline int getbit(char c)
{
	return c & 63;
}

static inline int set_len(void)
{
	return (int)memblen(set_t, s);
}

static inline void setclr(set_t *set)
{
	memset(set, 0, sizeof(*set));
}

static inline void setadd(set_t *set, set_t *new)
{
	for(int i=0; i < set_len(); ++i)
		set->s[i] |= new->s[i];
}

static inline void setadd_numchars(set_t *set)
{
	/*
	 * This could be done faster by shifting, but I am also kind of
	 * assuming that the compiler will completely change this code
	 * anyway since it can statically see everything.
	 */
	for(char c='0'; c <= '9'; ++c)
		set->s[getmask(c)] |= 1UL << getbit(c);
}

static inline void setadd_char(set_t *set, char c)
{
	set->s[getmask(c)] |= 1UL << getbit(c);
}

static inline void setrm(set_t *set, set_t *new)
{
	for(int i=0; i < set_len(); ++i)
		set->s[i] &= ~(new->s[i]);
}

static inline void setrm_char(set_t *set, char c)
{
	set->s[getmask(c)] &= ~(1UL << getbit(c));
}

static inline void setinv(set_t *set)
{
	for(int i=0; i < set_len(); ++i)
		set->s[i] = ~set->s[i];
}

static inline void setadd_all(set_t *set)
{
	memset(set->s, 0xff, sizeof(*set));
}

static inline void setadd_allbut(set_t *set, char c)
{
	setadd_all(set);
	setrm_char(set, c);
}

static inline bool set_has(set_t *set, char c)
{
	return set->s[getmask(c)] & (1UL << getbit(c));
}

static inline bool is_numchar(char c)
{
	return '0' <= c && c <= '9';
}

static inline int skip(const char *str, set_t *set)
{
	int i = 0;

	while (set_has(set, str[i]))
		i++;
	return i;
}

static inline int skip_safe(const char *str, int len, set_t *set)
{
	int i = 0;

	while(set_has(set, str[i]))
		if (++i >= len)
			return -1;
	return i;
}

static inline int skip_char(const char *str, char c)
{
	set_t set = {0};

	setadd_char(&set, c);
	return skip(str, &set);
}

static inline int skip_char_safe(const char *str, int len, char c)
{
	set_t set = {0};

	setadd_char(&set, c);
	return skip_safe(str, len, &set);
}

static inline int skip_numchars(const char *str)
{
	set_t set = {0};

	setadd_numchars(&set);
	return skip(str, &set);
}

static inline int find(const char *str, set_t *set)
{
	setinv(set);
	return skip(str, set);
}

static inline int find_safe(const char *str, int len, set_t *set)
{
	setinv(set);
	return skip_safe(str, len, set);
}

static inline int find_no_interrupt_safe(const char *str, int len,
		                         set_t *good, set_t *bad)
{
	int g = 0;
	int b = 0;

	g = find_safe(str, len, good);
	b = find_safe(str, len, bad);
	return g < b ? g : -1;
}

static inline int find_char(const char *str, char c)
{
	set_t set = {0};

	setadd_allbut(&set, c);
	return skip(str, &set);
}

static inline int find_numchar(const char *str)
{
	set_t set = {0};

	setadd_numchars(&set);
	setinv(&set);
	return skip(str, &set);
}

static inline int to_int(const char *str) {
	int ret = 0;
 	for(int i=0; str[i] >= '0' && str[i] <= '9'; ++i)
		ret = ret * 10 + str[i] - '0';
	return ret;
}

void bksl(void)
{
	switch(ptn.str.cstr[++ptn.pos]) {
	case 'd':
		setadd_numchars(&mtc.set);
		break;
	case 'D':
		setadd_numchars(&mtc.set);
		setinv(&mtc.set);
		break;
	default:
		setadd_char(&mtc.set, ptn.str.cstr[ptn.pos]);
		break;
	}
}

#define ALL 0x7fffffff

void fstp(void)
{
	ptn.pos++;
	setadd_all(&mtc.set);
}

void astk(void)
{
	ptn.pos++;
	mtc.max = ALL;
	mtc.min = 0;
}

void plus(void)
{
	ptn.pos++;
	mtc.max = ALL;
	mtc.min = 1;
}

void ques(void)
{
	ptn.pos++;
	mtc.max = 1;
	mtc.min = 0;
}

void curl(void)
{
	set_t set = {0};

	++ptn.pos;
	ptn.pos += skip_char(ptn.str.cstr + ptn.pos, ' ');
	mtc.min = to_int(ptn.str.cstr + ptn.pos);

	setadd_char(&set, ',');
	setadd_char(&set, '}');
	ptn.pos += find(ptn.str.cstr + ptn.pos, &set);

	if (ptn.str.cstr[ptn.pos++] == '}') {
		mtc.max = mtc.min;
		return;
	}

	setadd_numchars(&set);
	ptn.pos += find(ptn.str.cstr + ptn.pos, &set);

	if (ptn.str.cstr[ptn.pos] == '}') {
		mtc.max = ALL;
		ptn.pos++;
		return;
	}

	mtc.max = to_int(ptn.str.cstr + ptn.pos);
	ptn.pos += find_char(ptn.str.cstr + ptn.pos, '}') + 1;
}

static inline void reset_mtc(void)
{
	pr_info("resetting match config");
	mtc.min = 1;
	mtc.max = 1;
	setclr(&mtc.set);
}

bool match(string *str, int *pos)
{
	int i = 0;
	bool res = 0;

	pr_info("matching - min %i, max %i, set %uh %uh",
		mtc.min, mtc.max, mtc.set.s[1], mtc.set.s[0]);

	if (mtc.max == ALL) {
		if (ptn.pos >= (int)ptn.str.len) {
			res = true;
			*pos = str->len;
			goto out;
		}
		if (ptn.str.cstr[ptn.pos] == '.')
			setclr(&mtc.set);
		else
			setrm_char(&mtc.set, ptn.str.cstr[ptn.pos]);
	}

	for(i=0; i < mtc.min; ++i)
		if (!set_has(&mtc.set, str->cstr[*pos + i])) {
			res = false;
			goto out;
		}
	res = true;
	*pos += i;
	pr_info("passed min test, pos is at %i", *pos);

	if ((int)str->len - *pos <= mtc.max)  {
		*pos += skip(str->cstr + *pos, &mtc.set);
		res = true;
		goto out;
	}

	mtc.max -= i;
	for(i=0; i < mtc.max; ++i)
		if (!set_has(&mtc.set, str->cstr[*pos + i])) {
			*pos += i;
			res = true;
			goto out;
		}
out:
	pr_info("passed max test, pos is at %i", *pos);
	pr_info("returning %s", res ? "true" : "false");
	reset_mtc();
	return res;
}

static inline void set_ext(set_t *set)
{
	setadd_char(set, '*'); setadd_char(set, '+'); setadd_char(set, '[');
	setadd_char(set, '{'); setadd_char(set, '?');
}

static inline void set_escapable(set_t *set)
{
	setadd_char(set, '*'); setadd_char(set, '+'); setadd_char(set, '[');
	setadd_char(set, '{'); setadd_char(set, '?'); setadd_char(set, '$');
	setadd_char(set, '^'); setadd_char(set, '\\');
	setadd_char(set, '<'); setadd_char(set, '>');
}

static inline void set_ext_escapable(set_t *set)
{
	setadd_char(set, '*'); setadd_char(set, '+'); setadd_char(set, '[');
	setadd_char(set, '{'); setadd_char(set, '?'); setadd_char(set, '$');
	setadd_char(set, '^'); setadd_char(set, '\\');
}

static inline void set_ext_invalid_if_escaped(set_t *set)
{
	setadd_char(set, '<'); setadd_char(set, '>');
}

bool valid_esc(void)
{
	set_t set = {0};
	bool b = 0;

	if (++ptn.pos >= (int)ptn.str.len) {
		pr_err("invalid escape sequence - escape character at end of line");
		return false;
	}

	set_escapable(&set);
	setinv(&set);
	b = set_has(&set, ptn.str.cstr[ptn.pos++]);
	pr_err_if(!b, "invalid escape sequence - char '%c' at position %i cannot be escaped",
		  ptn.pos, ptn.str.cstr[ptn.pos]);
	return b;
}

bool valid_ext(void)
{
	set_t ext = {0};
	set_t esc = {0};
	char c = 0;
	char e = 0;

	if (ptn.pos == 0) {
		pr_err("invalid pattern - first char is extension char");
		return false;
	}

	set_ext_escapable(&ext);
	set_ext_invalid_if_escaped(&esc);

	if (!set_has(&ext, c) && !set_has(&esc, c))
		goto success;
	if (set_has(&ext, c) && ptn.pos < 2)
		goto fail;
	if (set_has(&esc, c) && ptn.pos < 2)
		goto success;

	c = ptn.str.cstr[ptn.pos-1];
	e = ptn.str.cstr[ptn.pos-2];

	if (set_has(&ext, c) && e == '\\')
		goto success;
	if (set_has(&esc, c) && e != '\\')
		goto success;

success:
	ptn.pos++;
	return true;
fail:
	pr_err("invalid pattern - extension char with un-escaped special char at pos %i, char '%c'",
		ptn.pos, ptn.str.cstr[ptn.pos]);
	return false;
}

bool valid_curl(void)
{
	set_t num = {0};
	set_t clo = {0};

	ptn.pos += 1;
	ptn.pos += skip_char_safe(ptn.str.cstr + ptn.pos,
			          ptn.str.len - ptn.pos, ' ');

	setadd_numchars(&num);
	if (!set_has(&num, ptn.str.cstr[ptn.pos]))
		goto fail;

	ptn.pos += skip_safe(ptn.str.cstr + ptn.pos,
			     ptn.str.len - ptn.pos, &num);
	ptn.pos += skip_char_safe(ptn.str.cstr + ptn.pos,
			          ptn.str.len - ptn.pos, ' ');

	setadd_char(&clo, ',');
	setadd_char(&clo, '}');
	if (!set_has(&clo, ptn.str.cstr[ptn.pos]))
		goto fail;
	if (ptn.str.cstr[ptn.pos] == '}')
		goto success;

	ptn.pos += 1;
	ptn.pos += skip_char_safe(ptn.str.cstr + ptn.pos,
			          ptn.str.len - ptn.pos, ' ');
	ptn.pos += skip_safe(ptn.str.cstr + ptn.pos,
			     ptn.str.len - ptn.pos, &num);
	ptn.pos += skip_char_safe(ptn.str.cstr + ptn.pos,
			          ptn.str.len - ptn.pos, ' ');

	if (ptn.str.cstr[ptn.pos] != '}')
		goto fail;

success:
	ptn.pos++;
	return true;
fail:
	pr_err("invalid pattern - curl at pos %i, char %c is not a valid format",
		ptn.pos, ptn.str.cstr[ptn.pos]);
	return false;
}

bool valid(void)
{
	int i = 0;

	pr_info("validating pattern %s", ptn.str.cstr);
	for(i=0; i < (int)ptn.str.len; ++i) {
		switch(ptn.str.cstr[ptn.pos]) {
		case '\\':
			if (!valid_esc())
				goto invalid;
			break;
		case '*':
		case '+':
		case '?':
			if (!valid_ext())
				goto invalid;
			break;
		case '{':
			if (!valid_curl())
				goto invalid;
			break;
		case '[':
			pr_err("'[' is unimplemented");
			break;
		default:
			break;
		}
	}
	pr_info("pattern is valid");
	return true;
invalid:
	pr_err("got invalid pattern, returning false");
	return false;
}

bool parse(string *str)
{
	set_t con = {0};
	int pos = 0;

	set_ext(&con);
	reset_mtc();

	pr_info("beginning string '%s'", str->cstr);
	while(ptn.pos < (int)ptn.str.len) {
		if (pos >= (int)str->len) {
			pr_info("returning false - no chars left in string");
			return false;
		}
		pr_info("beginning of loop: pattern char is '%c', string char is '%c'",
			ptn.str.cstr[ptn.pos], str->cstr[pos]);
		pr_info("beginning of loop: set is %uh %uh",
			mtc.set.s[1], mtc.set.s[0]);
		pr_info("pattern pos %i, string pos %i", ptn.pos, pos);
		switch(ptn.str.cstr[ptn.pos]) {
		case '\\':
			pr_info("bksl");
			bksl();
			break;
		case '.':
			pr_info("fstp");
			fstp();
			break;
		case '*':
			pr_info("asterisk");
			astk();
			break;
		case '+':
			pr_info("plus");
			plus();
			break;
		case '?':
			pr_info("question");
			ques();
			break;
		case '{':
			break;
		default:
			pr_info("default");
			setadd_char(&mtc.set, ptn.str.cstr[ptn.pos++]);
			break;
		}

		pr_info("end of loop: pattern char is '%c', string char is '%c'",
			ptn.str.cstr[ptn.pos], str->cstr[pos]);
		pr_info("end of loop: set is %uh %uh",
			mtc.set.s[1], mtc.set.s[0]);

		if (ptn.pos < (int)ptn.str.len &&
		    set_has(&con, ptn.str.cstr[ptn.pos]))
		{
			pr_info("next char extends, not matching yet");
			continue;
		}

		if (!match(str, &pos)) {
			pr_info("returning false - match failed");
			return false;
		}
	}
	return true;
}

#define INITBUFLEN 5136
#define INITARRLEN 256

int init_ptn(string *str)
{
	if (!str)
		goto invalid;

	pr_info("pattern %s", str->cstr);
	memset(&ptn, 0, sizeof(ptn));
	memcpy(&ptn.str, str, sizeof(*str));

	if (!valid())
		goto invalid;

	ptn.fnd = new_strarr(INITBUFLEN, INITARRLEN, NULL);
	return 0;
invalid:
	pr_err("invalid pattern");
	return -1;
}

void free_ptn(void)
{
	free_strarr(&ptn.fnd);
}

int main() {
	string_array vp = new_strarr(64, 64, NULL);
	for(int i=0; i < (int)carrlen(test_ptns); ++i) {
		if (init_ptn(&test_ptns[i]) < 0)
			continue;
		for(int j=0; j < (int)carrlen(test_strs); ++j)
			if (parse(&test_strs[j])) {
				strarr_add(&ptn.fnd, &test_strs[j]);
				strarr_add(&vp, &test_ptns[i]);
			}
		free_ptn();
	}
	println("\npatterns that match:");
	for(int i=0; i < (int)strarr_len(&vp); ++i)
		print_count_chars_ln(strarr_get(&vp, i).cstr,
				     strarr_get(&vp, i).len);
	return 0;
}
