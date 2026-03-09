#define W 4
#define X 1

static inline int w(int f, const void *b, unsigned long l) {
	register int r0 asm("r0") = f;
	register const void *r1 asm("r1") = b;
	register unsigned long r2 asm("r2") = l;
	register int r7 asm("r7") = W;
	asm volatile("svc 0" : "+r"(r0) : "r"(r1), "r"(r2), "r"(r7) : "memory");
	return r0;
}

static inline void x(int c) {
	register int r0 asm("r0") = c;
	register int r7 asm("r7") = X;
	asm volatile("svc 0" :: "r"(r0), "r"(r7));
	__builtin_unreachable();
}

static const char m[] = "Should I trust this binary?\n";

void main(void) {
	w(1, m, sizeof(m) - 1);
	x(0);
}
