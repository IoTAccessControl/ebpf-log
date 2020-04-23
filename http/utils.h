// tiny glibc

static __always_inline int mstrlen(u8 *b2) {
	for (int i = 0; i < 100;  i++) {
		if ((char) b2[i] == 0) {
			return i;
		}
	}
	return 0;
}

static __always_inline int mstrcmp(u8 *b1, u8 *b2, int n) {
	for (int i = 0; i < n; i++) {
		if (b1[i] == 0 || b2[i] == 0) {
			return 1;
		}
		if ((char ) b1[i] != (char) b2[i]) {
			return 0;
		}
	}
	return 1;
}