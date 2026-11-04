__attribute__((noinline)) int hepta_leaf(int value) { return value * 7 + 11; }
__attribute__((noinline)) int hepta_caller(int value) { return hepta_leaf(value) + 5; }
int main(int argc, char **argv) { return hepta_caller(argc); }
