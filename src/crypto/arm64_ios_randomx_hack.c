// this is workaround for linker problem with randomx on ios armv8-a. 
// see https://github.com/tevador/RandomX/issues/153 for more details
void __clear_cache(void* start, void* end) { }
