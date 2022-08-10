#include <stdint.h>
#include <stdbool.h>

static inline __forceinline void WaitForInterrupt() {
	#if defined(_M_X64) || defined(_M_IX86)
	__halt();
	#elif defined(_M_ARM) || defined(_M_ARM64)
	__wfi();
	#else
	#error "Unsupported architecture"
	#endif
}

uint32_t PocMain(void** FunctionTableOut, void** FunctionTableIn) {
	// We don't want to return back to the boot application.
	while (1) WaitForInterrupt();
	return 0xC00000BBL; // STATUS_NOT_SUPPORTED
}