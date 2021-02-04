#ifndef TCTI_UTIL_H
#define TCTI_UTIL_H

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tcti_mssim.h>

#ifdef __cplusplus
extern "C" {
#endif

TSS2_RC InitSocketTctiContext (const char  *device_conf,
                               TSS2_TCTI_CONTEXT      **tcti_context);
void TeardownTctiContext(TSS2_TCTI_CONTEXT **tctiContext);

#ifdef __cplusplus
} /* extern "C" */
#endif
#endif /* TCTI_UTIL_H */
