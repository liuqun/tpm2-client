#include <stdlib.h>
#include "tcti_util.h"

TSS2_RC
InitSocketTctiContext (const char *device_conf,
                       TSS2_TCTI_CONTEXT      **tcti_context)
{
    size_t size;
    TSS2_RC rc;

    rc = Tss2_Tcti_Mssim_Init (NULL, &size, device_conf);
    if (rc != TSS2_RC_SUCCESS)
        return rc;
    *tcti_context = malloc (size);
    return Tss2_Tcti_Mssim_Init (*tcti_context, &size, device_conf);
}

void TeardownTctiContext(TSS2_TCTI_CONTEXT **tctiContext)
{
    if (*tctiContext != NULL) {
        //tss2_tcti_finalize( *tctiContext );
        free (*tctiContext);
        *tctiContext = NULL;
    }
}
