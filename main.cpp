#include <sapi/tpm20.h>

#include "debug.h"
#include "tcti_util.h"


int main(/* int argc, char **argv */)
{
    TSS2_RC rval;
    TCTI_SOCKET_CONF rmInterfaceConfig = {
        DEFAULT_HOSTNAME,
        DEFAULT_RESMGR_TPM_PORT,
        DebugPrintfCallback,
        DebugPrintBufferCallback,
        NULL
    };
    TSS2_TCTI_CONTEXT *pTctiContext;
    TSS2_TCTI_CONTEXT **ppTctiContext = &pTctiContext;

    rval = InitSocketTctiContext(&rmInterfaceConfig, ppTctiContext);
    if (rval != TSS2_RC_SUCCESS)
    {
        DebugPrintf(NO_PREFIX, "initialization failed: rval=0x%x.  Exiting...\n", rval);
	return (-1);
    }

    /*
     * TODO: Add more tests here
     */

    return (0);
}


