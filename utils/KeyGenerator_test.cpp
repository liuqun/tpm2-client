/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.
#include <cstdio>
#include <cstdlib>
using namespace std;

#include <sapi/tpm20.h>
#include <tcti/tcti_socket.h>

/* 自定义函数 */
static void DoMyTestsWithTctiContext(TSS2_TCTI_CONTEXT *pTctiContext);
static void DoMyTestsWithSysContext(TSS2_SYS_CONTEXT *pSysContext);

extern "C"
{

int DebugPrintf(printf_type type, const char *format, ...);
int DebugPrintfCallback(void *data, printf_type type, const char *format, ...);

void DebugPrintBuffer(printf_type type, UINT8 *command_buffer, UINT32 cnt1);
int DebugPrintBufferCallback(void *data, printf_type type, UINT8 *buffer,
        UINT32 length);

TSS2_RC InitSocketTctiContext(const TCTI_SOCKET_CONF *conf,
        TSS2_TCTI_CONTEXT **ppTctiContext);
void TeardownTctiContext(TSS2_TCTI_CONTEXT **ppTctiContext);

} /* End of extern "C" */

/* 排版格式: 以下函数均使用4个空格缩进，不使用Tab缩进 */

static void PrintHelp()
{
    printf("用法:\n");
    printf("-rmhost 手动指定运行资源管理器(即 resourcemgr)的主机IP地址或主机名 (默认值: %s)\n",
            DEFAULT_HOSTNAME);
    printf("-rmport 手动指定运行资源管理器的主机端口号 (默认值: %d)\n", DEFAULT_RESMGR_TPM_PORT);
}

int main(int argc, char *argv[])
{
    TSS2_RC rval;
    TCTI_SOCKET_CONF rmInterfaceConfig;
    TSS2_TCTI_CONTEXT *pTctiContext;
    int count;

    rmInterfaceConfig.hostname = DEFAULT_HOSTNAME;
    rmInterfaceConfig.port = DEFAULT_RESMGR_TPM_PORT;
    rmInterfaceConfig.logCallback = DebugPrintfCallback;
    rmInterfaceConfig.logBufferCallback = DebugPrintBufferCallback;
    rmInterfaceConfig.logData = NULL;

    count = 1;
    while (count < argc)
    {
        if (0 == strcmp(argv[count], "-rmhost"))
        {
            if (count + 1 >= argc)
            {
                PrintHelp();
                return 1;
            }
            rmInterfaceConfig.hostname = argv[count + 1];  // 暂时不检查无效的输入参数
            count += 2;
        }
        else if (0 == strcmp(argv[count], "-rmport"))
        {
            if (count + 1 >= argc)
            {
                PrintHelp();
                return 1;
            }
            rmInterfaceConfig.port = strtoul(argv[count + 1], NULL, 10); // 暂时不检查无效的输入参数
            count += 2;
        }
        else
        {
            PrintHelp();
            return -1;
        }
    }
    // 以上代码提供了一组简单的命令行参数便于调试:
    // 其中包括 [-rmhost IP地址] 和 [-rmport 端口号]
    // 如果不指定命令行参数, 则会直接连接到本机 IP 地址默认端口上运行的资源管理器

    /**/
    rval = InitSocketTctiContext(&rmInterfaceConfig, &pTctiContext);
    if (rval != TSS2_RC_SUCCESS)
    {
        // Note:
        // 当前 InitSocketTcti() 返回的 TSS2_RC 值并未严格按照 TPM2.0 规范指示错误原因。
        // 错误返回值实测结果: 无法连接服务器端 IP 地址或默认端口号无法建立套接字时, 返回值均等于 1
        DebugPrintf(NO_PREFIX,
                "TCTI context initialization failed with error return code=0x%x\n",
                rval);
        return (-1);
    }
    else if (!pTctiContext)
    {
        DebugPrintf(NO_PREFIX, "TCTI context initialization failed\n");
        return (-1);
    }

    /* 使用前面创建的 TCTI 上下文对象进一步创建其他测试内容 */
    DoMyTestsWithTctiContext(pTctiContext);

    /* 测试结束后销毁 TCTI 上下文对象 */
    TeardownTctiContext(&pTctiContext);
    return (0);
}

static void DoMyTestsWithTctiContext(TSS2_TCTI_CONTEXT *pTctiContext)
{
    TSS2_RC rval;
    TSS2_ABI_VERSION abiVersion;
    TSS2_SYS_CONTEXT *pSysContext;
    size_t contextSize;

    contextSize = Tss2_Sys_GetContextSize(0);
    pSysContext = (TSS2_SYS_CONTEXT *) malloc(contextSize);
    if (!pSysContext)
    {
        DebugPrintf(NO_PREFIX,
                "Unable to allocate enough memory: malloc() failed.\n");
        DebugPrintf(NO_PREFIX, "Exiting...\n");
        return;
    }

    abiVersion.tssCreator = TSSWG_INTEROP;
    abiVersion.tssFamily = TSS_SAPI_FIRST_FAMILY;
    abiVersion.tssLevel = TSS_SAPI_FIRST_LEVEL;
    abiVersion.tssVersion = TSS_SAPI_FIRST_VERSION;

    rval = Tss2_Sys_Initialize(pSysContext, contextSize, pTctiContext,
            &abiVersion);

    if (rval != TSS2_RC_SUCCESS)
    {
        free(pSysContext);
        DebugPrintf(NO_PREFIX,
                "Unable to initialize system level API context:");
        DebugPrintf(NO_PREFIX,
                "Tss2_Sys_Initialize() returns error code 0x%06X.\n", rval);
        DebugPrintf(NO_PREFIX, "Exiting...\n");
        return;
    }

    DoMyTestsWithSysContext(pSysContext);

    /* Clean up the context when all tests ends */
    Tss2_Sys_Finalize(pSysContext);
    free(pSysContext);
    pSysContext = NULL;
    return;
}

static void DoMyTestsWithSysContext(TSS2_SYS_CONTEXT *pSysContext)
{

}

/* 调试专用函数 */
#include <stdarg.h>

extern "C"
{

int DebugPrintf(printf_type type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    if (type == RM_PREFIX)
    {
        printf("||  ");
    }
    va_start(args, format);
    rval = vprintf(format, args);
    va_end(args);

    return rval;
}

int DebugPrintfCallback(void *data, printf_type type, const char *format, ...)
{
    va_list args;
    int rval = 0;

    if (type == RM_PREFIX)
    {
        DebugPrintfCallback(data, NO_PREFIX, "||  ");
    }
    va_start(args, format);
    rval = vprintf(format, args);
    va_end(args);

    return rval;
}

void DebugPrintBuffer(printf_type type, UINT8 *buffer, UINT32 length)
{
    UINT32 i;

    for (i = 0; i < length; i++)
    {
        if ((i % 16) == 0)
        {
            DebugPrintf(NO_PREFIX, "\n");
            if (type == RM_PREFIX)
            {
                DebugPrintf(NO_PREFIX, "||  ");
            }
        }

        DebugPrintf(NO_PREFIX, "%2.2x ", buffer[i]);
    }
    DebugPrintf(NO_PREFIX, "\n\n");
    fflush (stdout);
}

int DebugPrintBufferCallback(void *data, printf_type type, UINT8 *buffer,
        UINT32 length)
{
    DebugPrintBuffer(type, buffer, length);
    return 0;
}

} /* End of extern "C" */
/* End of 调试专用函数 */

/* 自定义: 对TCTI底层接口进行的封装 */
extern "C"
{

static size_t GetSocketTctiContextSize()
{
    TCTI_SOCKET_CONF emptyConf;
    const uint8_t noSeverSockets = 0;
    size_t size;
    TSS2_RC err;

    err = InitSocketTcti(NULL, &size, &emptyConf, noSeverSockets);
    if (err)
    {
        fprintf(stderr,
                "Error: Failed to fetch size of TSS2_TCTI_CONTEXT from libtcti-socket\n");
        fprintf(stderr, "(This error should NEVER happen)\n");
        exit(0);
    }
    return size;
}

TSS2_RC InitSocketTctiContext(const TCTI_SOCKET_CONF *conf,
        TSS2_TCTI_CONTEXT **tcti_context)
{
    size_t size;

    size = GetSocketTctiContextSize();
    *tcti_context = (TSS2_TCTI_CONTEXT *) malloc(size);
    return InitSocketTcti(*tcti_context, &size, conf, 0);
}

void TeardownTctiContext(TSS2_TCTI_CONTEXT **tctiContext)
{
    if (*tctiContext != NULL)
    {
        tss2_tcti_finalize(*tctiContext);
        free(*tctiContext);
        *tctiContext = NULL;
    }
}

} /* End of extern "C" */
/* End of 自定义: 对TCTI底层接口进行的封装 */
