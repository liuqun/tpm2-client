/* encoding: utf-8 */  // 使用 UTF-8 汉字编码
#ifndef __cplusplus // 调用 C stdio.h 等标准库
# include <stdio.h>
# include <stdlib.h>
# include <ctype.h>
#else
# include <cstdio>
# include <cstdlib>
# include <cctype>
using namespace std;
#endif

#include <sapi/tpm20.h>

#include "debug.h"
#include "tcti_util.h"
#include "ResponseCodeResolver.h"
#include "NVSpaceMaster.h"

/* 自定义函数 */
static void DoMyTestsWithTctiContext(TSS2_TCTI_CONTEXT *pTctiContext);
static void DoMyTestsWithSysContext(TSS2_SYS_CONTEXT *pSysContext);

/* 以下函数均使用4个空格缩进，不使用Tab缩进 */

static void PrintHelp()
{
    const char *version = "0.01";

    printf("My TPM client test app, Version %s\n", version);
    printf("用法:\n");
    printf("tpmclient [-rmhost hostname|IP address] [-rmport port]\n\n");
    printf("其中:\n");
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
    /*
     * Test1:
     */
    class NVSpaceMaster master;
    master.pSysContext = pSysContext;

    const TPMI_RH_NV_INDEX NV_INDEX_WITHOUT_PASSWORD = 0x01500015;
    const uint16_t NV_SPACE_SIZE = 32;
    master.defineNVSpaceWithoutPassword(NV_INDEX_WITHOUT_PASSWORD, NV_SPACE_SIZE);

    /* 创建以下结构体作为 Write(), Read() 的输入参数 TSS2_SYS_CMD_AUTHS */
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_COMMAND *sessionDataArray[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    *((UINT8 *) ((void *) &sessionData.sessionAttributes)) = 0;
    sessionDataArray[0] = &sessionData;
    cmdAuthsArray.cmdAuths = &sessionDataArray[0];
    cmdAuthsArray.cmdAuthsCount = 1;

    /* 执行第 1 次写入操作 */
    TPM2B_MAX_NV_BUFFER data1;
    data1.t.size = 26;
    for (int i = 0; i < data1.t.size; i++)
    {
        data1.t.buffer[i] = 'a' + i; // 26个小写英文字母表作为测试数据
    }
    TPM_RC rc1write = Tss2_Sys_NV_Write(pSysContext, TPM_RH_PLATFORM,
            NV_INDEX_WITHOUT_PASSWORD, &cmdAuthsArray, &data1, 0, NULL);
    if (rc1write)
    {
        DebugPrintf(NO_PREFIX, "Write ERROR: rc1write=0x%X\n", rc1write);
    }
    else
    {
        DebugPrintf(NO_PREFIX, "Write success\n");
    }
    /* 执行第 1 次读取操作 */
    TPM2B_MAX_NV_BUFFER data1Out;
    data1Out.t.size = sizeof(TPM2B_MAX_NV_BUFFER) - 2;
    TPM_RC rc1read = Tss2_Sys_NV_Read(pSysContext, TPM_RH_PLATFORM,
            NV_INDEX_WITHOUT_PASSWORD, &cmdAuthsArray, data1.t.size, 0,
            &data1Out, NULL);
    if (rc1read)
    {
        DebugPrintf(NO_PREFIX, "Read ERROR: rc1read=0x%X\n", rc1read);
    }
    else
    {
        char str[100];
        int len;
        len = sizeof(str) - 1;
        if (data1Out.t.size < len)
        {
            len = data1Out.t.size;
        }
        memcpy(str, data1Out.t.buffer, len);
        str[len] = '\0';  // 补填字符串结束符号
        DebugPrintf(NO_PREFIX, "Read success: dataOut=%s\n", str);
    }

    /* 执行第 2 次写入操作 */
    TPM2B_MAX_NV_BUFFER data;
    data.t.size = 26;
    for (int i = 0; i < data.t.size; i++)
    {
        data.t.buffer[i] = 'A' + i; // 26个大写英文字母表作为测试数据
    }
    TPM_RC rc2write = Tss2_Sys_NV_Write(pSysContext, TPM_RH_PLATFORM,
            NV_INDEX_WITHOUT_PASSWORD, &cmdAuthsArray, &data, 0, NULL);
    if (rc2write)
    {
        DebugPrintf(NO_PREFIX, "Write ERROR: rc2write=0x%X\n", rc2write);
    }
    else
    {
        DebugPrintf(NO_PREFIX, "Write success\n");
    }
    /* 执行第 2 次读取操作 */
    TPM2B_MAX_NV_BUFFER dataOut;
    dataOut.t.size = sizeof(TPM2B_MAX_NV_BUFFER) - 2;
    TPM_RC rc2read = Tss2_Sys_NV_Read(pSysContext, TPM_RH_PLATFORM,
            NV_INDEX_WITHOUT_PASSWORD, &cmdAuthsArray, data.t.size, 0, &dataOut,
            NULL);
    if (rc2read)
    {
        DebugPrintf(NO_PREFIX, "Read ERROR: rc2read=0x%X\n", rc2read);
    }
    else
    {
        char str[100];
        int len;
        len = sizeof(str) - 1;
        if (dataOut.t.size < len)
        {
            len = dataOut.t.size;
        }
        memcpy(str, dataOut.t.buffer, len);
        str[len] = '\0';  // 补填字符串结束符号
        DebugPrintf(NO_PREFIX, "Read success: dataOut=%s\n", str);
    }

    master.undefineNVSpace(NV_INDEX_WITHOUT_PASSWORD);  // 测试结束时清除之前定义的 NV 区域

    /*
     *
     */
    DebugPrintf(NO_PREFIX, "Next: Define password protected NV Space\n");

    const TPMI_RH_NV_INDEX NV_INDEX = 0x01500020;
    const char password[] = "My password";
    TPM2B_MAX_NV_BUFFER nvWriteData;
    nvWriteData.t.size = 2;
    for (int i = 0; i < nvWriteData.t.size; i++)
    {
        nvWriteData.t.buffer[i] = i + 1;
    }

    DebugPrintf(NO_PREFIX,
            "Try to invoke NV_DefineSpace() with password=\"%s\"\n", password);
    try
    {
        master.defineNVSpaceWithPassword(NV_INDEX, password,
                nvWriteData.t.size);  // 定义一块 NV 区域用于测试

        DebugPrintf(NO_PREFIX, "NV_DefineSpace() successfully.\n");
        DebugPrintf(NO_PREFIX,
                "Next: Try to write an read with this NV index(=0x%08X)\n",
                NV_INDEX);

        /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输入参数 TSS2_SYS_CMD_AUTHS */
        TPMS_AUTH_COMMAND cmdAuth;
        TPMS_AUTH_COMMAND *cmdAuths[1];
        TSS2_SYS_CMD_AUTHS cmdAuthsArray;

        cmdAuth.sessionHandle = TPM_RS_PW;
        cmdAuth.nonce.t.size = 0;
        cmdAuth.hmac.t.size = strlen(password);
        memcpy(cmdAuth.hmac.t.buffer, password, cmdAuth.hmac.t.size);
        memset(&(cmdAuth.sessionAttributes), 0x00,
                sizeof(cmdAuth.sessionAttributes));
        cmdAuths[0] = &cmdAuth;
        cmdAuthsArray.cmdAuths = cmdAuths;
        cmdAuthsArray.cmdAuthsCount = 1;

        /* 执行第 1 次写入操作 */
        TPM_RC rc1passwd;
        rc1passwd = Tss2_Sys_NV_Write(pSysContext, NV_INDEX, NV_INDEX,
                &cmdAuthsArray, &nvWriteData, 0, NULL);
        if (rc1passwd)
        {
            DebugPrintf(NO_PREFIX, "Write ERROR: %s\n",
                    GetErrMsgOfTPMResponseCode(rc1passwd));
        }
        else
        {
            DebugPrintf(NO_PREFIX, "Write success: input data={ ");
            for (int i = 0; i < nvWriteData.t.size; i++)
            {
                DebugPrintf(NO_PREFIX, "0x%02X, ",
                        0xFF & nvWriteData.t.buffer[i]);
            }
            DebugPrintf(NO_PREFIX, "}\n");
        }
        /* 执行第 1 次读取操作 */
        TPM2B_MAX_NV_BUFFER dataOut1passwd;
        dataOut1passwd.t.size = sizeof(TPM2B_MAX_NV_BUFFER) - 2;
        rc1passwd = Tss2_Sys_NV_Read(pSysContext, NV_INDEX, NV_INDEX,
                &cmdAuthsArray, nvWriteData.t.size, 0, &dataOut1passwd,
                NULL);
        if (rc1passwd)
        {
            DebugPrintf(NO_PREFIX, "Read ERROR: %s\n",
                    GetErrMsgOfTPMResponseCode(rc1passwd));
        }
        else
        {
            int len = dataOut1passwd.t.size;
            DebugPrintf(NO_PREFIX, "Read success: output data={ ");
            for (int i = 0; i < len; i++)
            {
                DebugPrintf(NO_PREFIX, "0x%02X, ",
                        0xFF & dataOut1passwd.t.buffer[i]);
            }
            DebugPrintf(NO_PREFIX, "}\n");
        }
        /* 执行第 2 次读取操作, 使用错误密码 */
        const char *wrongPassword = "wrong passwd";
        cmdAuth.hmac.t.size = strlen(wrongPassword);
        memcpy(cmdAuth.hmac.t.buffer, wrongPassword, cmdAuth.hmac.t.size);
        TPM_RC rc2passwd;
        TPM2B_MAX_NV_BUFFER dataOut2passwd;
        dataOut2passwd.t.size = sizeof(TPM2B_MAX_NV_BUFFER) - 2;
        rc2passwd = Tss2_Sys_NV_Read(pSysContext, NV_INDEX, NV_INDEX,
                &cmdAuthsArray, nvWriteData.t.size, 0, &dataOut2passwd,
                NULL);
        if (rc2passwd)
        {
            DebugPrintf(NO_PREFIX, "Read ERROR: %s\n",
                    GetErrMsgOfTPMResponseCode(rc2passwd));
        }
        else
        {
            int len = dataOut2passwd.t.size;
            DebugPrintf(NO_PREFIX, "Read success: output data={ ");
            for (int i = 0; i < len; i++)
            {
                DebugPrintf(NO_PREFIX, "0x%02X, ",
                        0xFF & dataOut2passwd.t.buffer[i]);
            }
            DebugPrintf(NO_PREFIX, "}\n");
        }
        master.undefineNVSpace(NV_INDEX);  // 测试结束时清除之前定义的 NV 区域
        DebugPrintf(NO_PREFIX, "NV_UndefineSpace() successfully. The end.\n");
    } catch (const char *ErrMsg)
    {
        DebugPrintf(NO_PREFIX, "Error: %s\n", ErrMsg);
    }

    /*
     * TODO: Add more tests here
     */

    return;
}
