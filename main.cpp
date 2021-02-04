/* encoding: utf-8 */  // 使用 UTF-8 汉字编码
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
using namespace std;

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tpm2_types.h>

#include "tcti_util.h"
#include "ResponseCodeResolver.h"
#include "NVSpaceMaster.h"
/*
 * longest possible conf string:
 * HOST_NAME_MAX + max char uint16 (5) + strlen ("host=,port=") (11)
 */
#define TCTI_MSSIM_CONF_MAX (256 + 16)
#define TCTI_MSSIM_DEFAULT_HOST "localhost"
#define TCTI_MSSIM_DEFAULT_PORT 2321
#define MSSIM_CONF_DEFAULT_INIT { \
    .host = TCTI_MSSIM_DEFAULT_HOST, \
    .port = TCTI_MSSIM_DEFAULT_PORT, \
}

#if !defined(DEFAULT_HOSTNAME) && !defined(DEFAULT_RESMGR_TPM_PORT)
const char DEFAULT_HOSTNAME[] = TCTI_MSSIM_DEFAULT_HOST;
const uint16_t DEFAULT_RESMGR_TPM_PORT = TCTI_MSSIM_DEFAULT_PORT;
#endif

//#define TCTI_MSSIM_MAGIC 0xf05b04cd9f02728dULL

typedef struct {
    const char *host;
    uint16_t port;
} mssim_conf_t;


/* 自定义函数 */
static void DoMyTestsWithTctiContext(TSS2_TCTI_CONTEXT *pTctiContext);
static void DoMyTestsWithSysContext(TSS2_SYS_CONTEXT *pSysContext);

int main()
{
    TSS2_RC rval;
    TSS2_TCTI_CONTEXT *pTctiContext;

    /**/
    rval = InitSocketTctiContext("host=localhost,port=2321", &pTctiContext);
    if (rval != TSS2_RC_SUCCESS)
    {
        // Note:
        // 当前 InitSocketTcti() 返回的 TSS2_RC 值并未严格按照 TPM2.0 规范指示错误原因。
        // 错误返回值实测结果: 无法连接服务器端 IP 地址或默认端口号无法建立套接字时, 返回值均等于 1
        printf("TCTI context initialization failed with error return code=0x%x\n",
                rval);
        return (-1);
    }
    else if (!pTctiContext)
    {
        printf("TCTI context initialization failed\n");
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
        printf("Unable to allocate enough memory: malloc() failed.\n");
        printf("Exiting...\n");
        return;
    }

    abiVersion.tssCreator = 1;//TSSWG_INTEROP;
    abiVersion.tssFamily = 1;//TSS_SAPI_FIRST_FAMILY;
    abiVersion.tssLevel = 1;//TSS_SAPI_FIRST_LEVEL;
    abiVersion.tssVersion = 1;//TSS_SAPI_FIRST_VERSION;

    rval = Tss2_Sys_Initialize(pSysContext, contextSize, pTctiContext,
            &abiVersion);

    if (rval != TSS2_RC_SUCCESS)
    {
        free(pSysContext);
        printf("Unable to initialize system level API context:");
        printf("Tss2_Sys_Initialize() returns error code 0x%06X.\n", rval);
        printf("Exiting...\n");
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
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray;

    sessionData.sessionHandle = TPM2_RS_PW;
    sessionData.nonce.size = 0;
    sessionData.hmac.size = 0;
    sessionData.sessionAttributes = 0;
    cmdAuthsArray.count = 1;
    cmdAuthsArray.auths[0] = sessionData;

    /* 执行第 1 次写入操作 */
    TPM2B_MAX_NV_BUFFER data1;
    data1.size = 26;
    for (int i = 0; i < data1.size; i++)
    {
        data1.buffer[i] = 'a' + i; // 26个小写英文字母表作为测试数据
    }
    TPM2_RC rc1write = Tss2_Sys_NV_Write(pSysContext, TPM2_RH_PLATFORM,
            NV_INDEX_WITHOUT_PASSWORD, &cmdAuthsArray, &data1, 0, NULL);
    if (rc1write)
    {
        printf("Write ERROR: rc1write=0x%X\n", rc1write);
    }
    else
    {
        printf("Write success\n");
    }
    /* 执行第 1 次读取操作 */
    TPM2B_MAX_NV_BUFFER data1Out;
    data1Out.size = sizeof(TPM2B_MAX_NV_BUFFER) - 2;
    TPM2_RC rc1read = Tss2_Sys_NV_Read(pSysContext, TPM2_RH_PLATFORM,
            NV_INDEX_WITHOUT_PASSWORD, &cmdAuthsArray, data1.size, 0,
            &data1Out, NULL);
    if (rc1read)
    {
        printf("Read ERROR: rc1read=0x%X\n", rc1read);
    }
    else
    {
        char str[100];
        int len;
        len = sizeof(str) - 1;
        if (data1Out.size < len)
        {
            len = data1Out.size;
        }
        memcpy(str, data1Out.buffer, len);
        str[len] = '\0';  // 补填字符串结束符号
        printf("Read success: dataOut=%s\n", str);
    }

    /* 执行第 2 次写入操作 */
    TPM2B_MAX_NV_BUFFER data;
    data.size = 26;
    for (int i = 0; i < data.size; i++)
    {
        data.buffer[i] = 'A' + i; // 26个大写英文字母表作为测试数据
    }
    TPM2_RC rc2write = Tss2_Sys_NV_Write(pSysContext, TPM2_RH_PLATFORM,
            NV_INDEX_WITHOUT_PASSWORD, &cmdAuthsArray, &data, 0, NULL);
    if (rc2write)
    {
        printf("Write ERROR: rc2write=0x%X\n", rc2write);
    }
    else
    {
        printf("Write success\n");
    }
    /* 执行第 2 次读取操作 */
    TPM2B_MAX_NV_BUFFER dataOut;
    dataOut.size = sizeof(TPM2B_MAX_NV_BUFFER) - 2;
    TPM2_RC rc2read = Tss2_Sys_NV_Read(pSysContext, TPM2_RH_PLATFORM,
            NV_INDEX_WITHOUT_PASSWORD, &cmdAuthsArray, data.size, 0, &dataOut,
            NULL);
    if (rc2read)
    {
        printf("Read ERROR: rc2read=0x%X\n", rc2read);
    }
    else
    {
        char str[100];
        int len;
        len = sizeof(str) - 1;
        if (dataOut.size < len)
        {
            len = dataOut.size;
        }
        memcpy(str, dataOut.buffer, len);
        str[len] = '\0';  // 补填字符串结束符号
        printf("Read success: dataOut=%s\n", str);
    }

    master.undefineNVSpace(NV_INDEX_WITHOUT_PASSWORD);  // 测试结束时清除之前定义的 NV 区域

    /*
     *
     */
    printf("Next: Define password protected NV Space\n");

    const TPMI_RH_NV_INDEX NV_INDEX = 0x01500020;
    const char password[] = "My password";
    TPM2B_MAX_NV_BUFFER nvWriteData;
    nvWriteData.size = 2;
    for (int i = 0; i < nvWriteData.size; i++)
    {
        nvWriteData.buffer[i] = i + 1;
    }

    printf(            "Try to invoke NV_DefineSpace() with password=\"%s\"\n", password);
    try
    {
        master.defineNVSpaceWithPassword(NV_INDEX, password,
                nvWriteData.size);  // 定义一块 NV 区域用于测试

        printf("NV_DefineSpace() successfully.\n");
        printf("Next: Try to write an read with this NV index(=0x%08X)\n",
                NV_INDEX);

        /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输入参数 TSS2_SYS_CMD_AUTHS */
        TPMS_AUTH_COMMAND cmdAuth;
        TSS2L_SYS_AUTH_COMMAND cmdAuthsArray;

        cmdAuth.sessionHandle = TPM2_RS_PW;
        cmdAuth.nonce.size = 0;
        cmdAuth.hmac.size = strlen(password);
        memcpy(cmdAuth.hmac.buffer, password, cmdAuth.hmac.size);
        memset(&(cmdAuth.sessionAttributes), 0x00,
                sizeof(cmdAuth.sessionAttributes));
        cmdAuthsArray.count = 1;
        cmdAuthsArray.auths[0] = cmdAuth;

        /* 执行第 1 次写入操作 */
        TPM2_RC rc1passwd;
        rc1passwd = Tss2_Sys_NV_Write(pSysContext, NV_INDEX, NV_INDEX,
                &cmdAuthsArray, &nvWriteData, 0, NULL);
        if (rc1passwd)
        {
            printf("Write ERROR: %s\n",
                    GetErrMsgOfTPMResponseCode(rc1passwd));
        }
        else
        {
            printf("Write success: input data={ ");
            for (int i = 0; i < nvWriteData.size; i++)
            {
                printf("0x%02X, ",
                        0xFF & nvWriteData.buffer[i]);
            }
            printf("}\n");
        }
        /* 执行第 1 次读取操作 */
        TPM2B_MAX_NV_BUFFER dataOut1passwd;
        dataOut1passwd.size = sizeof(TPM2B_MAX_NV_BUFFER) - 2;
        rc1passwd = Tss2_Sys_NV_Read(pSysContext, NV_INDEX, NV_INDEX,
                &cmdAuthsArray, nvWriteData.size, 0, &dataOut1passwd,
                NULL);
        if (rc1passwd)
        {
            printf("Read ERROR: %s\n",
                    GetErrMsgOfTPMResponseCode(rc1passwd));
        }
        else
        {
            int len = dataOut1passwd.size;
            printf("Read success: output data={ ");
            for (int i = 0; i < len; i++)
            {
                printf("0x%02X, ",
                        0xFF & dataOut1passwd.buffer[i]);
            }
            printf("}\n");
        }
        /* 执行第 2 次读取操作, 使用错误密码 */
        const char *wrongPassword = "wrong passwd";
        cmdAuth.hmac.size = strlen(wrongPassword);
        memcpy(cmdAuth.hmac.buffer, wrongPassword, cmdAuth.hmac.size);
        TPM2_RC rc2passwd;
        TPM2B_MAX_NV_BUFFER dataOut2passwd;
        dataOut2passwd.size = sizeof(TPM2B_MAX_NV_BUFFER) - 2;
        rc2passwd = Tss2_Sys_NV_Read(pSysContext, NV_INDEX, NV_INDEX,
                &cmdAuthsArray, nvWriteData.size, 0, &dataOut2passwd,
                NULL);
        if (rc2passwd)
        {
            printf("Read ERROR: %s\n",
                    GetErrMsgOfTPMResponseCode(rc2passwd));
        }
        else
        {
            int len = dataOut2passwd.size;
            printf("Read success: output data={ ");
            for (int i = 0; i < len; i++)
            {
                printf("0x%02X, ",
                        0xFF & dataOut2passwd.buffer[i]);
            }
            printf("}\n");
        }
        master.undefineNVSpace(NV_INDEX);  // 测试结束时清除之前定义的 NV 区域
        printf("NV_UndefineSpace() successfully. The end.\n");
    } catch (const char *ErrMsg)
    {
        printf("Error: %s\n", ErrMsg);
    }

    /*
     * TODO: Add more tests here
     */

    return;
}
