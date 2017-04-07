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
static void CreateChildNode(TSS2_SYS_CONTEXT *pSysContext, TPM_HANDLE parent, const TPM2B_AUTH *pParentNodeAuth);

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

/**
 * 访问密钥节点公开信息
 */
class KeyPublicDataReadingOperation {
private:
    TPMI_DH_OBJECT keyHandle;
    // 上面的成员变量用于保存输入参数
    // 下面的成员变量用于保存输出结果
    TPM2B_PUBLIC keyPublicData; // 内部包含 TPM 定义的巨型数据结构
    TPM2B_NAME keyName;
    TPM2B_NAME qualifiedName;
    TPM_RC rc;
public:
    KeyPublicDataReadingOperation() {
        keyHandle = (TPM_HANDLE) 0;
        // 输出结果初始化
        keyPublicData.t.size = 0;
        keyName.t.name[0] = '\0'; // Used for debugging
        qualifiedName.t.name[0] = '\0'; // Used for debugging
        rc = TPM_RC_SUCCESS;
    }
    ~KeyPublicDataReadingOperation() {
    }

    /**
     * 通过句柄指定访问的密钥节点, 同时保存相应的访问授权数据
     *
     * @param handle 指定句柄, 取值一般为 0x81 或 0x80 开头
     * @return TPMI_DH_OBJECT 仅用于调试, 返回值总是等于参数列表中指定的句柄
     */
    TPMI_DH_OBJECT setKeyHandle(TPMI_DH_OBJECT handle) {
        this->keyHandle = handle;
        return handle;
    }

    /**
     * 执行 TPM 命令
     */
    void execute(TSS2_SYS_CONTEXT *pSysContext) {
        /* 调用 TPM 命令 */
        keyName.t.size = sizeof(keyName) - sizeof(qualifiedName.t.size);
        qualifiedName.t.size = sizeof(qualifiedName) - sizeof(qualifiedName.t.size);
        rc =  Tss2_Sys_ReadPublic(
                pSysContext,
                keyHandle, // IN
                (TSS2_SYS_CMD_AUTHS *) NULL, // 读取公开数据不需要授权, 另外只有输出参数没有输入参数
                &keyPublicData, // OUT
                &keyName, // OUT
                &qualifiedName, // OUT
                (TSS2_SYS_RSP_AUTHS *) NULL // 回传输出参数时可选择是否加密传输, 但这里可以暂时不实现该选项
                );
        if (rc) {
            // fprintf(stderr, "Error: rc=0x%X\n", rc);
            throw (TSS2_RC) rc;
        }
        return;
    }
    /**
     *
     */
    const TPM2B_NAME& getKeyName() {
        return keyName;
    }
};

static void DoMyTestsWithSysContext(TSS2_SYS_CONTEXT *pSysContext)
{
    TSS2_SYS_CONTEXT *sysContext = pSysContext;

    const TPMI_RH_HIERARCHY hierarchy = TPM_RH_NULL;
    if (TPM_RH_NULL == hierarchy)
    {
        printf("We will create a new key in TPM NULL-hierarchy.\n");
    }

    //printf("命令帧报文的 Authorization Area 字段, sessionHandle=TPM_RS_PW=%08H\n", TPM_RS_PW);
    TPMS_AUTH_COMMAND sessionData;
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = 0;
    memset(&(sessionData.sessionAttributes), 0x00, sizeof(TPMA_SESSION));
    TPMS_AUTH_COMMAND *cmdAuths[1];
    cmdAuths[0] = &sessionData;
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    //printf("设置密钥初始条件(含有密码等敏感数据): \n");
    TPM2B_SENSITIVE_CREATE inSensitive;
    inSensitive.t.size = 0;
    inSensitive.t.sensitive.userAuth.t.size = strlen("abcd");
    inSensitive.t.sensitive.userAuth.t.buffer[0] = 'a';
    inSensitive.t.sensitive.userAuth.t.buffer[1] = 'b';
    inSensitive.t.sensitive.userAuth.t.buffer[2] = 'c';
    inSensitive.t.sensitive.userAuth.t.buffer[3] = 'd';
    if (inSensitive.t.sensitive.userAuth.t.size > 0)
    {
        inSensitive.t.size += sizeof(UINT16) + inSensitive.t.sensitive.userAuth.t.size;
    }
    inSensitive.t.sensitive.data.t.size = 0;
    if (inSensitive.t.sensitive.data.t.size > 0)
    {
        inSensitive.t.size += sizeof(UINT16) + inSensitive.t.sensitive.data.t.size;
    }

    //printf("选择密钥类型和算法: \n");
    TPM2B_PUBLIC inPublic;
    inPublic.t.publicArea.type = TPM_ALG_RSA;
    if (TPM_ALG_RSA == inPublic.t.publicArea.type)
    {
        printf("Key type: RSA.\n");
    }
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
    memset(&(inPublic.t.publicArea.objectAttributes), 0x00, sizeof(UINT32));
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 1;
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic.t.publicArea.authPolicy.t.size = 0;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
    inPublic.t.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_ECB;
    inPublic.t.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    inPublic.t.publicArea.parameters.rsaDetail.keyBits = 2048;
    printf("Key size: %d bits.\n", inPublic.t.publicArea.parameters.rsaDetail.keyBits);
    inPublic.t.publicArea.parameters.rsaDetail.exponent = 0;
    inPublic.t.publicArea.unique.rsa.t.size = 0;

    //printf("其他输入参数\n");
    TPM2B_DATA outsideInfo;
    outsideInfo.t.size = 0;
    TPML_PCR_SELECTION creationPCR;
    creationPCR.count = 0;

    //printf("分别为各个输出参数预分配空间其他输入参数\n");
    TPM_HANDLE handle2048rsa;
    TPM2B_PUBLIC outPublic;
    outPublic.t.size = 0;
    TPM2B_CREATION_DATA creationData;
    creationData.t.size = 0;
    TPM2B_DIGEST creationHash;
    creationHash.t.size = sizeof(creationHash) - sizeof(UINT16);
    TPM2B_NAME keyName;
    keyName.t.size = sizeof(keyName) - sizeof(UINT16);
    TPMT_TK_CREATION creationTicket;
    creationTicket.tag = 0;
    creationTicket.hierarchy = 0x0;
    creationTicket.digest.t.size = sizeof(creationTicket.digest.t.buffer);

    //printf("应答帧报文的 Authorization Area\n");
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *rspAuths[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    rspAuths[0] = &sessionDataOut;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = 1;

    /* 发送 TPM 命令 */
    TPM_RC rc = Tss2_Sys_CreatePrimary(sysContext,
            hierarchy, //
            &cmdAuthsArray, //
            &inSensitive, //
            &inPublic, //
            &outsideInfo, //
            &creationPCR, //
            // 以上为输入参数
            // 以下为输出参数
            &handle2048rsa, //
            &outPublic, //
            &creationData, //
            &creationHash, //
            &creationTicket, //
            &keyName, //
            &rspAuthsArray //
            );
    if (rc)
    {
        fprintf(stderr, "ERROR: rc=0x%X\n", rc);
        if (TSS2_SYS_RC_BAD_VALUE == rc)
        {
            fprintf(stderr, "ERROR: TSS2_SYS_RC_BAD_VALUE=0x%X\n", TSS2_SYS_RC_BAD_VALUE);
        }
        //fprintf(stderr, "%s\n", GetErrMsgOfTPMResponseCode(rc));
        return;
    }
    printf("New key successfully created in NULL hierarchy (RSA 2048).  Handle: 0x%8.8x\n", handle2048rsa);
    printf("keyName.t.size=%d\n", keyName.t.size);
    printf("keyName data: ");
    for (size_t i=0; i<keyName.t.size; i++)
    {
        printf("0x%02X,", keyName.t.name[i]);
    }
    printf("\n");
    int printfNameOfHandle = 1;
    TPM_HANDLE objectHandle = handle2048rsa;
    if (printfNameOfHandle)
    {
        TPM2B_PUBLIC keyInfo; // Fetch the public infomation of the key we created
        TPM2B_NAME name;
        TPM2B_NAME qualifiedName;
        keyInfo.t.size = 0;
        name.t.size = sizeof(TPM2B_NAME) - sizeof(UINT16);
        qualifiedName.t.size = sizeof(TPM2B_NAME) - sizeof(UINT16);

        rc = Tss2_Sys_ReadPublic(sysContext, objectHandle, NULL, &keyInfo, &name, &qualifiedName, NULL);
        if (rc)
        {
            fprintf(stderr, "ERROR: Tss2_Sys_ReadPublic() returns a response code rc=0x%X\n", rc);
            if (TSS2_SYS_RC_BAD_VALUE == rc)
            {
                fprintf(stderr, "ERROR: TSS2_SYS_RC_BAD_VALUE=0x%X\n", TSS2_SYS_RC_BAD_VALUE);
            }
            return;
        }
        printf("Key handle=0x%8.8x\n", objectHandle);
        printf("name.t.size=%d\n", name.t.size);
        printf("Key name data: ");
        for (size_t i=0; i<name.t.size; i++)
        {
            printf("0x%02X,", name.t.name[i]);
        }
        printf("\n");
    }
    CreateChildNode(pSysContext, handle2048rsa, &(inSensitive.t.sensitive.userAuth));
}

static void CreateChildNode(TSS2_SYS_CONTEXT *pSysContext, TPM_HANDLE parent, const TPM2B_AUTH *pParentNodeAuth)
{
    TSS2_SYS_CONTEXT *sysContext = pSysContext;

    const TPMI_DH_OBJECT parentHandle = (const TPMI_DH_OBJECT) parent;
    printf("We will create a child key node under parentHandle(0x%08X).\n",
            parentHandle);

    //printf("访问父节点(句柄=0x%08X)所提供的授权信息\n", parentHandle);
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_COMMAND *cmdAuths[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.sessionAttributes.val = (UINT32) 0;
    sessionData.hmac.t.size = pParentNodeAuth->t.size; // 访问父节点需要填写授权密码
    memcpy(sessionData.hmac.t.buffer, pParentNodeAuth->t.buffer, sessionData.hmac.t.size);
    cmdAuths[0] = &sessionData;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    //printf("设置密钥的敏感数据, 其中包含随意设置的子节点的密码, 仅用于后续功能测试\n");
    TPM2B_SENSITIVE_CREATE  inSensitive;
    inSensitive.t.sensitive.userAuth.t.size = strlen("child");
    inSensitive.t.sensitive.userAuth.t.buffer[0] = 'c';
    inSensitive.t.sensitive.userAuth.t.buffer[1] = 'h';
    inSensitive.t.sensitive.userAuth.t.buffer[2] = 'i';
    inSensitive.t.sensitive.userAuth.t.buffer[3] = 'l';
    inSensitive.t.sensitive.userAuth.t.buffer[3] = 'd';
    if (inSensitive.t.sensitive.userAuth.t.size > 0)
    {
        inSensitive.t.size += sizeof(UINT16) + inSensitive.t.sensitive.userAuth.t.size;
    }
    inSensitive.t.sensitive.data.t.size = 0; // 附加敏感数据, 长度可以为空
    if (inSensitive.t.sensitive.data.t.size > 0)
    {
        inSensitive.t.size += sizeof(UINT16) + inSensitive.t.sensitive.data.t.size;
    }

    //printf("选择密钥类型和算法: \n");
    TPM2B_PUBLIC inPublic;
    inPublic.t.publicArea.type = TPM_ALG_KEYEDHASH;
    if (TPM_ALG_KEYEDHASH == inPublic.t.publicArea.type)
    {
        printf("Key type: Keyed-hashing.\n");
    }
    inPublic.t.publicArea.nameAlg = TPM_ALG_SHA1;
    inPublic.t.publicArea.objectAttributes.val = (UINT32) 0; // 先清空全部标记位, 然后逐个设置
    inPublic.t.publicArea.objectAttributes.fixedTPM = 1;
    inPublic.t.publicArea.objectAttributes.fixedParent = 1;
    inPublic.t.publicArea.objectAttributes.sensitiveDataOrigin = 1;
    inPublic.t.publicArea.objectAttributes.userWithAuth = 1;
    inPublic.t.publicArea.objectAttributes.restricted = 1;
    inPublic.t.publicArea.objectAttributes.decrypt = 0;
    inPublic.t.publicArea.objectAttributes.sign = 1; // 用于签名
    inPublic.t.publicArea.authPolicy.t.size = 0;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM_ALG_HMAC;
    inPublic.t.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM_ALG_SHA1;
    inPublic.t.publicArea.unique.keyedHash.t.size = 0;

    //printf("其他输入参数\n");
    TPM2B_DATA outsideInfo;
    outsideInfo.t.size = 0;
    TPML_PCR_SELECTION creationPCR;
    creationPCR.count = 0;

    //printf("输出参数-1\n");
    TPM2B_PRIVATE outPrivate;
    outPrivate.t.size = sizeof(TPM2B_PRIVATE) - sizeof(UINT16);

    //printf("输出参数-2\n");
    TPM2B_PUBLIC outPublic;
    outPublic.t.size = 0; // 必须被初始化为 0, 否则报错 0x8000B: TSS2_SYS_RC_BAD_VALUE

    //printf("输出参数-3\n");
    TPM2B_CREATION_DATA creationData;
    creationData.t.size = 0; // 必须被初始化为 0, 否则报错 0x8000B: TSS2_SYS_RC_BAD_VALUE

    //printf("输出参数-4\n");
    TPM2B_DIGEST creationHash;
    creationHash.t.size = sizeof(TPM2B_DIGEST) - sizeof(UINT16);

    //printf("输出参数-5\n");
    TPMT_TK_CREATION creationTicket;
    creationTicket.tag = 0;
    creationTicket.hierarchy = 0x0;
    creationTicket.digest.t.size = sizeof(TPM2B_DIGEST) - sizeof(UINT16);

    //printf("输出参数-6\n");
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *rspAuths[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    rspAuths[0] = &sessionDataOut;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = 1;

    UINT32 rc = Tss2_Sys_Create(
            sysContext, //
            parentHandle, //
            &cmdAuthsArray, //
            &inSensitive, //
            &inPublic, //
            &outsideInfo, //
            &creationPCR, //
            // 以上为输入参数
            // 以下为输出参数
            &outPrivate, // 1
            &outPublic, // 2
            &creationData, // 3
            &creationHash, // 4
            &creationTicket, // 5
            &rspAuthsArray // 6
            );
    if (rc)
    {
        fprintf(stderr, "ERROR: %s():%d: Tss2_Sys_Create returns rc=0x%X\n", __func__, __LINE__, rc);
        if (TPM_RC_LOCKOUT == rc)
        {
            fprintf(stderr, "TPM_RC_LOCKOUT=0x%X\n", TPM_RC_LOCKOUT);
            fprintf(stderr, "Wrong password is used for too many times\n");
        }
        return;
    }
    printf("Child key node has been created successfully.\n");
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
