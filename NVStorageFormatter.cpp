#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include "NVStorageFormatter.h"
#include "ResponseCodeResolver.h"

NVStorageFormatter::NVStorageFormatter()
{
    this->pSysContext = NULL;
}

const char* NVStorageFormatter::GetErrMsgOfTPMResponseCode(TPM2_RC rval)
{
    const char *msg = "";
    ResponseCodeResolver *pResolver =
            (ResponseCodeResolver *) new NVSpaceRelatedResponseCodeResolver();

    pResolver->setResponseCode(rval);
    msg = pResolver->msg();
    delete pResolver;
    return msg;
}

void NVStorageFormatter::defineNVSpaceWithPassword(TPMI_RH_NV_INDEX nvIndex,
        const char *password, uint16_t dataSize)
{
    if (!this->pSysContext)
    {
        throw "Uninitialized Context!";
    }

    /* 设置如何定义 NV 空间的参数 */
    TPM2B_NV_PUBLIC publicInfo;

    publicInfo.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH)
            + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);
    publicInfo.nvPublic.nvIndex = nvIndex;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;
    publicInfo.nvPublic.attributes =
            TPMA_NV_AUTHREAD  // 定义读NV数据时是否需要授权
            |TPMA_NV_AUTHWRITE  // 定义写NV数据时是否需要授权
            |TPMA_NV_PLATFORMCREATE
            |TPMA_NV_ORDERLY;
    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = dataSize;

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输入参数 */
    TPMS_AUTH_COMMAND cmdAuth;
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray;

    cmdAuth.sessionHandle = TPM2_RS_PW;
    memset(&(cmdAuth.sessionAttributes), 0x00, sizeof(cmdAuth.sessionAttributes));
    cmdAuth.nonce.size = 0;
    cmdAuth.hmac.size = 0;
    cmdAuthsArray.count = 1;
    cmdAuthsArray.auths[0] = cmdAuth;

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输出参数 */
    TPMS_AUTH_RESPONSE rspAuth;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    memset(&rspAuth, 0x00, sizeof(rspAuth));
    rspAuthsArray.count = 1;
    rspAuthsArray.auths[0] = rspAuth;

    /* 指定密码 */
    TPM2B_AUTH auth;  // auth.t.buffer[] 在这里用于保存 password 明文

    auth.size = strlen(password);
    if (auth.size > sizeof(auth.buffer))
    {
        throw "password too long!";
    }
    memcpy(auth.buffer, password, auth.size);

    /* System API 函数调用 */
    TPM2_RC rval = Tss2_Sys_NV_DefineSpace(pSysContext, TPM2_RH_PLATFORM,
            &cmdAuthsArray, &auth, &publicInfo, &rspAuthsArray);

    /* 退出之前擦除内存中的密码副本 */
    if (auth.size > 0)
    {
        srand(time(NULL));
        for (int i = 0; i < auth.size; i++)
        {
            auth.buffer[i] = (0xFF & rand());
        }
        auth.size = 0;
    }

    /* 抛出错误信息字符串 */
    if (rval)
    {
        throw GetErrMsgOfTPMResponseCode(rval);
    }
}

void NVStorageFormatter::undefineNVSpace(TPMI_RH_NV_INDEX nvIndex)
{
    if (!this->pSysContext)
    {
        throw "Uninitialized Context!";
    }

    /* 创建以下结构体作为 Tss2_Sys_NV_UndefineSpace() 的输入参数 */
    TPMS_AUTH_COMMAND cmdAuth;
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray;

    cmdAuth.sessionHandle = TPM2_RS_PW;
    memset(&(cmdAuth.sessionAttributes), 0x00, sizeof(cmdAuth.sessionAttributes));
    cmdAuth.nonce.size = 0;
    cmdAuth.hmac.size = 0;
    cmdAuthsArray.auths[0] = cmdAuth;
    cmdAuthsArray.count = 1;

    /* System API 函数调用 */
    TPM2_RC rval = Tss2_Sys_NV_UndefineSpace(pSysContext, TPM2_RH_PLATFORM,
            nvIndex, &cmdAuthsArray, NULL);
    /* 检查返回值 */
    if (rval)
    {
        throw GetErrMsgOfTPMResponseCode(rval);
    }
}

void NVStorageFormatter::defineNVSpaceWithoutPassword(TPMI_RH_NV_INDEX nvIndex,
        uint16_t dataSize)
{
    if (!this->pSysContext)
    {
        throw "Uninitialized Context!";
    }

    /* 设置如何定义 NV 空间的参数 */
    TPM2B_NV_PUBLIC publicInfo;

    publicInfo.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH)
            + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);
    publicInfo.nvPublic.nvIndex = nvIndex;
    publicInfo.nvPublic.nameAlg = TPM2_ALG_SHA1;
    publicInfo.nvPublic.attributes =
            TPMA_NV_PPREAD
            |TPMA_NV_PPWRITE
            |TPMA_NV_PLATFORMCREATE
            |TPMA_NV_WRITE_STCLEAR;
    publicInfo.nvPublic.authPolicy.size = 0;
    publicInfo.nvPublic.dataSize = dataSize;

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输入参数 */
    TPMS_AUTH_COMMAND cmdAuth;
    TSS2L_SYS_AUTH_COMMAND cmdAuthsArray;

    cmdAuth.sessionHandle = TPM2_RS_PW;
    cmdAuth.nonce.size = 0;
    cmdAuth.hmac.size = 0;
    memset(&(cmdAuth.sessionAttributes), 0x00, sizeof(cmdAuth.sessionAttributes));
    cmdAuthsArray.auths[0] = cmdAuth;
    cmdAuthsArray.count = 1;

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输出参数 */
    TPMS_AUTH_RESPONSE rspAuth;
    TSS2L_SYS_AUTH_RESPONSE rspAuthsArray;

    memset(&rspAuth, 0x00, sizeof(rspAuth));
    rspAuthsArray.auths[0] = rspAuth;
    rspAuthsArray.count = 1;

    /* 指定密码 */
    TPM2B_AUTH auth;
    auth.size = 0;  // 不需要密码

    /* System API 函数调用 */
    TPM2_RC rval = Tss2_Sys_NV_DefineSpace(pSysContext, TPM2_RH_PLATFORM,
            &cmdAuthsArray, &auth, &publicInfo, &rspAuthsArray);

    /* 退出之前擦除内存中的密码副本 */
    if (auth.size > 0)
    {
        srand(time(NULL));
        for (int i = 0; i < auth.size; i++)
        {
            auth.buffer[i] = (0xFF & rand());
        }
        auth.size = 0;
    }

    /* 抛出异常 */
    if (0x0100 == rval)
    {
        const char *FatalErrorMessage =
            "This TPM chip or simulator has not been initialized!\n"
            "A TPM2_Startup() commmand MUST be performed before doing anything else.";
        fprintf(stderr, "Error 0x%04X: %s\n", rval, FatalErrorMessage);
    }
    if (rval)
    {
        throw GetErrMsgOfTPMResponseCode(rval);
    }
}

/*
 * [附录]代码维护和排版建议:
 *
 * 1. 缩进对齐:
 * 函数统一使用 4 个空格缩进，尽量不要使用 Tab 键与空格键混合的缩进排版
 * (记事本下默认 Tab=8 会引起混乱)
 *
 * 2. 换行: 大括号另起一行并且不额外增加缩进. 尽量不要把左大括号放在行末
 * 尽量使用 C++ 的构造函数代替 C 结构体初始化赋值语句, 避免行末出现大括号
 *
 * 3. 大小写以及下划线命名原则:
 * 驼峰写法中出现缩略词(例如 USB, NVRAM, TPM 等)时, 缩略词尽量保持全大写, 避免出现 Usb, Nvram, Tpm 形式的写法
 * 推荐写法如下: NVStorageFormatter, GetErrMsgOfTPMResponseCode()
 * C++ 函数名尽量不使用下划线, 推荐使用 namespace 取代下划线命名方式
 */
