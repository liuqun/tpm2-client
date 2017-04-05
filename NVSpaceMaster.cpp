// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <stdint.h>
#include <time.h>

#include "NVSpaceMaster.h"
#include "ResponseCodeResolver.h"

NVSpaceMaster::NVSpaceMaster()
{
    this->pSysContext = NULL;
}

const char* NVSpaceMaster::GetErrMsgOfTPMResponseCode(TPM_RC rval)
{
    const char *msg = "";
    ResponseCodeResolver *pResolver =
            (ResponseCodeResolver *) new NVSpaceRelatedResponseCodeResolver();

    pResolver->setResponseCode(rval);
    msg = pResolver->msg();
    delete pResolver;
    return msg;
}

void NVSpaceMaster::defineNVSpaceWithPassword(TPMI_RH_NV_INDEX nvIndex,
        const char *password, uint16_t dataSize)
{
    if (!this->pSysContext)
    {
        return;
    }

    /* 设置如何定义 NV 空间的参数 */
    TPM2B_NV_PUBLIC publicInfo;

    publicInfo.t.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH)
            + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);
    publicInfo.t.nvPublic.nvIndex = nvIndex;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;
    memset(&(publicInfo.t.nvPublic.attributes), 0x00,
            sizeof(publicInfo.t.nvPublic.attributes));
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHREAD = 1;  // 定义读NV数据时是否需要授权
    publicInfo.t.nvPublic.attributes.TPMA_NV_AUTHWRITE = 1;  // 定义写NV数据时是否需要授权
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_ORDERLY = 1;
    publicInfo.t.nvPublic.authPolicy.t.size = 0;
    publicInfo.t.nvPublic.dataSize = dataSize;

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输入参数 TSS2_SYS_CMD_AUTHS */
    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdAuths[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;

    cmdAuth.sessionHandle = TPM_RS_PW;
    memset(&(cmdAuth.sessionAttributes), 0x00, sizeof(cmdAuth.sessionAttributes));
    cmdAuth.nonce.t.size = 0;
    cmdAuth.hmac.t.size = 0;
    cmdAuths[0] = &cmdAuth;
    cmdAuthsArray.cmdAuthsCount = 1;
    cmdAuthsArray.cmdAuths = cmdAuths;

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输出参数 TSS2_SYS_RSP_AUTHS  */
    TPMS_AUTH_RESPONSE rspAuth;
    TPMS_AUTH_RESPONSE *rspAuths[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;

    memset(&rspAuth, 0x00, sizeof(rspAuth));
    rspAuths[0] = &rspAuth;
    rspAuthsArray.rspAuthsCount = 1;
    rspAuthsArray.rspAuths = rspAuths;

    /* 指定密码 */
    TPM2B_AUTH auth;  // auth.t.buffer[] 在这里用于保存 password 明文

    auth.t.size = strlen(password);
    if (auth.t.size > sizeof(auth.t.buffer))
    {
        throw "password too long!";
    }
    memcpy(auth.t.buffer, password, auth.t.size);

    /* System API 函数调用 */
    TPM_RC rval = Tss2_Sys_NV_DefineSpace(pSysContext, TPM_RH_PLATFORM,
            &cmdAuthsArray, &auth, &publicInfo, &rspAuthsArray);

    /* 退出之前擦除内存中的密码副本 */
    if (auth.t.size > 0)
    {
        srand(time(NULL));
        for (int i = 0; i < auth.t.size; i++)
        {
            auth.t.buffer[i] = (0xFF & rand());
        }
        auth.t.size = 0;
    }

    /* 抛出错误信息字符串 */
    if (rval)
    {
        throw GetErrMsgOfTPMResponseCode(rval);
    }
}

void NVSpaceMaster::undefineNVSpace(TPMI_RH_NV_INDEX nvIndex)
{
    if (!this->pSysContext)
    {
        return;
    }

    /* 创建以下结构体作为 Tss2_Sys_NV_UndefineSpace() 的输入参数 TSS2_SYS_CMD_AUTHS */
    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdAuths[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;

    cmdAuth.sessionHandle = TPM_RS_PW;
    memset(&(cmdAuth.sessionAttributes), 0x00, sizeof(cmdAuth.sessionAttributes));
    cmdAuth.nonce.t.size = 0;
    cmdAuth.hmac.t.size = 0;
    cmdAuths[0] = &cmdAuth;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    /* System API 函数调用 */
    TPM_RC rval = Tss2_Sys_NV_UndefineSpace(pSysContext, TPM_RH_PLATFORM,
            nvIndex, &cmdAuthsArray, NULL);
    /* 检查返回值 */
    if (rval)
    {
        throw GetErrMsgOfTPMResponseCode(rval);
    }
}

void NVSpaceMaster::defineNVSpaceWithoutPassword(TPMI_RH_NV_INDEX nvIndex,
        uint16_t dataSize)
{
    if (!this->pSysContext)
    {
        return;
    }

    /* 设置如何定义 NV 空间的参数 */
    TPM2B_NV_PUBLIC publicInfo;

    publicInfo.t.size = sizeof(TPMI_RH_NV_INDEX) + sizeof(TPMI_ALG_HASH)
            + sizeof(TPMA_NV) + sizeof(UINT16) + sizeof(UINT16);
    publicInfo.t.nvPublic.nvIndex = nvIndex;
    publicInfo.t.nvPublic.nameAlg = TPM_ALG_SHA1;
    memset(&(publicInfo.t.nvPublic.attributes), 0x00,
            sizeof(publicInfo.t.nvPublic.attributes));
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPREAD = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PPWRITE = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_WRITE_STCLEAR = 1;
    publicInfo.t.nvPublic.attributes.TPMA_NV_PLATFORMCREATE = 1;
    publicInfo.t.nvPublic.authPolicy.t.size = 0;
    publicInfo.t.nvPublic.dataSize = dataSize;

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输入参数 TSS2_SYS_CMD_AUTHS */
    TPMS_AUTH_COMMAND cmdAuth;
    TPMS_AUTH_COMMAND *cmdAuths[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;

    cmdAuth.sessionHandle = TPM_RS_PW;
    cmdAuth.nonce.t.size = 0;
    cmdAuth.hmac.t.size = 0;
    memset(&(cmdAuth.sessionAttributes), 0x00, sizeof(cmdAuth.sessionAttributes));
    cmdAuths[0] = &cmdAuth;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    /* 创建以下结构体作为 Tss2_Sys_NV_DefineSpace() 的输出参数 TSS2_SYS_RSP_AUTHS  */
    TPMS_AUTH_RESPONSE rspAuth;
    TPMS_AUTH_RESPONSE *rspAuths[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;

    memset(&rspAuth, 0x00, sizeof(rspAuth));
    rspAuths[0] = &rspAuth;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = 1;

    /* 指定密码 */
    TPM2B_AUTH auth;
    auth.t.size = 0;  // 不需要密码

    /* System API 函数调用 */
    TPM_RC rval = Tss2_Sys_NV_DefineSpace(pSysContext, TPM_RH_PLATFORM,
            &cmdAuthsArray, &auth, &publicInfo, &rspAuthsArray);

    /* 退出之前擦除内存中的密码副本 */
    if (auth.t.size > 0)
    {
        srand(time(NULL));
        for (int i = 0; i < auth.t.size; i++)
        {
            auth.t.buffer[i] = (0xFF & rand());
        }
        auth.t.size = 0;
    }

    /* 抛出异常 */
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
 * 推荐写法如下: NVSpaceMaster, GetErrMsgOfTPMResponseCode()
 * C++ 函数名尽量不使用下划线, 推荐使用 namespace 取代下划线命名方式
 */
