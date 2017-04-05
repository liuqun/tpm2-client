// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

/*
 * TPM 2.0 协议应答桢返回码解析器
 */

#include <cstring>
#include <cstdio>
using namespace std;
#include <sapi/tpm20.h>
#include "ResponseCodeResolver.h"

/**
 * 公共 API 函数: GetErrMsgOfTPMResponseCode()
 *
 * 用法及函数参数列表参见头文件 ResponseCodeResolver.h
 */
const char *GetErrMsgOfTPMResponseCode(TPM_RC rc)
{
    ResponseCodeResolver resolver(rc);
    return resolver.msg();
}

/**
 * 构造函数
 *
 * @param TPM_RC rc
 */
ResponseCodeResolver::ResponseCodeResolver(TPM_RC rc)
{
    uint32_t val;

    val = static_cast<uint32_t>(rc);
    UnsignedInt32Box::operator=(val);
}

/**
 * 析构函数
 */
ResponseCodeResolver::~ResponseCodeResolver()
{
}

/**
 * 无参数时的默认构造函数
 */
UnsignedInt32Box::UnsignedInt32Box()
{
    this->m_value = 0;
}

uint32_t UnsignedInt32Box::value()
{
    return this->m_value;
}

/**
 * 查找应答码对应的错误信息
 */
const char *ResponseCodeResolver::msg()
{
    static char msg[512] = "";
    const size_t SIZE = sizeof(msg);
    size_t n;
    struct
    {
        const char *reason;
        const char *suggestion;
    } err;
    TPM_RC rc;

    rc = this->getResponseCode();
    if (!rc)
    {
        return "";
    }

    err.reason = "Unknown Response Code";
    err.suggestion = "";
    if (rc & RC_FMT1)
    {
        if ((rc & TPM_RC_P) && (rc & TPM_RC_SIZE))
        {
            err.reason = "Parameter size error";
            err.suggestion =
                    "Check your command parameters which might be too long or too short.";
        }
    }
    else
    {
        if (rc == TPM_RC_INITIALIZE)
        {
            err.reason = "TPM has not been initialized";
            err.suggestion =
                    "A TPM2_Startup command MUST be performed before doing anything else.";
        }
    }
    n = SIZE;
    snprintf(msg, n, "0x%X:%s. %s", rc, err.reason, err.suggestion);
    return msg;
}

void ResponseCodeResolver::setResponseCode(TPM_RC rc)
{
    uint32_t val = static_cast<uint32_t>(rc);
    UnsignedInt32Box::operator=(val);
}

TPM_RC ResponseCodeResolver::getResponseCode()
{
    return static_cast<TPM_RC>(this->UnsignedInt32Box::value());
}

void UnsignedInt32Box::operator=(uint32_t& value)
{
    this->m_value = value;
}

/**
 * 查找与执行 NV 空间操作返回的应答码相关的错误信息
 */
const char *NVSpaceRelatedResponseCodeResolver::msg()
{
    static char msg[1024] = "";
    const size_t SIZE = sizeof(msg);
    size_t n;
    struct
    {
        const char *reason;
        const char *suggestion;
    } err;
    TPM_RC rc;

    rc = this->getResponseCode();
    if (!rc)
    {
        return "";
    }

    n = SIZE;
    err.reason = "Unknown Response Code";
    err.suggestion = "";
    if (rc & RC_FMT1)
    {
        if ((rc & TPM_RC_P) && (rc & TPM_RC_SIZE))
        {
            err.reason = "Parameter size error";
            err.suggestion = "Your password might be too long,"
                    " please check the TPM's capability specifications";
            snprintf(msg, n, "0x%X:%s. %s", rc, err.reason, err.suggestion);
            return msg;
        }
    }
    return this->ResponseCodeResolver::msg();
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
 */
