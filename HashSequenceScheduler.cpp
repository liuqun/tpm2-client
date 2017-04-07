// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <cassert>
using namespace std;
#include "HashSequenceScheduler.h"
#include "ResponseCodeResolver.h"

#define TPM_HT_NONE ((TPM_HT) 0xFC)
#define HR_NONE ((TPM_HC) (TPM_HT_NONE << HR_SHIFT))

void HashSequenceScheduler::start(TPMI_ALG_HASH algorithm,
        TPM2B_AUTH *pAuthValue)
{
    HashSequenceStartCommand cmd;

    if (TPM_ALG_NULL == algorithm)
    {
        // FIXME: Warning: 当调用者指定算法编码 algorithm=0x0010 (即 TPM_ALG_NULL)
        // 时, TPM 会将该序列初始化成一个 EventSequence(事件序列)
    }

    if (m_started)
    {
        throw "Error: You have already called method start(), please do NOT call it again before calling complete()";
    }

    if (pAuthValue)
    {
        /* Save TPM2B_AUTH for later used to build cmdAuthsArray in method update() and complete() */
        m_savedAuthValue.t.size = pAuthValue->t.size;
        memcpy(m_savedAuthValue.t.buffer, pAuthValue->t.buffer,
                pAuthValue->t.size);
    }
    else /* Build an empty TPM2B_AUTH instead */
    {
        m_savedAuthValue.t.size = 0;
        pAuthValue = &m_savedAuthValue;
    }

    m_savedSequenceHandle = 0x0;  // 方便调试
    cmd.prepareHashAlgorithm(algorithm);
    cmd.prepareOptionalAuthValue(pAuthValue->t.buffer, pAuthValue->t.size);
    try {
        cmd.execute(m_pSysContext);
    } catch (TSS2_RC rc) {
        m_started = false;
        /* 将错误码转换为字符串内容, 之后再向上层抛出异常 */
        throw GetErrMsgOfTPMResponseCode(rc);
    }
    m_savedSequenceHandle = cmd.getHashSequenceHandle();
    m_started = true;
}

void HashSequenceScheduler::update(const TPM2B_MAX_BUFFER *pMessagePacket)
{
    HashSequenceUpdateCommand cmd;

    if (!m_started)
    {
        throw "Error: You should call method start() before update()";
    }
    if (!pMessagePacket || pMessagePacket->t.size <= 0)
    {
        return; // Warning: Empty data block detected and will be ignored here
    }
    else if (pMessagePacket->t.size > MAX_DIGEST_BUFFER)
    {
        throw "Warning: Unable to handle single data block which is larger than MAX_DIGEST_BUFFER";
    }

    cmd.setSequenceHandleWithOptionalAuthValue(m_savedSequenceHandle, m_savedAuthValue.t.buffer, m_savedAuthValue.t.size);
    cmd.prepareData(pMessagePacket->t.buffer, pMessagePacket->t.size);
    try {
        cmd.execute(m_pSysContext);
    } catch (TSS2_RC rc) {
        m_started = false;
        /* 将错误码转换为字符串内容, 之后再向上层抛出异常 */
        throw GetErrMsgOfTPMResponseCode(rc);
    }
}

void HashSequenceScheduler::complete(TPM2B_DIGEST *result)
{
    if (!m_started)
    {
        throw "Error: You should call method start() and update() before complete()";
    }

    HashSequenceCompleteCommand cmd;
    cmd.setSequenceHandleWithOptionalAuthValue(m_savedSequenceHandle, m_savedAuthValue.t.buffer, m_savedAuthValue.t.size);
    try {
        cmd.execute(m_pSysContext);
    } catch (TSS2_RC rc) {
        /* 将错误码转换为字符串内容, 之后再向上层抛出异常 */
        throw GetErrMsgOfTPMResponseCode(rc);
    }

    const TPM2B_DIGEST& digest = cmd.getResponseDigest();

    UINT16 n = digest.t.size;
    if (n > sizeof(result->t.buffer))
    {
        n = sizeof(result->t.buffer);
    }
    result->t.size = n;
    memcpy(result->t.buffer, digest.t.buffer, n);
    m_started = false;
    m_savedSequenceHandle = 0x0;  // 方便调试
}

HashSequenceScheduler::HashSequenceScheduler(TSS2_SYS_CONTEXT *pSysContext)
{
    this->m_pSysContext = pSysContext;
    this->m_started = false;
    this->m_savedSequenceHandle = 0x0;  // 方便调试
}

/**
 * 构造函数
 */
HashSequenceStartCommand::HashSequenceStartCommand() {
    auth.t.size = 0;
    auth.t.buffer[0] = '\0'; // Used for debugging
    hashAlg = TPM_ALG_NULL;
    sequenceHandle = (TPM_HT_NONE << HR_SHIFT);
    rc = TPM_RC_SUCCESS;
}

/**
 * 析构函数
 */
HashSequenceStartCommand::~HashSequenceStartCommand() {
    clearAuthValue();
}

TPMI_ALG_HASH HashSequenceStartCommand::prepareHashAlgorithm(TPMI_ALG_HASH algorithm) {
    hashAlg = algorithm;
    return hashAlg;
}

const TPM2B_AUTH& HashSequenceStartCommand::prepareOptionalAuthValue(const BYTE value[], UINT16 size) {
    if (size > sizeof(auth.t.buffer)) {
        /* 自动截断并舍弃超过长度上限的数据 */
        size = sizeof(auth.t.buffer);
    }
    auth.b.size = size;
    memcpy(auth.b.buffer, value, size);
    return auth;
}

void HashSequenceStartCommand::clearAuthValue() {
    const size_t len = sizeof(auth);
    memset(&auth, 0x00, len); // 清空残留数据
}

void HashSequenceStartCommand::execute(TSS2_SYS_CONTEXT *pSysContext) {
    rc = Tss2_Sys_HashSequenceStart(
            pSysContext, //
            (TSS2_SYS_CMD_AUTHS *) NULL, //
            &auth, // IN
            hashAlg, // IN
            &sequenceHandle, // OUT
            (TSS2_SYS_RSP_AUTHS *) NULL); //
    if (rc) {
        throw (TSS2_RC) rc;
        // fprintf(stderr, "Error: rc=0x%X\n", rc);
    }
    return;
}

/**
 * 取出最终哈希摘要计算结果数据缓冲区的长度, 单位字节
 *
 * @return 长度
 */
TPMI_DH_OBJECT HashSequenceStartCommand::getHashSequenceHandle() const {
    return sequenceHandle;
}

// -----------------------------------------------------
// 以下为 C++ class HashSequenceUpdateCommand 的实现代码

/**
 * 构造函数
 */
HashSequenceUpdateCommand::HashSequenceUpdateCommand() {
    sequenceHandle = (TPM_HT_NONE << HR_SHIFT);
    data.t.size = 0;
    data.t.buffer[0] = '\0'; // Used for debugging
    rc = TPM_RC_SUCCESS;
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.sessionAttributes.val = 0;
    sessionData.hmac.t.size = 0;
    sessionData.hmac.t.buffer[0] = '\0'; // Used for debugging
}

/**
 * 析构函数
 */
HashSequenceUpdateCommand::~HashSequenceUpdateCommand() {
    clearAuthValue();
    clearData();
}

/**
 * 指定哈希序列句柄(但不设置句柄本身的访问授权值)
 */
void HashSequenceUpdateCommand::setSequenceHandle(
        TPMI_DH_OBJECT sequenceHandle // 句柄
        ) {
    const TPM_HT type =
            (sequenceHandle & HR_RANGE_MASK) >> HR_SHIFT;
    if (type != TPM_HT_TRANSIENT) {
        /* 当遇到无效的句柄时, 子函数将抛出异常 0x0103 TPM_RC_SEQUENCE */
        throw (TSS2_RC) TPM_RC_SEQUENCE;
    }
    this->sequenceHandle = sequenceHandle;
}

/**
 * 指定哈希序列句柄, 同时指定句柄本身的访问授权 AuthValue
 */
void HashSequenceUpdateCommand::setSequenceHandleWithOptionalAuthValue(
        TPMI_DH_OBJECT sequenceHandle, // 句柄
        BYTE authValue[], // 句柄授权数据
        UINT16 size // 数据长度
        ) {
    const TPM_HT type =
            (sequenceHandle & HR_RANGE_MASK) >> HR_SHIFT;
    if (type != TPM_HT_TRANSIENT) {
        /* 当遇到无效的句柄时, 子函数将抛出异常 0x0103 TPM_RC_SEQUENCE */
        throw (TSS2_RC) TPM_RC_SEQUENCE;
    }
    this->sequenceHandle = sequenceHandle;

    if (size > sizeof(sessionData.hmac.t.buffer)) {
        /* 自动截断并舍弃超过长度上限的数据 */
        size = sizeof(sessionData.hmac.t.buffer);
    }
    sessionData.hmac.t.size = size;
    memcpy(sessionData.hmac.t.buffer, authValue, size);
}

/**
 * 清除之前指定的句柄访问授权 AuthValue, 以免泄露敏感数据
 */
void HashSequenceUpdateCommand::clearAuthValue() {
    const size_t len = sizeof(sessionData.hmac);
    memset(&(sessionData.hmac), 0x00, len); // 清空残留数据
}

/**
 * 存入本次进行哈希计算的数据
 *
 * 详细参数及返回值参见头文件中的定义
 */
const TPM2B_MAX_BUFFER& HashSequenceUpdateCommand::prepareData(const BYTE data[], UINT16 size) {
    if (size > MAX_DIGEST_BUFFER) {
        /* 自动截断并舍弃超过长度上限的数据 */
        size = MAX_DIGEST_BUFFER;
    }
    this->data.t.size = size;
    memcpy(this->data.t.buffer, data, size);
    return this->data;
}

/**
 * 清除数据
 */
void HashSequenceUpdateCommand::clearData() {
    const size_t len = sizeof(data);
    memset(&data, 0x00, len); // 清空残留数据
}

/**
 * 执行 TPM 命令
 */

void HashSequenceUpdateCommand::execute(TSS2_SYS_CONTEXT *pSysContext) {
    if (data.t.size <= 0 || data.t.size > MAX_DIGEST_BUFFER) {
        /* 检查待处理的字节数 */
        throw (TSS2_RC) TSS2_SYS_RC_BAD_VALUE;
    }
    if (HR_NONE == (TPM_HC) sequenceHandle) {
        /* 检查句柄 sequenceHandle 的有效值 */
        throw (TSS2_RC) TPM_RC_SEQUENCE;
    }

    TPMS_AUTH_COMMAND *cmdAuths[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    cmdAuths[0] = &sessionData;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *rspAuths[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    rspAuths[0] = &sessionDataOut;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = 1;

    /* 调用 TPM 命令 */
    rc = Tss2_Sys_SequenceUpdate(
            pSysContext, //
            sequenceHandle, // IN
            &cmdAuthsArray, //
            &data, // IN
            &rspAuthsArray); //
    if (rc) {
        // fprintf(stderr, "Error: rc=0x%X\n", rc); // 临时调试用
        throw (TSS2_RC) rc;
    }
    return;
}

// -------------------------------------------------------
// 以下为 C++ class HashSequenceCompleteCommand 的实现代码
/**
 * 构造函数
 */
HashSequenceCompleteCommand::HashSequenceCompleteCommand() {
    sequenceHandle = (TPM_HT_NONE << HR_SHIFT);
    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.sessionAttributes.val = 0;
    sessionData.hmac.t.size = 0;
    sessionData.hmac.t.buffer[0] = '\0'; // Used for debugging
    data.t.size = 0;
    data.t.buffer[0] = '\0'; // Used for debugging
    hierarchy = TPM_RH_PLATFORM;
    result.t.size = 0; // Used for debugging
    result.t.buffer[0] = '\0'; // Used for debugging
    rc = TPM_RC_SUCCESS;
}

/**
 * 析构函数
 */
HashSequenceCompleteCommand::~HashSequenceCompleteCommand() {
    clearAuthValue();
    clearFinalDataPack();
}

/**
 * 指定哈希序列句柄(但不设置句柄本身的访问授权值)
 */
void HashSequenceCompleteCommand::setSequenceHandle(
        TPMI_DH_OBJECT sequenceHandle // 句柄
        ) {
    const TPM_HT type =
            (sequenceHandle & HR_RANGE_MASK) >> HR_SHIFT;
    if (type != TPM_HT_TRANSIENT) {
        /* 当遇到无效的句柄时, 子函数将抛出异常 0x103 TPM_RC_SEQUENCE */
        throw (TSS2_RC) TPM_RC_SEQUENCE;
    }
    this->sequenceHandle = sequenceHandle;
}

/**
 * 指定哈希序列句柄, 同时指定句柄本身的访问授权 AuthValue
 */
void HashSequenceCompleteCommand::setSequenceHandleWithOptionalAuthValue(
        TPMI_DH_OBJECT sequenceHandle, // 句柄
        BYTE authValue[], // 句柄授权数据
        UINT16 size // 数据长度
        ) {
    const TPM_HT type =
            (sequenceHandle & HR_RANGE_MASK) >> HR_SHIFT;
    if (type != TPM_HT_TRANSIENT) {
        /* 当遇到无效的句柄时, 子函数将抛出异常 0x0103 TPM_RC_SEQUENCE */
        throw (TSS2_RC) TPM_RC_SEQUENCE;
    }
    this->sequenceHandle = sequenceHandle;

    if (size > sizeof(sessionData.hmac.t.buffer)) {
        /* 自动截断并舍弃超过长度上限的数据 */
        size = sizeof(sessionData.hmac.t.buffer);
    }
    sessionData.hmac.t.size = size;
    memcpy(sessionData.hmac.t.buffer, authValue, size);
}

/**
 * 清除之前指定的句柄访问授权 AuthValue, 以免泄露敏感数据
 */
void HashSequenceCompleteCommand::clearAuthValue() {
    const size_t len = sizeof(sessionData.hmac);
    memset(&(sessionData.hmac), 0x00, len); // 清空残留数据
}

/**
 * 存入待进行哈希计算的最后一个数据包
 *
 * 具体参数及返回值以头文件中的定义为准
 */
const TPM2B_MAX_BUFFER& HashSequenceCompleteCommand::prepareFinalDataPack(const BYTE data[], UINT16 size){
    if (size > MAX_DIGEST_BUFFER) {
        /* 自动截断并舍弃超过长度上限的数据 */
        size = MAX_DIGEST_BUFFER;
    }
    this->data.t.size = size;
    memcpy(this->data.t.buffer, data, size);
    return this->data;
}

/**
 * 清除数据(清除运行时缓存的最后一个待计算的原始数据包)
 */
void HashSequenceCompleteCommand::clearFinalDataPack() {
    const size_t len = sizeof(data);
    memset(&data, 0x00, len); // 清空残留数据
}

/**
 * 执行 TPM 命令
 */
void HashSequenceCompleteCommand::execute(TSS2_SYS_CONTEXT *pSysContext) {
    if (data.t.size > MAX_DIGEST_BUFFER) {
        /* 检查待处理的字节数 */
        throw (TSS2_RC) TSS2_SYS_RC_BAD_VALUE;
    }
    if (HR_NONE == (TPM_HC) sequenceHandle) {
        /* 检查句柄 sequenceHandle 的有效值 */
        throw (TSS2_RC) TPM_RC_SEQUENCE;
    }

    TPMS_AUTH_COMMAND *cmdAuths[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    cmdAuths[0] = &sessionData;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *rspAuths[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;
    rspAuths[0] = &sessionDataOut;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = 1;

    /* 调用 TPM 命令 */
    result.t.size = sizeof(result.t.buffer);
    rc = Tss2_Sys_SequenceComplete(
            pSysContext, //
            sequenceHandle, // IN
            &cmdAuthsArray, // IN
            &data, // IN
            hierarchy, // IN
            &result, // OUT
            &validationTicket, // OUT
            &rspAuthsArray); //
    if (rc) {
        throw (TSS2_RC) rc;
        // fprintf(stderr, "Error: rc=0x%X\n", rc);
    }
    return;
}

/**
 * 取出最终哈希摘要计算结果数据缓冲区指针
 */
const BYTE *HashSequenceCompleteCommand::getResponseDigestValue() const {
    return result.t.buffer;
}

/**
 * 取出最终哈希摘要计算结果数据缓冲区的长度, 单位字节
 */
UINT16 HashSequenceCompleteCommand::getResponseDigestSize() const {
    return result.t.size;
}

/**
 * 取出最终哈希摘要计算结果 TPM2B 结构体
 */
const TPM2B_DIGEST& HashSequenceCompleteCommand::getResponseDigest() const {
    return result;
}

/**
 * 指定哈希操作输出凭据中引用的 hierarchy 树
 *
 * (参数及返回值定义请以头文件中的定义为准)
 */
TPMI_RH_HIERARCHY HashSequenceCompleteCommand::setHierarchyForValidationTicket(TPMI_RH_HIERARCHY hierarchy) {
    this->hierarchy = hierarchy;
    return hierarchy;
}
 /**
 * 取出证明哈希摘要是由 TPM 模块输出的凭据
 *
 * @return TPMT_TK_HASHCHECK (C++引用) 凭据
 */
const TPMT_TK_HASHCHECK& HashSequenceCompleteCommand::getResponseValidationTicket() const {
    return validationTicket;
}

