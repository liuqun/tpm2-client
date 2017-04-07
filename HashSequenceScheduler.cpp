// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include <cassert>
using namespace std;
#include "HashSequenceScheduler.h"
#include "ResponseCodeResolver.h"

#define TPM_HT_NONE ((TPM_HT) 0xFC)
#define HR_NONE ((TPM_HC) (TPM_HT_NONE << HR_SHIFT))

class HashSequenceStartCommand {
private:
    TPM2B_AUTH auth;
    TPMI_ALG_HASH hashAlg;
    TPMI_DH_OBJECT sequenceHandle;
    TPM_RC rc;

public:
    /**
     * 构造函数
     */
    HashSequenceStartCommand() {
        auth.t.size = 0;
        auth.t.buffer[0] = '\0'; // Used for debugging
        hashAlg = TPM_ALG_NULL;
        sequenceHandle = (TPM_HT_NONE << HR_SHIFT);
        rc = TPM_RC_SUCCESS;
    }

    /**
     * 析构函数
     */
    ~HashSequenceStartCommand()
    {
        clearAuthValue();
    }

public:
    TPMI_ALG_HASH prepareHashAlgorithm(TPMI_ALG_HASH algorithm) {
        hashAlg = algorithm;
        return hashAlg;
    }

    const TPM2B_AUTH& prepareOptionalAuthValue(const BYTE value[], UINT16 size) {
        if (size > sizeof(auth.t.buffer)) {
            /* 自动截断并舍弃超过长度上限的数据 */
            size = sizeof(auth.t.buffer);
        }
        auth.b.size = size;
        memcpy(auth.b.buffer, value, size);
        return auth;
    }

    void clearAuthValue() {
        const size_t len = sizeof(auth);
        memset(&auth, 0x00, len); // 清空残留数据
    }

    virtual void execute(TSS2_SYS_CONTEXT *pSysContext) {
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
    TPMI_DH_OBJECT getHashSequenceHandle() const {
        return sequenceHandle;
    }
};

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

class HashSequenceUpdateCommand {
private:
    TPMI_DH_OBJECT sequenceHandle;
    TPM2B_MAX_BUFFER data; // 用于存储本轮哈希操作待处理的原始数据
    TPM_RC rc;
    TPMS_AUTH_COMMAND sessionData;

public:
    HashSequenceUpdateCommand() {
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
    virtual ~HashSequenceUpdateCommand() {
        clearAuthValue();
        clearData();
    }

public:
    void setSequenceHandle(
            TPMI_DH_OBJECT sequenceHandle // 句柄
            ) {
        // FIXME 检查句柄 sequenceHandle 的有效值
        const TPM_HT type =
                (sequenceHandle & HR_RANGE_MASK) >> HR_SHIFT;
        if (type != TPM_HT_TRANSIENT) {
            /* 当遇到无效的句柄时, 子函数将抛出异常 0x0103 TPM_RC_SEQUENCE */
            throw (TSS2_RC) TPM_RC_SEQUENCE;
        }
        this->sequenceHandle = sequenceHandle;
    }
    void setSequenceHandleWithOptionalAuthValue(
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
    void clearAuthValue() {
        const size_t len = sizeof(sessionData.hmac);
        memset(&(sessionData.hmac), 0x00, len); // 清空残留数据
    }

    /**
     * 存入本次进行哈希计算的数据
     *
     * @param data 待哈希的数据
     * @param size 如果数据长度超过 MAX_DIGEST_BUFFER=1024 字节, 这里将自动截断多余的字节
     * @return TPM2B 格式的数据块, 仅为调试使用, 可直接忽略该返回值
     */
    const TPM2B_MAX_BUFFER& prepareData(const BYTE data[], UINT16 size) {
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
    void clearData() {
        const size_t len = sizeof(data);
        memset(&data, 0x00, len); // 清空残留数据
    }

    virtual void execute(TSS2_SYS_CONTEXT *pSysContext) {
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
            throw (TSS2_RC) rc;
            // fprintf(stderr, "Error: rc=0x%X\n", rc);
        }
        return;
    }
    TPM_RC parseResponseValues() { // SequenceUpdate 命令本身没有输出值
        return rc;
    }
};

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

/**
 * C++ 类名: HashSequenceCompleteCommand
 *
 * 将 Tss2_Sys_SequenceComplete 的所有函数参数封装在一起,
 * 避免调用该函数时需额外创建一堆零散的数据结构作为参数
 */
class HashSequenceCompleteCommand {
private:
    TPMI_DH_OBJECT sequenceHandle;
    TPMS_AUTH_COMMAND sessionData;
    TPM2B_MAX_BUFFER data; // 用于存储最后一轮哈希操作中待处理的原始数据 (可以为空)
    TPMI_RH_HIERARCHY hierarchy; // The hierarchy of the ticket for a hash operation
    // 以上成员变量用于存储输入数据
    // 以下用于记录输出结果
    TPM2B_DIGEST result; // 哈希摘要运算结果
    TPMT_TK_HASHCHECK validationTicket; // 附带一份哈希结果有效性证明, 用于后续调用相关命令对摘要结果进行签名
    TPM_RC rc;

public:
    HashSequenceCompleteCommand() {
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
    virtual ~HashSequenceCompleteCommand() {
        clearAuthValue();
        clearFinalDataPack();
    }

public:
    void setSequenceHandle(
            TPMI_DH_OBJECT sequenceHandle // 句柄
            ) {
        // FIXME 检查句柄 sequenceHandle 的有效值
        const TPM_HT type = (sequenceHandle & HR_RANGE_MASK) >> HR_SHIFT;
        if (type != TPM_HT_TRANSIENT) {
            /* 当遇到无效的句柄时, 子函数将抛出异常 0x0103 TPM_RC_SEQUENCE */
            throw (TSS2_RC) TPM_RC_SEQUENCE;
        }
        this->sequenceHandle = sequenceHandle;
    }
    void setSequenceHandleWithOptionalAuthValue(
            TPMI_DH_OBJECT sequenceHandle, // 句柄
            BYTE authValue[], // 访问该句柄时所需的授权数据
            UINT16 size       // 授权数据长度
            ) {
        // FIXME 检查句柄 sequenceHandle 的有效值
        const TPM_HT type = (sequenceHandle & HR_RANGE_MASK) >> HR_SHIFT;
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
    void clearAuthValue() {
        const size_t len = sizeof(sessionData.hmac);
        memset(&(sessionData.hmac), 0x00, len); // 清空残留数据
    }

    /**
     * 存入待进行哈希计算的最后一个数据包
     *
     * @param data 待哈希的数据包
     * @param size 如果数据长度超过 MAX_DIGEST_BUFFER=1024 字节, 这里将自动截断多余的字节
     * @return TPM2B 格式的数据块, 仅为调试使用, 可直接忽略该返回值
     */
    const TPM2B_MAX_BUFFER& prepareFinalDataPack(const BYTE data[], UINT16 size) {
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
    void clearFinalDataPack() {
        const size_t len = sizeof(data);
        memset(&data, 0x00, len); // 清空残留数据
    }

    /**
     * 执行 TPM 命令
     */
    virtual void execute(TSS2_SYS_CONTEXT *pSysContext) {
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
     *
     * @return 缓冲区首地址指针
     */
    const BYTE *getResponseDigestValue() const {
        return result.t.buffer;
    }

    /**
     * 取出最终哈希摘要计算结果数据缓冲区的长度, 单位字节
     *
     * @return 长度
     */
    UINT16 getResponseDigestSize() const {
        return result.t.size;
    }

    /**
     * 取出最终哈希摘要计算结果 TPM2B 结构体
     *
     * @return TPM2B_DIGEST (C++引用)
     */
    const TPM2B_DIGEST& getResponseDigest() const {
        return result;
    }

    /**
     * 指定哈希操作输出凭据中引用的 hierarchy 树
     *
     * @param hierarchy 可以选择 TPM_RH_PLATFORM 或 TPM_RH_OWNER 等
     * @return TPMI_RH_HIERARCHY 仅用于方便调试
     */
    TPMI_RH_HIERARCHY setHierarchyForValidationTicket(TPMI_RH_HIERARCHY hierarchy) {
        this->hierarchy = hierarchy;
        return hierarchy;
    }
     /**
     * 取出证明哈希摘要是由 TPM 模块输出的凭据
     *
     * @return TPMT_TK_HASHCHECK (C++引用) 凭据
     */
    const TPMT_TK_HASHCHECK& getResponseValidationTicket() const {
        return validationTicket;
    }
};

void HashSequenceScheduler::complete(TPM2B_DIGEST *result)
{
    TPM_RC rc;
    TPM2B emptyBuffer;
    TPM2B_MAX_BUFFER *pEmptyBuffer;
    TPMT_TK_HASHCHECK validation;

    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_COMMAND *cmdAuths[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *rspAuths[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;

    if (!m_started)
    {
        throw "Error: You should call method start() and update() before complete()";
    }

    sessionData.sessionHandle = TPM_RS_PW;
    sessionData.nonce.t.size = 0;
    sessionData.hmac.t.size = m_savedAuthValue.t.size; // 取出之前保存的 auth value 数据块
    memcpy(sessionData.hmac.t.buffer, m_savedAuthValue.t.buffer,
            m_savedAuthValue.t.size);
    memset(&(sessionData.sessionAttributes), 0x00, sizeof(TPMA_SESSION));

    cmdAuths[0] = &sessionData;
    cmdAuthsArray.cmdAuths = cmdAuths;
    cmdAuthsArray.cmdAuthsCount = 1;

    rspAuths[0] = &sessionDataOut;
    rspAuthsArray.rspAuths = rspAuths;
    rspAuthsArray.rspAuthsCount = 1;

    emptyBuffer.size = 0;
    pEmptyBuffer =
            static_cast<TPM2B_MAX_BUFFER *>(static_cast<void *>(&emptyBuffer));
    rc = Tss2_Sys_SequenceComplete(m_pSysContext, m_savedSequenceHandle,
            &cmdAuthsArray, pEmptyBuffer, TPM_RH_PLATFORM, result, &validation,
            &rspAuthsArray);
    if (rc)
    {
        throw GetErrMsgOfTPMResponseCode(rc);
    }

    m_started = false;
    m_savedSequenceHandle = 0x0;  // 方便调试
}

HashSequenceScheduler::HashSequenceScheduler(TSS2_SYS_CONTEXT *pSysContext)
{
    this->m_pSysContext = pSysContext;
    this->m_started = false;
    this->m_savedSequenceHandle = 0x0;  // 方便调试
}
