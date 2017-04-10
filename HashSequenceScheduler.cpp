// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include "HashSequenceScheduler.h"
#include "ResponseCodeResolver.h"

void HashSequenceScheduler::start(TPMI_ALG_HASH algorithm,
        TPM2B_AUTH *pAuthValue)
{
    TPM_RC rc;

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
    rc = Tss2_Sys_HashSequenceStart(m_pSysContext, NULL, pAuthValue, algorithm,
            &m_savedSequenceHandle, NULL);
    if (rc)
    {
        throw GetErrMsgOfTPMResponseCode(rc);
    }
    m_started = true;
}

void HashSequenceScheduler::update(const TPM2B_MAX_BUFFER *pMessagePacket)
{
    TPM_RC rc;
    TPM2B_MAX_BUFFER copy;
    TPMS_AUTH_COMMAND sessionData;
    TPMS_AUTH_COMMAND *cmdAuths[1];
    TSS2_SYS_CMD_AUTHS cmdAuthsArray;
    TPMS_AUTH_RESPONSE sessionDataOut;
    TPMS_AUTH_RESPONSE *rspAuths[1];
    TSS2_SYS_RSP_AUTHS rspAuthsArray;

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

    copy.t.size = pMessagePacket->t.size;
    memcpy(copy.t.buffer, pMessagePacket->t.buffer, copy.t.size);
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

    rc = Tss2_Sys_SequenceUpdate(m_pSysContext, m_savedSequenceHandle,
            &cmdAuthsArray, &copy, &rspAuthsArray);
    if (rc)
    {
        throw GetErrMsgOfTPMResponseCode(rc);
    }
}

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
