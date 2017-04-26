// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef HASH_SEQUENCE_SCHEDULER_H_
#define HASH_SEQUENCE_SCHEDULER_H_

#include "sapi/tpm20.h"

class HashSequenceScheduler
{
public:
    HashSequenceScheduler(TSS2_SYS_CONTEXT *p);
    void start(TPMI_ALG_HASH algorithm, TPM2B_AUTH *pAuthValue);
    void update(const TPM2B_MAX_BUFFER *pMessagePacket);
    /**
     * Method complete()
     *
     * @param TPM2B_DIGEST *pOutputDigest - The output digest struct
     *  注意摘要内容的存储空间需经调用者预先分配,
     *  可以由该结构体首部的 2 字节 size 指示预先分配的空间大小,
     *  但函数内部具体实现有可能忽略 size 字段的具体内容,
     *  建议与其他厂家提供的 TSS 保持一致
     * @throw const char * - 字符串表示的错误信息, 只读, 字符串以 '\0' 结尾
     */
    void complete(TPM2B_DIGEST *pOutputDigest);
private:
    TSS2_SYS_CONTEXT *m_pSysContext;
    bool m_started;
    TPM2B_AUTH m_savedAuthValue;
    TPMI_DH_OBJECT m_savedSequenceHandle;
};

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
    HashSequenceStartCommand();

    /**
     * 析构函数
     */
    ~HashSequenceStartCommand();

    /**
     *
     */
    TPMI_ALG_HASH prepareHashAlgorithm(TPMI_ALG_HASH algorithm);

    /**
     *
     */
    const TPM2B_AUTH& prepareOptionalAuthValue(const BYTE value[], UINT16 size);

    /**
     *
     */
    void clearAuthValue();

    /**
     * 执行 TPM 命令
     */
    virtual void execute(TSS2_SYS_CONTEXT *pSysContext);

    /**
     * 取出最终哈希摘要计算结果数据缓冲区的长度, 单位字节
     *
     * @return 长度
     */
    TPMI_DH_OBJECT getHashSequenceHandle() const;
};

class HashSequenceUpdateCommand {
private:
    TPMI_DH_OBJECT sequenceHandle;
    TPM2B_MAX_BUFFER data; // 用于存储本轮哈希操作待处理的原始数据
    TPM_RC rc;
    TPMS_AUTH_COMMAND sessionData;

public:
    /**
     * 构造函数
     */
    HashSequenceUpdateCommand();

    /**
     * 析构函数
     */
    virtual ~HashSequenceUpdateCommand();

    /**
     * 指定哈希序列句柄及句柄本身的访问授权 AuthValue
     */
    void setSequenceHandle(TPMI_DH_OBJECT sequenceHandle);
    void setSequenceHandleWithOptionalAuthValue(
            TPMI_DH_OBJECT sequenceHandle, // 句柄
            BYTE authValue[], // 句柄授权数据
            UINT16 size // 数据长度
            );
    void clearAuthValue();

    /**
     * 存入本次进行哈希计算的数据
     *
     * @param data 待哈希的数据
     * @param size 如果数据长度超过 MAX_DIGEST_BUFFER=1024 字节, 这里将自动截断多余的字节
     * @return TPM2B 格式的数据块, 仅为调试使用, 可直接忽略该返回值
     */
    const TPM2B_MAX_BUFFER& prepareData(const BYTE data[], UINT16 size);

    /**
     * 清除数据
     */
    void clearData();

    /**
     * 执行 TPM 命令
     */
    virtual void execute(TSS2_SYS_CONTEXT *pSysContext);

};

#endif /* HASH_SEQUENCE_SCHEDULER_H_ */
