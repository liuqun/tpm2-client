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
    const TPM2B_AUTH& prepareOptionalAuthValueForHashSequenceHandle(const BYTE value[], UINT16 size);

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

/**
 * C++ 类名: HashSequenceCompleteCommand
 *
 * 设计意图:
 * 将 Tss2_Sys_SequenceComplete() 与自己的所有调用参数捆绑到一起,
 * 从而避免客户程序调用该函数时必须创建一堆零散的数据结构引入过高的复杂度的问题.
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
    /**
     * 构造函数
     */
    HashSequenceCompleteCommand();

    /**
     * 析构函数
     */
    virtual ~HashSequenceCompleteCommand();

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
     * 存入待进行哈希计算的最后一个数据包
     *
     * @param data 待哈希的数据包
     * @param size 如果数据长度超过 MAX_DIGEST_BUFFER=1024 字节, 这里将自动截断多余的字节
     * @return TPM2B 格式的数据块, 仅为调试使用, 可直接忽略该返回值
     */
    const TPM2B_MAX_BUFFER& prepareFinalDataPack(const BYTE data[], UINT16 size);

    /**
     * 清除数据(清除运行时缓存的最后一个待计算的原始数据包)
     */
    void clearFinalDataPack();

    /**
     * 执行 TPM 命令
     */
    virtual void execute(TSS2_SYS_CONTEXT *pSysContext);

    /**
     * 取出最终哈希摘要计算结果数据缓冲区指针
     *
     * @return 缓冲区首地址指针
     */
    const BYTE *getResponseDigestValue() const;

    /**
     * 取出最终哈希摘要计算结果数据缓冲区的长度, 单位字节
     *
     * @return 长度
     */
    UINT16 getResponseDigestSize() const;

    /**
     * 取出最终哈希摘要计算结果 TPM2B 结构体
     *
     * @return TPM2B_DIGEST (C++引用)
     */
    const TPM2B_DIGEST& getResponseDigest() const;

    /**
     * 指定哈希操作输出凭据中引用的 hierarchy 树
     *
     * @param hierarchy 可以选择 TPM_RH_PLATFORM 或 TPM_RH_OWNER 等.
     *        调用此函数前, hierarchy 的默认值由构造函数设置, 通常取 TPM_RH_PLATFORM
     * @return TPMI_RH_HIERARCHY 仅用于方便调试
     */
    TPMI_RH_HIERARCHY setHierarchyForValidationTicket(TPMI_RH_HIERARCHY hierarchy);

    /**
     * 取出证明哈希摘要是由 TPM 模块输出的凭据
     *
     * @return TPMT_TK_HASHCHECK (C++引用) 凭据
     */
    const TPMT_TK_HASHCHECK& getResponseValidationTicket() const;
};

#endif /* HASH_SEQUENCE_SCHEDULER_H_ */
