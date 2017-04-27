/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef KEY_UTILITIES_H_
#define KEY_UTILITIES_H_

#include <sapi/tpm20.h>

#ifdef __cplusplus

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

public:
    TPM_RC rc;

public:
    KeyPublicDataReadingOperation();
    ~KeyPublicDataReadingOperation();

    /**
     * 通过句柄指定访问的密钥节点, 同时保存相应的访问授权数据
     *
     * @param handle 指定句柄, 取值一般为 0x81 或 0x80 开头
     * @return TPMI_DH_OBJECT 仅用于调试, 返回值总是等于参数列表中指定的句柄
     */
    TPMI_DH_OBJECT setKeyHandle(TPMI_DH_OBJECT handle);

    /**
     * 执行 TPM 命令
     */
    void execute(TSS2_SYS_CONTEXT *pSysContext);

    /**
     * 取回命令应答结果中的密钥唯一名字
     */
    const TPM2B_NAME& getKeyName();
};

#endif // __cplusplus
#endif // KEY_UTILITIES_H_

