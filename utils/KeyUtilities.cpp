/* encoding: utf-8 */
// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#include "KeyUtilities.h"
#include <sapi/tpm20.h>

KeyPublicDataReadingOperation::KeyPublicDataReadingOperation() {
    keyHandle = (TPM_HANDLE) 0;
    // 输出结果初始化
    keyPublicData.t.size = 0;
    keyName.t.name[0] = '\0'; // Used for debugging
    qualifiedName.t.name[0] = '\0'; // Used for debugging
    rc = TPM_RC_SUCCESS;
}

KeyPublicDataReadingOperation::~KeyPublicDataReadingOperation() {
}

/**
 * 通过句柄指定访问的密钥节点, 同时保存相应的访问授权数据
 *
 * (参数列表及返回值详见头文件中的声明)
 */
TPMI_DH_OBJECT KeyPublicDataReadingOperation::setKeyHandle(TPMI_DH_OBJECT handle) {
    this->keyHandle = handle;
    return handle;
}

/**
 * 执行 TPM 命令
 */
void KeyPublicDataReadingOperation::execute(TSS2_SYS_CONTEXT *pSysContext) {
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
const TPM2B_NAME& KeyPublicDataReadingOperation::getKeyName() {
    return keyName;
}

