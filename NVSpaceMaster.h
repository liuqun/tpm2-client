// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

#ifndef NVSPACEMASTER_H_
#define NVSPACEMASTER_H_
#ifdef __cplusplus

#include <sapi/tpm20.h>

class NVSpaceMaster
{
public:
    NVSpaceMaster();

    /**
     * 申请一块通过密码授权访问的非易失存储空间
     *
     * 用法:
     * NVSpaceMaster master;
     * master.pSysContext = pSysContext;
     * try
     * {
     *     master.defineNVSpaceWithPassword(nvIndex, password, nvDataSize);
     *     ...
     *     master.undefineNVSpace(nvIndex);
     * }catch (const char *ErrMsg)
     * {   printf("Error %s\n", ErrMsg);
     * }
     *
     * @param TPMI_RH_NV_INDEX nvIndex 指定 TPM Object 句柄编号
     * @param const char *password 访问密码
     * @param uint16_t nvDataSize 指定空间大小
     * @throws const char* 一个表示错误信息的字符串(只读)
     */
    void defineNVSpaceWithPassword(TPMI_RH_NV_INDEX nvIndex,
            const char *password, uint16_t nvDataSize);

    /**
     * 注销一块通过密码授权访问的非易失存储空间
     *
     * 用法:
     * NVSpaceMaster master;
     * master.pSysContext = pSysContext;
     * try
     * {
     *     master.defineNVSpaceWithPassword(nvIndex, password, nvDataSize);
     *     ...
     *     master.undefineNVSpace(nvIndex);
     * }catch (const char *ErrMsg)
     * {   printf("Error %s\n", ErrMsg);
     * }
     *
     * @param TPMI_RH_NV_INDEX nvIndex 指定 TPM Object 句柄编号
     * @throws const char* 一个表示错误信息的字符串(只读)
     */
    void undefineNVSpace(TPMI_RH_NV_INDEX nvIndex);

    /**
     * 申请一块无需密码授权即可访问的非易失存储空间
     *
     * 用法:与defineNVSpaceWithPassword()基本相同
     * 两者区别只是带不带密码字段
     *
     * @param TPMI_RH_NV_INDEX nvIndex 指定 TPM Object 句柄编号
     * @param uint16_t nvDataSize 指定空间大小
     * @throws const char* 一个表示错误信息的字符串(只读)
     */
    void defineNVSpaceWithoutPassword(TPMI_RH_NV_INDEX nvIndex,
            uint16_t nvDataSize);

    /**
     * 公共成员变量: pSysContext
     * 用法:
     * NVSpaceMaster master;
     * master.pSysContext = pSysContext;
     * try
     * {
     *     master.defineNVSpaceWithPassword(nvIndex, password, nvDataSize);
     *     ...
     *     master.undefineNVSpace(nvIndex);
     * }catch (const char *ErrMsg)
     * {   printf("Error %s\n", ErrMsg);
     * }
     */
public:
    TSS2_SYS_CONTEXT *pSysContext;

    /* 其他公开的 API 接口 */
public:
    /**
     * An overwritten method of global func GetErrMsgOfTPMResponseCode()
     *
     * 用法1: printf("%s\n", GetErrMsgOfTPMResponseCode(rc));
     * 用法2: printf("%s\n", NVSpaceMaster::GetErrMsgOfTPMResponseCode(rc));
     *
     * @param TPM_RC rc
     * @return const char* - 一个表示错误信息的字符串(只读)
     */
    static const char* GetErrMsgOfTPMResponseCode(TPM_RC rc); // 注: 此处定义重载了函数名称GetErrMsgOfTPMResponseCode()
};

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

#endif /* __cplusplus */
#endif /* NVSPACEMASTER_H_ */
