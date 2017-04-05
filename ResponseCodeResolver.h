// Copyright (c) 2017, 青岛中怡智能安全研究院有限公司
// All rights reserved.

/*
 * ResponseCodeResolver.h
 *
 * TPM 2.0 协议应答桢返回码解析器 - 公共 API 接口
 */

#ifndef RESPONSECODERESOLVER_H_
#define RESPONSECODERESOLVER_H_

#include <sapi/tpm20.h>
#include <stdint.h>

#ifdef __cplusplus

extern "C"
{ /* C 接口函数声明 - 开始 */

#endif /* __cplusplus */

/**
 * 公共 API 函数: GetErrMsgOfTPMResponseCode()
 *
 * 用法: printf("%s\n", GetErrMsgOfTPMResponseCode(rc));
 *
 * @param TPM_RC rc
 * @return const char* - 一个表示错误信息的字符串(只读)
 */
const char *GetErrMsgOfTPMResponseCode(TPM_RC rc);

#ifdef __cplusplus
} /* C 接口函数声明 - 结束 */

/**
 * UnsignedInt32 装箱
 *
 * 参考 Java int数据自动装箱机制 <int> 与 <Integer> 之间自动转换
 *
 */

class UnsignedInt32Box
{
private:
    uint32_t m_value;
public:
    UnsignedInt32Box();
    //UnsignedInt32Box& operator=(uint32_t other);
    void operator=(uint32_t& other);
    uint32_t value();
};

/**
 * Response code resolver 辅助类
 *
 * 解析TPM_RC编码
 */
class ResponseCodeResolver: UnsignedInt32Box
{
public:
    /**
     * 构造函数
     *
     * @param TPM_RC rc
     */
    ResponseCodeResolver(TPM_RC rc = TPM_RC_SUCCESS);

    /**
     * 析构函数
     */
    virtual ~ResponseCodeResolver();

    /**
     * 成员函数: setResponseCode()
     *
     * @param TPM_RC rc
     */
    void setResponseCode(TPM_RC rc);

    /**
     * 成员函数: getResponseCode()
     *
     * @return TPM_RC - 返回之前 setResponseCode() 函数存储的错误编码值
     * 如果之前没有存储过错误编码则返回TPM_RC_SUCCESS
     */
    TPM_RC getResponseCode();

    /**
     * 成员函数: msg()
     *
     * @return const char* - 一个表示错误信息的字符串(只读)
     * 该字符串最大长度由具体实现决定, 约定字符串以 '\0' 结尾
     */
    virtual
    const char *msg();

};

#endif /* __cplusplus */

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

#endif /* RESPONSECODERESOLVER_H_ */
