//
// Created by Haohandc on 25-12-19.
//

#ifndef PEHEADERMODIFIER_H
#define PEHEADERMODIFIER_H

#define SUCCESS 0
#define PE_TYPE_UNKNOWN 3

#define FILE_NOT_OPEN 6
#define INVALID_PARAMETER 7 //无效参数
#define PE_FAILED 8

//Characteristics
//(img file header);Source:
//https://learn.microsoft.com/zh-cn/windows/win32/api/winnt/ns-winnt-image_file_header

//重定位信息已从文件中剥离。 文件必须在其首选基址加载。 如果基址不可用，加载程序将报告错误。
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001

// 该文件是可执行文件（没有未解析的外部引用）。
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002

// COFF 行号已从文件中删除。
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004

// COFF 符号表项已从文件中剥离。
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008

// 积极剪裁工作集。 此值已过时。
#define IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010

// 应用程序可以处理大于 2 GB 的地址。
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020

// 反转单词的字节数。 此标志已过时。
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080

// 计算机支持 32 位单词。
#define IMAGE_FILE_32BIT_MACHINE 0x0100

// 调试信息已删除，并单独存储在另一个文件中。
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200

// 如果映像位于可移动媒体上，请将其复制到交换文件并从中运行。
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400

// 如果映像位于网络上，请将其复制到交换文件并从中运行。
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800

// 映像是系统文件。
#define IMAGE_FILE_SYSTEM 0x1000

// 映像是 DLL 文件。 虽然它是可执行文件，但它不能直接运行。
#define IMAGE_FILE_DLL 0x2000

// 该文件应仅在单处理器计算机上运行。
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000

// 反转单词的字节数。 此标志已过时。
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000


#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE        		 0x0040     // DLL can move.
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY    		 0x0080     // Code Integrity Image
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT          	   	 0x0100     // Image is NX compatible
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION       		 0x0200     // Image understands isolation and doesn't want it
#define IMAGE_DLLCHARACTERISTICS_NO_SEH             	 	 0x0400     // Image does not use SEH.  No SE handler may reside in this image
#define IMAGE_DLLCHARACTERISTICS_NO_BIND           	     	 0x0800     // Do not bind this image.
//                                            			 	 0x1000     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER         	 	 0x2000     // Driver uses WDM model
//                                                  	 	 0x4000     // Reserved.
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE       0x8000


#include "PEHeaderReader.h"
#include <string>
#include <vector>
#include <Windows.h>
namespace PEFile {
namespace Header {

class PEHeaderModifier : public PEHeaderReader{
private:
    struct CharacAndName {
        WORD Characteristics;
        std::string name;
        std::string desc;//description缩写
    };
    struct dllCharacAndName {
        WORD dllCharacteristics;
        std::string name;
        std::string desc;
    };
public:
    PEHeaderModifier();
    ~PEHeaderModifier() override = default
    ;
    WORD getFileCharacteristics();
    int setFileCharacteristics(WORD targetvalue, int mode = 0);
    WORD getDllCharacteristics();
    int setDllCharacteristics(WORD targetvalue, int mode = 0);

    DWORD open(const std::wstring &wFilePath, bool WritePermission = false) override;
    // int openPEFileForModify(const std::wstring& wFilePath);

    DWORD save();


    const std::vector<CharacAndName> getFileCharacteristicsList() const {
        return std::vector<CharacAndName>(std::begin(Characteristics), std::end(Characteristics));
    }

    const std::vector<dllCharacAndName> getDllCharacteristicsList() const {
        return std::vector<dllCharacAndName>(std::begin(dllCharacteristics), std::end(dllCharacteristics));
    }

private:

    CharacAndName Characteristics[15] = {
        {IMAGE_FILE_RELOCS_STRIPPED, "RELOCS_STRIPPED", "重定位信息已从文件中剥离"},
        {IMAGE_FILE_EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE", "是可执行文件（无未解析外部引用）"},
        {IMAGE_FILE_LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED", "COFF行号已从文件中删除"},
        {IMAGE_FILE_LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED", "COFF符号表项已从文件中剥离"},
        {IMAGE_FILE_AGGRESIVE_WS_TRIM, "AGGRESIVE_WS_TRIM", "积极剪裁工作集（已过时）"},
        {IMAGE_FILE_LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE", "支持大于2GB的地址"},
        {IMAGE_FILE_BYTES_REVERSED_LO, "BYTES_REVERSED_LO", "反转单词的字节数（已过时）"},
        {IMAGE_FILE_32BIT_MACHINE, "32BIT_MACHINE", "支持32位单词"},
        {IMAGE_FILE_DEBUG_STRIPPED, "DEBUG_STRIPPED", "调试信息已删除并单独存储"},
        {IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP", "可移动媒体文件复制到交换文件运行"},
        {IMAGE_FILE_NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP", "网络文件复制到交换文件运行"},
        {IMAGE_FILE_SYSTEM, "SYSTEM", "映像是系统文件"},
        {IMAGE_FILE_DLL, "DLL", "映像是DLL文件（不可直接运行）"},
        {IMAGE_FILE_UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY", "仅在单处理器计算机运行"},
        {IMAGE_FILE_BYTES_REVERSED_HI, "BYTES_REVERSED_HI", "反转单词的字节数（已过时）"}
    };
    dllCharacAndName dllCharacteristics[8] = {
        {IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, "DYNAMIC_BASE", "DLL可随机基址加载"},
        {IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, "FORCE_INTEGRITY", "代码完整性校验"},
        {IMAGE_DLLCHARACTERISTICS_NX_COMPAT, "NX_COMPAT", "兼容NX（数据区不可执行）"},
        {IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, "NO_ISOLATION", "不使用进程隔离"},
        {IMAGE_DLLCHARACTERISTICS_NO_SEH, "NO_SEH", "不使用结构化异常处理（SEH）"},
        {IMAGE_DLLCHARACTERISTICS_NO_BIND, "NO_BIND", "不绑定此映像"},
        {IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, "WDM_DRIVER", "使用WDM驱动模型"},
        {IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, "TERMINAL_SERVER_AWARE", "终端服务器感知"}
    };

    WORD m_curFileCharac;
    WORD m_curDllCharac;
};


}
}



#endif //PEHEADERMODIFIER_H
