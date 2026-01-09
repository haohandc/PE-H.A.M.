//
// Created by Haohandc on 25-12-18.
//

#include "../include/PEHeaderReader.h"
#include "../include/PEHeaderModifier.h"

#include <fstream>
#include <string>
#include <Windows.h>


namespace PEFile {
    //注：该函数由AI生成
    std::wstring ansiToUnicode(const std::string& ansiStr) {
        if (ansiStr.empty()) return L"";

        // 关键：CP_ACP = 系统默认ANSI编码（CMD的中文是GBK/CP936）
        int wLen = MultiByteToWideChar(
            CP_ACP,        // 替换原CP_UTF8，适配CMD的GBK编码
            0,             // 无特殊转换标志
            ansiStr.c_str(),// CMD传入的GBK编码char*
            -1,            // 自动识别字符串结束符
            nullptr,       // 先获取所需缓冲区长度
            0
        );

        if (wLen == 0) return L""; // 转换失败返回空

        std::wstring wStr(wLen - 1, 0);// AI:去除末尾的'\0'（多加了个 -1）
        MultiByteToWideChar(
            CP_ACP,
            0,
            ansiStr.c_str(),
            -1,
            &wStr[0],
            wLen
        );

        return wStr;
    }
namespace Header {
        //初始化指针和句柄
    PEHeaderReader::PEHeaderReader() : pDosHeader(nullptr),
        pNtHeaders64(nullptr),
        pNtHeaders32(nullptr),
        hFile(INVALID_HANDLE_VALUE),
        pHeaderBuf(nullptr),
        peType(PE_UNKNOWN)
        {}
    //构造函数，初始化成员变量，防止无效句柄，给个空指针防止野指针
    //野指针（有实际内容）会瞎指向某个内存地址，导致读取到错误的数据
    //这种用 冒号 的方法可以在构造函数 {}内的 代码执行前，对成员变量进行初始化
    //校验DOS头和NT头的签名，确认是有效的PE文件（可以考虑后续增加对elf文件的识别）
    //pDosHeader是个指向存放DosHeader这个结构体的指针，里面的魔数0x54AD(MZ)就是IMAGE_DOS_SIGNATURE
    //另外，这一部分也负责检测NT头，存储NT头



    WORD PEHeaderReader::parsePESignature() {
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return DOS_SIGNATURE_INVALID;//这个有助于标识功能，比一堆数值之类的好很多
        }
        //这个是定位NT头的file header的方法。IMAGE_FILE_HEADER是32/64头里面的一个成员结构体，而且不是第一个，所以不能用这个存储信息。
        //可选头之前的部分都是长一样的，所以可以用32的头去存
        PIMAGE_NT_HEADERS32 pTempNtHeader = (PIMAGE_NT_HEADERS32)(pHeaderBuf + pDosHeader->e_lfanew);
        if (pTempNtHeader == nullptr || pTempNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            return NT_SIGNATURE_INVALID;
        }
        //读取魔数，这里是指向成员结构体的magic变量，如果是32结构体，magic是0x10B，64的是0x20B
        WORD magic = pTempNtHeader->OptionalHeader.Magic;
        //如果是32头
        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            peType = PE_32;
            pNtHeaders32 = pTempNtHeader;
            pNtHeaders64 = nullptr;
        }
        //如果是64头
        else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            peType = PE_64;
            pNtHeaders64 = (PIMAGE_NT_HEADERS64)(pHeaderBuf + pDosHeader->e_lfanew);
            pNtHeaders32 = nullptr;
        }
        //未知魔数（考虑之后增加方法判别32/64，用于应对修改过魔数的文件）
        else {
            peType = PE_UNKNOWN;
            // return magic;
            return PE_TYPE_UNKNOWN;
        }
        return SUCCESS;
    }
/*注意！！！！readPEFile虽然写在下面，但应该是第一个执行的，你不读取文件你怎么检测其他东西呢*/

        // wFilePath: 支持中文目录等非英文目录
        // withWrite: true=读写权限，false=只读权限
    [[nodiscard]] DWORD PEHeaderReader::
        open(const std::wstring &wFilePath, bool WritePermission) {
        if (pHeaderBuf != nullptr) {
            delete[] pHeaderBuf;
            pHeaderBuf = nullptr;
        }
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
        // pDosHeader = nullptr;
        // pNtHeaders32 = nullptr;
        // pNtHeaders64 = nullptr;
        // peType = PE_UNKNOWN;
        //可调的读写权限，这样子类(修改部分)可直接复用句柄
        DWORD dwDesiredAccess = GENERIC_READ;
        if (WritePermission) {
            dwDesiredAccess |= GENERIC_WRITE;
        }

        //AI还是靠不住，不过我自己想的用string，AI也想的用string，然后提示类型不匹配LPCWSTR(看定义，发现实际上是utf-16的字符类型)，
        //再问了问AI知道有wstring这个东西，这样才能支持中文路径(这种工具鲁棒性必须高)
        hFile = CreateFileW(wFilePath.c_str(),
            dwDesiredAccess,//只读
            FILE_SHARE_READ | FILE_SHARE_WRITE,//FILE_SHARE_READ允许其他程序使用该文件（只读，不能写），为0则不行。为了兼容读写，要加上写权限
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        //文件打开失败
        if (hFile == INVALID_HANDLE_VALUE) {
            return GetLastError();
        }
        DWORD dwFileSize = GetFileSize(hFile, nullptr);
        if (dwFileSize == INVALID_FILE_SIZE) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return GetLastError();
        }

        //原来的是读取整个文件，参考了一下其他人写的，只读文件头。其他部分应该要lazydfu
        //分配内存，PE头再怎么也大不过4096B。如果是极小PE文件，按实际文件大小读取(整个文件)
        constexpr DWORD dwHeaderBufSize = 4096;
        DWORD dwActualReadSize = min(dwHeaderBufSize, dwFileSize);

        pHeaderBuf = new char[dwHeaderBufSize];

        // if (pHeaderBuf == nullptr) {
        //     CloseHandle(hFile);
        //     hFile = INVALID_HANDLE_VALUE;//这个是int64类型值
        //     return INVALID;
        // }
        //读取文件
        DWORD dwReadSize = 0;
        BOOL bReadSuccess = ReadFile(hFile, pHeaderBuf,
            dwActualReadSize, &dwReadSize, nullptr);
        //这BOOL实际上是int
        if (!bReadSuccess || dwReadSize < sizeof(IMAGE_DOS_HEADER)) {
            delete[] pHeaderBuf;
            pHeaderBuf = nullptr;
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return MEM_ALLOCA_FAILED;
        }
        //解析DOS
        pDosHeader = (PIMAGE_DOS_HEADER)pHeaderBuf;
        //校验PE
        if (parsePESignature() != SUCCESS) {
            delete[] pHeaderBuf;
            pHeaderBuf = nullptr;
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
            return PE_FAILED;
        }
        return SUCCESS;
    }
    void PEHeaderReader::close() {
        //如果文件没有被释放
        if (pHeaderBuf != nullptr) {
            delete[] pHeaderBuf;//带[]用来释放指针
            pHeaderBuf = nullptr;
        }
        // 如果文件句柄有效，关闭句柄
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            hFile = INVALID_HANDLE_VALUE;
        }
        pDosHeader = nullptr;
        pNtHeaders64 = nullptr;
        pNtHeaders32 = nullptr;
        peType = PE_UNKNOWN;
    }

    PIMAGE_DOS_HEADER PEHeaderReader::getDosHeader() {
        return pDosHeader != nullptr ? pDosHeader : nullptr;
    }
    PIMAGE_NT_HEADERS64 PEHeaderReader::getNtHeaders64() {
        return pNtHeaders64 != nullptr && peType == PE_64? pNtHeaders64 : nullptr;
    }
    PIMAGE_NT_HEADERS32 PEHeaderReader::getNtHeaders32() {
        return pNtHeaders32 != nullptr && peType == PE_32 ? pNtHeaders32 : nullptr;
    }



}
} // PEFile