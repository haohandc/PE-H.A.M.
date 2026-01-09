//
// Created by Haohandc on 25-12-19.
//

#include "../include/PEHeaderModifier.h"
#include "../include/PEHeaderReader.h"
#include <optional>

namespace PEFile {
namespace Header {
    PEHeaderModifier::PEHeaderModifier() : PEHeaderReader(), m_curFileCharac(0), m_curDllCharac(0)
    {};

    //重写，实现中这里的成员变量留作未来的功能扩展，比如撤销

    // wFilePath: 支持中文目录等非英文目录
    // withWrite: true=读写权限，false=只读权限
    DWORD PEHeaderModifier::open(const std::wstring &wFilePath, bool WritePermission) {
        DWORD ret = PEHeaderReader::open(wFilePath, WritePermission);
        if (ret != SUCCESS) {
            return ret;
        }
        // if (peType == PE_32) {
        //     m_curFileCharac = pNtHeaders32->FileHeader.Characteristics;
        //     m_curDllCharac = pNtHeaders32->OptionalHeader.DllCharacteristics;
        // } else if (peType == PE_64) {
        //     m_curFileCharac = pNtHeaders64->FileHeader.Characteristics;
        //     m_curDllCharac = pNtHeaders64->OptionalHeader.DllCharacteristics;
        // } else {
        //     m_curFileCharac = 0xFFFF;
        //     m_curDllCharac = 0xFFFF;
        //     return PE_FAILED;
        // }
        m_curFileCharac = getFileCharacteristics();
        m_curDllCharac = getDllCharacteristics();

        return SUCCESS;
    }
    WORD PEHeaderModifier::getFileCharacteristics() {
        if (this->peType == PE_UNKNOWN || this->pHeaderBuf == nullptr) {
            return PE_TYPE_UNKNOWN;
        }
        if (this->peType == PE_32) {
            return this->pNtHeaders32->FileHeader.Characteristics;
        }
        else if (this->peType == PE_64) {
            return this->pNtHeaders64->FileHeader.Characteristics;
        }
        return m_curFileCharac;
    }

    //target value 传入逆向修改成的数值
    //mode(默认为0) 0:覆写  1:切换  2:删除
    int PEHeaderModifier::setFileCharacteristics(WORD targetvalue, int mode) {
        if (this->peType == PE_UNKNOWN || this->pHeaderBuf == nullptr) {
            return PE_TYPE_UNKNOWN;
        }
        if (mode < 0 || mode > 2) {
            return 0xFFFF;
        }
        WORD newFileCharac = m_curFileCharac;
        switch (mode) {
            case 0:
                newFileCharac = targetvalue;
                break;
            case 1:
                newFileCharac |= targetvalue;
                break;
            case 2:
                newFileCharac &= ~targetvalue;
                break;
            default:
                break;
        }
        if (this->peType == PE_32) {
            this->pNtHeaders32->FileHeader.Characteristics = newFileCharac;
        }
        else if (this->peType == PE_64) {
            this->pNtHeaders64->FileHeader.Characteristics = newFileCharac;
        }
        m_curFileCharac = newFileCharac;
        return SUCCESS;
    }

    WORD PEHeaderModifier::getDllCharacteristics() {
        if (this->peType == PE_UNKNOWN || this->pHeaderBuf == nullptr) {
            return ERROR;
        }
        if (this->peType == PE_32) {
            return this->pNtHeaders32->OptionalHeader.DllCharacteristics;
        }
        else if (this->peType == PE_64) {
            return this->pNtHeaders64->OptionalHeader.DllCharacteristics;
        }
        return m_curDllCharac;
    }

    //target value 传入逆向修改成的数值
    //mode(默认为0) 0:覆写  1:增加特征  2:删除特征
    int PEHeaderModifier::setDllCharacteristics(WORD targetvalue, int mode) {
        if (this->peType == PE_UNKNOWN || this->pHeaderBuf == nullptr) {
            return PE_TYPE_UNKNOWN;
        }
        if (mode < 0 || mode > 2) {
            return INVALID_PARAMETER;
        }
        WORD newDllCharac = m_curDllCharac;
        switch (mode) {
            case 0:
                newDllCharac = targetvalue;
                break;
            case 1:
                newDllCharac |= targetvalue;
                break;
            case 2:
                newDllCharac &= ~targetvalue;
                break;
            default:
                return INVALID_PARAMETER;
        }
        if (this->peType == PE_32) {
            this->pNtHeaders32->OptionalHeader.DllCharacteristics = newDllCharac;
        }
        else if (this->peType == PE_64) {
            this->pNtHeaders64->OptionalHeader.DllCharacteristics = newDllCharac;
        }
        m_curDllCharac = newDllCharac;
        return SUCCESS;
    }
    DWORD PEHeaderModifier::save() {
        //检查句柄和缓冲区（就是内存的某一部分）
        if (this-> hFile == INVALID_HANDLE_VALUE || this-> pHeaderBuf == nullptr) {
            return FILE_NOT_OPEN;
        }
        //设置偏移
        LARGE_INTEGER fileOffset{};
        if (!SetFilePointerEx(this->hFile, fileOffset, nullptr, FILE_BEGIN)) {
            return PE_FAILED;
        }

        DWORD dwFileSize = GetFileSize(this->hFile, nullptr);
        if (dwFileSize == INVALID_FILE_SIZE) {
            return PE_FAILED;
        }

        DWORD dwWriteSize = min(static_cast<DWORD>(4096), dwFileSize);
        //写入
        DWORD dwWritten = 0;
        BOOL writeOk = WriteFile(
            this->hFile,
            this->pHeaderBuf,
            dwWriteSize,
            &dwWritten,
            nullptr
        );
        if (!writeOk || dwWritten != dwWriteSize) {
            return GetLastError();
        }
        FlushFileBuffers(this->hFile);
        return SUCCESS;
    }

}
}
