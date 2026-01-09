//
// Created by Haohandc on 25-12-18.
//

#ifndef PEHEADERREADER_H
#define PEHEADERREADER_H

//提一嘴，底层上true->1，false->0。但是(大于0的数字)->true
// #define VALID 0
#define SUCCESS 0

// #define INVALID 1
#define DOS_SIGNATURE_INVALID 1
#define NT_SIGNATURE_INVALID 2
#define PE_TYPE_UNKNOWN 3
#define MEM_ALLOCA_FAILED 4
#define FILE_READ_FAILED 5

#include <Windows.h>
#include <string>
#include <codecvt>
#include <locale>

namespace PEFile {
    
    std::wstring ansiToUnicode(const std::string& ansiStr);
    
namespace Header {

class PEHeaderReader {
public:
    enum PE_TYPE {
        PE_UNKNOWN = 3,
        PE_32 = 32,
        PE_64 = 64,
    };

    //初始化指针和句柄
    PEHeaderReader();
    virtual ~PEHeaderReader() {
        ///相较于C语言（IDA中天天见的），创建和释放指针方便很多
        /*
         *int *p4 = (int *)malloc(sizeof(int)); C
         *int *p1 = new int; CPP
         *free(p4);C
         *delete p1;CPP
         */
        //动态分配的内存和句柄才需要手动释放，其他的实际上归这两个指针管理，不需要手动释放
        //跟C一个原则：只有申请的才需要释放（可能是因为C的malloc实在太显眼了，我才有释放普通指针的想法）
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
    }

    void close();
    //声明读取PE文件的函数
    //[[nodiscard]]，这个是如果返回值没有被使用，编译器会强制警告
    [[nodiscard]] virtual DWORD open(const std::wstring &wFilePath, bool WritePermission = false);


    PIMAGE_DOS_HEADER getDosHeader();
    PIMAGE_NT_HEADERS64 getNtHeaders64();
    PIMAGE_NT_HEADERS32 getNtHeaders32();



    //声明一个枚举类型的函数，专门用于获取PE文件的类型
    PE_TYPE getPEType() const {
        return peType;
    }


protected:
    /*
     *指针可以理解为是一种句柄，句柄广义上是一个指向一大堆数据的东西，然后handle实际上是个uint32_t，是一个存储地址的东西。
     *打开任务管理器可以看到一大堆句柄
     *以下来自https://www.cnblogs.com/vinsonLu/p/3613453.html
     *所以，Windows操作系统就采用进一步的间接：在进程的地址空间中设一张表，表里头专门保存一些编号和由这个编号对应一个地址，
     *而由那个地址去引用实际的对象，这个编号跟那个地址在数值上没有任何规律性的联系，纯粹是个映射而已。在Windows系统中，这个编号就叫做"句柄"。
     */
    HANDLE hFile;//定义句柄
    CHAR* pHeaderBuf;//实际上就是char*，MS应该是为了统一风格换了个名字


    PE_TYPE peType;

    WORD parsePESignature();//检测PE签名（16进制编辑器可以看到MZ和PE两个签名
    PIMAGE_DOS_HEADER pDosHeader;//DOS头
    //吐槽一下，早就对AI不靠谱深有体会，要不是我手边有书，我还看了，我就要被坑了，NT的附加头是由两个类型的，我不说AI根本不知道（应该是搜不到吧）
    PIMAGE_NT_HEADERS64 pNtHeaders64;//这个是PE32+的头
    PIMAGE_NT_HEADERS32 pNtHeaders32;//这个是PE32头
};

}
} // PEFile

// 二、int main(int argc, char* argv[]) 中括号内参数的作用
// main 函数的参数不是必须写（可以空着 int main()），但如果要接收命令行参数（比如传入 PE 文件路径），就必须用这两个参数，具体作用：
// 参数	含义
// argc	全称 argument count，表示命令行参数的个数（至少为 1，因为 argv[0] 是程序自身路径）
// argv	全称 argument vector，表示参数数组，argv[0] 是程序路径，argv[1]/argv[2] 是传入的参数
// 示例（你的 PE 解析场景）：
// 假设编译后程序叫 PEReader.exe，在命令行执行：
// cmd
// PEReader.exe D:\测试.exe
// 此时：
// argc = 2（参数个数：程序路径 + 文件路径）；
// argv[0] = "PEReader.exe"（程序自身路径）；
// argv[1] = "D:\\测试.exe"（你传入的 PE 文件路径）。
// ansiToUnicode可以用来转换控制台输入的文件地址
#endif //PEHEADERREADER_H
