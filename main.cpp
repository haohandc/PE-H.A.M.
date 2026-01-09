// #include <iostream>
// #include <Windows.h>
// #include <string>
// #include "include/PEHeaderReader.h"
// #include "include/PEHeaderModifier.h"

#include "include/mainwindow.h"
#include <QStyleFactory>
#include <QApplication>


int main(int argc, char* argv[]) {
    QApplication app(argc, argv);
    MainWindow window;
    app.setStyle(QStyleFactory::create("Fusion"));
    // // 处理命令行参数（拖拽文件/右键打开方式）
    // QCommandLineParser parser;
    // parser.addPositionalArgument("file", tr("要打开的PE文件路径"));
    // parser.process(app);
    //
    // // 如果有文件参数，自动打开
    // QStringList args = parser.positionalArguments();
    // if (!args.isEmpty()) {
    //     QString filePath = args.first();
    //     if (QFile::exists(filePath)) {
    //         window.parsePEFile(filePath); // 调用MainWindow的解析函数
    //         window.m_curFilePath = filePath; // 注意：需要将m_curFilePath改为public，或添加setter函数
    //         window.ui->statusbar->showMessage(tr("已打开：%1").arg(filePath)); // 同理，ui改为public或添加接口
    //     }
    // }
    window.show();
    return app.exec();

    // using namespace PEFile::Header;
    // if (argc < 2) {
    //     std::cout << "没有要分析的文件。用法：" << std::endl;
    //     std::cout << "PEHeader_Analyzer <yourfile>";
    //     return 0;
    // }
    // std::string tmp = argv[1];
    // const std::wstring wFilePath = PEFile::ansiToUnicode(tmp);
    //
    // PEHeaderModifier File;
    // DWORD flag = File.open(wFilePath, true);
    // if (flag != SUCCESS) {
    //     std::cerr << "Failed to read PE file" << std::endl;
    // }
    // std::cout << "Successfully open" << std::endl;
    //
    // if (File.getPEType() == PEHeaderReader::PE_UNKNOWN) {
    //     std::cerr << "Failed to read PE file" << std::endl;
    //     return 0;
    // }
    // std::cout << "Characteristics:0x" << std::hex << File.getFileCharacteristics() << std::endl;
    // File.setFileCharacteristics(IMAGE_FILE_RELOCS_STRIPPED, 2);
    // // File.setFileCharacteristics(0x102, 0);
    // File.save();
    // std::cout << "Characteristics:0x" << std::hex << File.getFileCharacteristics() << std::endl;
    //
    // //一定要手动调用。实际到UI界面，不能说我设置完程序就被改了吧。到时候这个需要绑定save按钮和退出时的提示
    // // std::cout << "Modified File Characteristics:0x" << std::hex << File.getFileCharacteristics();
    // File.close();

    // QApplication a(argc, argv);
    // QPushButton button("Hello world!", nullptr);
    // button.resize(200, 100);
    // button.show();
    // return QApplication::exec();
    return 0;
}