#include "../include/mainwindow.h"
#include <QCloseEvent>   // 关闭窗口事件
#include <QDropEvent>    // 拖拽放下事件
#include <QDragEnterEvent>// 拖拽进入事件
#include <QMessageBox>   // 提示框（checkUnsavedChanges用）
#include <QFileInfo>     // 文件信息（拖拽时检查后缀用）
#include <QMimeData>
//
// Created by Haohandc on 25-12-30.
//

//信号与槽实际上很好理解
//信号就是某个按钮，事件被触发
//槽在被绑定到某个信号后，就会响应信号，执行动作

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
    , ui(new Ui::MainWindow())  // 初始化UI对象
    , m_peModifier(new PEFile::Header::PEHeaderModifier())  // 初始化PE后端对象
    , m_curFilePath("")
    , m_isModified(false)
{
    ui->setupUi(this);  // 将UI绑定到当前窗口
    this->setWindowTitle(tr("PE H.A.M."));
    this->setAcceptDrops(true);
    initPETreeWidget();  // 初始化PE结构树
    // 初始化Table样式
    ui->tableWidget->setColumnCount(2);
    ui->tableWidget->setHorizontalHeaderLabels({tr("字段名"), tr("值")});
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
}

MainWindow::~MainWindow() {
    delete m_peModifier;
    delete ui;
}

void MainWindow::on_OpenBtn_clicked() {
    if (!checkUnsavedChanges()) {
        return;
    }
    QString filePath = QFileDialog::getOpenFileName(
        this,
        tr("选择PE文件"),
        QDir::homePath(),
        tr("PE文件 (*.exe *.dll *.sys);;所有文件 (*.*)")
    );
    if (filePath.isEmpty()) return;

    parsePEFile(filePath);

    m_curFilePath = filePath;
    ui->statusbar->showMessage(tr("已打开：%1").arg(filePath));
}

void MainWindow::on_actionopen_triggered()
{
    on_OpenBtn_clicked();
}

void MainWindow::on_SaveBtn_clicked() {
    if (m_curFilePath.isEmpty() || !m_peModifier) {
        QMessageBox::warning(this, tr("警告"), tr("请先打开PE文件！"));
        // return;
    }
    int ret = m_peModifier->save();
    if (ret == SUCCESS) {
        // QMessageBox::information(this, tr("成功"), tr("修改已保存！"));
        ui->statusbar->showMessage(tr("已保存：%1").arg(m_curFilePath));
        m_isModified = false;
    } else {
        QMessageBox::critical(this, tr("失败"), tr("保存失败！错误码：%1").arg(ret));
        m_isModified = false;
    }
}

// 菜单Save动作（复用Save按钮逻辑）
void MainWindow::on_actionSave_triggered()
{
    on_SaveBtn_clicked();
}

void MainWindow::on_actionClose_triggered()
{
    if (!checkUnsavedChanges()) {
        return;
    }
    // 关闭文件 + 清空UI
    if (m_peModifier) m_peModifier->close();
    m_curFilePath = "";
    ui->tableWidget->clearContents();
    ui->statusbar->showMessage(tr("已关闭文件"));
    m_isModified = false;
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (!checkUnsavedChanges()) {
        event->ignore(); // 取消关闭窗口
    } else {
        event->accept(); // 允许关闭
    }
}

void MainWindow::dragEnterEvent(QDragEnterEvent *event)
{
    // 检查拖入的是否是文件，且是单个文件
    if (event->mimeData()->hasUrls() && event->mimeData()->urls().size() == 1) {
        QUrl url = event->mimeData()->urls().first();
        if (url.isLocalFile()) { // 是本地文件
            event->acceptProposedAction(); // 允许放下
        }
    }
}

void MainWindow::dropEvent(QDropEvent *event)
{
    // 先检查未保存修改
    if (!checkUnsavedChanges()) return;

    // 获取拖入的文件路径
    QUrl url = event->mimeData()->urls().first();
    QString filePath = url.toLocalFile();

    // 检查是否是PE文件
    QFileInfo fileInfo(filePath);
    QString suffix = fileInfo.suffix().toLower();
    if (suffix != "exe" && suffix != "dll" && suffix != "sys") {
        QMessageBox::warning(this, tr("警告"), tr("仅支持拖拽PE文件（.exe/.dll/.sys）！"));
        return;
    }

    // 解析PE文件（复用原有逻辑）
    parsePEFile(filePath);
    m_curFilePath = filePath;
    ui->statusbar->showMessage(tr("已打开：%1").arg(filePath));

    // 更新窗口名称
    QString fileName = fileInfo.fileName();
    this->setWindowTitle(tr("PE文件编辑器 - %1").arg(fileName));
}


void MainWindow::on_treeWidget_itemClicked(QTreeWidgetItem *item, [[maybe_unused]] int column)
{
    // 1. 强化空指针防护（核心崩溃点）
    if (m_curFilePath.isEmpty() || !m_peModifier ||
        m_peModifier->getPEType() == PEFile::Header::PEHeaderReader::PE_UNKNOWN) {
        QMessageBox::warning(this, tr("警告"), tr("PE文件未打开"));
        return;
    }

    // 清空TableWidget
    ui->tableWidget->clearContents();
    ui->tableWidget->setRowCount(0);
    ui->tableWidget->setColumnCount(2);
    ui->tableWidget->setHorizontalHeaderLabels({tr("字段名"), tr("值")});

    // 根据点击的节点填充数据
    QString itemText = item->text(0);
    if (itemText == tr("Dos Header")) {
        PIMAGE_DOS_HEADER dosHeader = m_peModifier->getDosHeader();
        if (!dosHeader) { // 空指针防护
            QMessageBox::warning(this, tr("警告"), tr("Dos Header解析失败！"));
            return;
        }
        // 原有Dos Header逻辑（不变）
        QList<QPair<QString, QString>> dosFields = {
            {tr("e_magic"), QString("0x%1").arg(dosHeader->e_magic, 4, 16, QChar('0'))},
            {tr("e_cblp"), QString("0x%1").arg(dosHeader->e_cblp, 4, 16, QChar('0'))},
            {tr("e_cp"), QString("0x%1").arg(dosHeader->e_cp, 4, 16, QChar('0'))},
            {tr("e_crlc"), QString("0x%1").arg(dosHeader->e_crlc, 4, 16, QChar('0'))},
            {tr("e_cparhdr"), QString("0x%1").arg(dosHeader->e_cparhdr, 4, 16, QChar('0'))},
            {tr("e_minalloc"), QString("0x%1").arg(dosHeader->e_minalloc, 4, 16, QChar('0'))},
            {tr("e_maxalloc"), QString("0x%1").arg(dosHeader->e_maxalloc, 4, 16, QChar('0'))},
            {tr("e_ss"), QString("0x%1").arg(dosHeader->e_ss, 4, 16, QChar('0'))},
            {tr("e_sp"), QString("0x%1").arg(dosHeader->e_sp, 4, 16, QChar('0'))},
            {tr("e_csum"), QString("0x%1").arg(dosHeader->e_csum, 4, 16, QChar('0'))},
            {tr("e_ip"), QString("0x%1").arg(dosHeader->e_ip, 4, 16, QChar('0'))},
            {tr("e_cs"), QString("0x%1").arg(dosHeader->e_cs, 4, 16, QChar('0'))},
            {tr("e_lfarlc"), QString("0x%1").arg(dosHeader->e_lfarlc, 4, 16, QChar('0'))},
            {tr("e_ovno"), QString("0x%1").arg(dosHeader->e_ovno, 4, 16, QChar('0'))},
            {tr("e_lfanew"), QString("0x%1").arg(dosHeader->e_lfanew, 8, 16, QChar('0'))}
        };

        for (int i = 0; i < dosFields.size(); ++i) {
            ui->tableWidget->insertRow(i);
            ui->tableWidget->setItem(i, 0, new QTableWidgetItem(dosFields[i].first));
            ui->tableWidget->setItem(i, 1, new QTableWidgetItem(dosFields[i].second));
        }
    } else if (itemText == tr("File Header")) {
        // 2. 获取File Characteristics
        WORD charac = m_peModifier->getFileCharacteristics();
        if (charac == 0 && m_peModifier->getPEType() != PEFile::Header::PEHeaderReader::PE_UNKNOWN) {
            QMessageBox::warning(this, tr("警告"), tr("File Characteristics解析失败！"));
            return;
        }

        // 3. 分PE类型获取FileHeader
        QList<QPair<QString, QString>> fileFields;
        if (m_peModifier->getPEType() == PEFile::Header::PEHeaderReader::PE_32) {
            PIMAGE_NT_HEADERS32 nt32 = m_peModifier->getNtHeaders32();
            if (!nt32) {
                QMessageBox::warning(this, tr("警告"), tr("PE32头解析失败！"));
                return;
            }
            fileFields = {
                {tr("Machine"), QString("0x%1").arg(nt32->FileHeader.Machine, 4, 16, QChar('0'))},
                {tr("NumberOfSections"), QString("%1").arg(nt32->FileHeader.NumberOfSections)},
                {tr("TimeDateStamp"), QString("0x%1").arg(nt32->FileHeader.TimeDateStamp, 8, 16, QChar('0'))},
                {tr("PointerToSymbolTable"), QString("0x%1").arg(nt32->FileHeader.PointerToSymbolTable, 8, 16, QChar('0'))},
                {tr("NumberOfSymbols"), QString("%1").arg(nt32->FileHeader.NumberOfSymbols)},
                {tr("SizeOfOptionalHeader"), QString("%1").arg(nt32->FileHeader.SizeOfOptionalHeader)},
                {tr("Characteristics"), QString("0x%1 (点击编辑)").arg(charac, 4, 16, QChar('0'))}
            };
        } else if (m_peModifier->getPEType() == PEFile::Header::PEHeaderReader::PE_64) {
            PIMAGE_NT_HEADERS64 nt64 = m_peModifier->getNtHeaders64();
            if (!nt64) {
                QMessageBox::warning(this, tr("警告"), tr("PE64头解析失败！"));
                return;
            }
            fileFields = {
                {tr("Machine"), QString("0x%1").arg(nt64->FileHeader.Machine, 4, 16, QChar('0'))},
                {tr("NumberOfSections"), QString("%1").arg(nt64->FileHeader.NumberOfSections)},
                {tr("TimeDateStamp"), QString("0x%1").arg(nt64->FileHeader.TimeDateStamp, 8, 16, QChar('0'))},
                {tr("PointerToSymbolTable"), QString("0x%1").arg(nt64->FileHeader.PointerToSymbolTable, 8, 16, QChar('0'))},
                {tr("NumberOfSymbols"), QString("%1").arg(nt64->FileHeader.NumberOfSymbols)},
                {tr("SizeOfOptionalHeader"), QString("%1").arg(nt64->FileHeader.SizeOfOptionalHeader)},
                {tr("Characteristics"), QString("0x%1 (点击编辑)").arg(charac, 4, 16, QChar('0'))}
            };
        }

        // 填充TableWidget
        for (int i = 0; i < fileFields.size(); ++i) {
            ui->tableWidget->insertRow(i);
            ui->tableWidget->setItem(i, 0, new QTableWidgetItem(fileFields[i].first));
            ui->tableWidget->setItem(i, 1, new QTableWidgetItem(fileFields[i].second));
        }

        // ========== 移除原有弹框逻辑 ==========
        // 弹框逻辑移到tableWidget的cellClicked槽函数中
    } else if (itemText == tr("Optional Header")) {
        // 5. 安全获取DLL Characteristics
        WORD dllCharac = m_peModifier->getDllCharacteristics();
        if (dllCharac == 0 && m_peModifier->getPEType() != PEFile::Header::PEHeaderReader::PE_UNKNOWN) {
            QMessageBox::warning(this, tr("警告"), tr("DLL Characteristics解析失败！"));
            return;
        }

        // 分PE类型填充Optional Header
        QList<QPair<QString, QString>> optFields;
        if (m_peModifier->getPEType() == PEFile::Header::PEHeaderReader::PE_32) {
            PIMAGE_NT_HEADERS32 nt32 = m_peModifier->getNtHeaders32();
            if (!nt32) {
                QMessageBox::warning(this, tr("警告"), tr("PE32头解析失败！"));
                return;
            }
            PIMAGE_OPTIONAL_HEADER32 optHeader = &nt32->OptionalHeader;
            optFields = {
                {tr("Magic"), QString("0x%1").arg(optHeader->Magic, 4, 16, QChar('0'))},
                {tr("MajorLinkerVersion"), QString("%1").arg(optHeader->MajorLinkerVersion)},
                {tr("MinorLinkerVersion"), QString("%1").arg(optHeader->MinorLinkerVersion)},
                {tr("SizeOfCode"), QString("0x%1").arg(optHeader->SizeOfCode, 8, 16, QChar('0'))},
                {tr("SizeOfInitializedData"), QString("0x%1").arg(optHeader->SizeOfInitializedData, 8, 16, QChar('0'))},
                {tr("SizeOfUninitializedData"), QString("0x%1").arg(optHeader->SizeOfUninitializedData, 8, 16, QChar('0'))},
                {tr("AddressOfEntryPoint"), QString("0x%1").arg(optHeader->AddressOfEntryPoint, 8, 16, QChar('0'))},
                {tr("BaseOfCode"), QString("0x%1").arg(optHeader->BaseOfCode, 8, 16, QChar('0'))},
                {tr("BaseOfData"), QString("0x%1").arg(optHeader->BaseOfData, 8, 16, QChar('0'))},
                {tr("ImageBase"), QString("0x%1").arg(optHeader->ImageBase, 8, 16, QChar('0'))},
                {tr("SectionAlignment"), QString("0x%1").arg(optHeader->SectionAlignment, 8, 16, QChar('0'))},
                {tr("FileAlignment"), QString("0x%1").arg(optHeader->FileAlignment, 8, 16, QChar('0'))},
                {tr("DllCharacteristics"), QString("0x%1 (点击编辑)").arg(dllCharac, 4, 16, QChar('0'))}
            };
        } else if (m_peModifier->getPEType() == PEFile::Header::PEHeaderReader::PE_64) {
            PIMAGE_NT_HEADERS64 nt64 = m_peModifier->getNtHeaders64();
            if (!nt64) {
                QMessageBox::warning(this, tr("警告"), tr("PE64头解析失败！"));
                return;
            }
            PIMAGE_OPTIONAL_HEADER64 optHeader = &nt64->OptionalHeader;
            optFields = {
                {tr("Magic"), QString("0x%1").arg(optHeader->Magic, 4, 16, QChar('0'))},
                {tr("MajorLinkerVersion"), QString("%1").arg(optHeader->MajorLinkerVersion)},
                {tr("MinorLinkerVersion"), QString("%1").arg(optHeader->MinorLinkerVersion)},
                {tr("SizeOfCode"), QString("0x%1").arg(optHeader->SizeOfCode, 8, 16, QChar('0'))},
                {tr("SizeOfInitializedData"), QString("0x%1").arg(optHeader->SizeOfInitializedData, 8, 16, QChar('0'))},
                {tr("SizeOfUninitializedData"), QString("0x%1").arg(optHeader->SizeOfUninitializedData, 8, 16, QChar('0'))},
                {tr("AddressOfEntryPoint"), QString("0x%1").arg(optHeader->AddressOfEntryPoint, 8, 16, QChar('0'))},
                {tr("BaseOfCode"), QString("0x%1").arg(optHeader->BaseOfCode, 8, 16, QChar('0'))},
                {tr("ImageBase"), QString("0x%1").arg(optHeader->ImageBase, 16, 16, QChar('0'))},
                {tr("SectionAlignment"), QString("0x%1").arg(optHeader->SectionAlignment, 8, 16, QChar('0'))},
                {tr("FileAlignment"), QString("0x%1").arg(optHeader->FileAlignment, 8, 16, QChar('0'))},
                {tr("DllCharacteristics"), QString("0x%1 (点击编辑)").arg(dllCharac, 4, 16, QChar('0'))}
            };
        }

        // 填充TableWidget
        for (int i = 0; i < optFields.size(); ++i) {
            ui->tableWidget->insertRow(i);
            ui->tableWidget->setItem(i, 0, new QTableWidgetItem(optFields[i].first));
            ui->tableWidget->setItem(i, 1, new QTableWidgetItem(optFields[i].second));
        }

        // ========== 移除原有弹框逻辑 ==========
        // 弹框逻辑移到tableWidget的cellClicked槽函数中
    }
}

// ========== TableWidget单元格点击事件（弹编辑框） ==========
void MainWindow::on_tableWidget_cellClicked(int row, int column)
{
    // 仅处理“值”列（column=1）的点击
    if (column != 1 || m_curFilePath.isEmpty() || !m_peModifier) return;

    // 获取当前点击的字段名
    QTableWidgetItem *fieldItem = ui->tableWidget->item(row, 0);
    if (!fieldItem) return;
    QString fieldName = fieldItem->text();

    // 获取当前选中的Tree节点
    QTreeWidgetItem *curTreeItem = ui->treeWidget->currentItem();
    if (!curTreeItem) return;
    QString treeItemText = curTreeItem->text(0);

    // 处理File Characteristics编辑
    if (treeItemText == tr("File Header") && fieldName == tr("Characteristics")) {
        WORD curCharac = m_peModifier->getFileCharacteristics();
        try {
            CharacteristicsDialog dlg(EditType::FILE_CHARAC, curCharac, this);
            if (dlg.exec() == QDialog::Accepted) {
                WORD newCharac = dlg.getModifiedValue();
                int ret = m_peModifier->setFileCharacteristics(newCharac);
                if (ret != SUCCESS) {
                    QMessageBox::warning(this, tr("警告"), tr("修改Characteristics失败！错误码：%1").arg(ret));
                    return;
                }
                // 更新Table显示
                ui->tableWidget->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(newCharac, 4, 16, QChar('0'))));
                ui->statusbar->showMessage(tr("File Characteristics已修改，需保存生效"));
                m_isModified = true;
            }
        } catch (const std::exception& e) {
            // 打印具体异常信息（控制台输出）
            qCritical() << "[MainWindow] 打开File特征对话框失败：" << e.what();
            QMessageBox::critical(this, tr("错误"), tr("打开编辑对话框失败：%1").arg(e.what()));
        } catch (...) {
            qCritical() << "[MainWindow] 打开File特征对话框失败：未知异常";
            QMessageBox::critical(this, tr("错误"), tr("打开编辑对话框失败：未知异常"));
        }
    }
    // 处理DLL Characteristics编辑
    else if (treeItemText == tr("Optional Header") && fieldName == tr("DllCharacteristics")) {
        WORD curDllCharac = m_peModifier->getDllCharacteristics();
        try {
            CharacteristicsDialog dlg(EditType::DLL_CHARAC, curDllCharac, this);
            if (dlg.exec() == QDialog::Accepted) {
                WORD newDllCharac = dlg.getModifiedValue();
                int ret = m_peModifier->setDllCharacteristics(newDllCharac);
                if (ret != SUCCESS) {
                    QMessageBox::warning(this, tr("警告"), tr("修改DLL Characteristics失败！错误码：%1").arg(ret));
                    return;
                }
                // 更新Table显示
                ui->tableWidget->setItem(row, 1, new QTableWidgetItem(QString("0x%1").arg(newDllCharac, 4, 16, QChar('0'))));
                ui->statusbar->showMessage(tr("DLL Characteristics已修改，需保存生效"));
            }
        } catch (...) {
            QMessageBox::critical(this, tr("错误"), tr("打开编辑对话框失败！"));
        }
    }
}


void MainWindow::parsePEFile(const QString &filePath)
{
    // 转换路径：QString → std::wstring
    std::wstring wFilePath = filePath.toStdWString();

    // 调用后端打开文件（读写模式）
    DWORD ret = m_peModifier->open(wFilePath, true);
    if (ret != SUCCESS) {
        QMessageBox::critical(this, tr("失败"), tr("打开PE文件失败！错误码：%1").arg(ret));
        return;
    }

    // 验证PE类型
    if (m_peModifier->getPEType() == PEFile::Header::PEHeaderReader::PE_UNKNOWN) {
        QMessageBox::critical(this, tr("失败"), tr("不是合法的PE文件！"));
        m_peModifier->close();
        return;
    }

    // QMessageBox::information(this, tr("成功"), tr("PE文件解析成功！"));
}

void MainWindow::initPETreeWidget()
{
    ui->treeWidget->clear();
    // 构建PE结构树
    QTreeWidgetItem *root = new QTreeWidgetItem(ui->treeWidget);
    root->setText(0, tr("PE Structure"));

    QTreeWidgetItem *dosHeader = new QTreeWidgetItem(root);
    dosHeader->setText(0, tr("Dos Header"));

    QTreeWidgetItem *ntHeaders = new QTreeWidgetItem(root);
    ntHeaders->setText(0, tr("Nt Headers"));

    QTreeWidgetItem *fileHeader = new QTreeWidgetItem(ntHeaders);
    fileHeader->setText(0, tr("File Header"));

    QTreeWidgetItem *optHeader = new QTreeWidgetItem(ntHeaders);
    optHeader->setText(0, tr("Optional Header"));

    QTreeWidgetItem *dataDir = new QTreeWidgetItem(optHeader);
    dataDir->setText(0, tr("Data Directories"));

    QTreeWidgetItem *sectionHeader = new QTreeWidgetItem(ntHeaders);
    sectionHeader->setText(0, tr("Section Headers"));

    ui->treeWidget->expandAll();
}


// 返回值：true=继续操作（保存/不保存），false=取消操作
bool MainWindow::checkUnsavedChanges()
{
    if (!m_isModified) return true; // 无修改，直接继续

    // 弹出提示框
    QMessageBox::StandardButton ret = QMessageBox::question(
        this,
        tr("提示"),
        tr("当前文件有未保存的修改，是否保存？"),
        QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel
    );

    switch (ret) {
        case QMessageBox::Save:
            // 用户选择保存：调用保存逻辑
            on_SaveBtn_clicked();
            return true;
        case QMessageBox::Discard:
            // 用户选择放弃保存：直接继续
            return true;
        case QMessageBox::Cancel:
            // 用户选择取消：终止当前操作
            return false;
        default:
            return false;
    }
}