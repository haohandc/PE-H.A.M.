//
// Created by Haohandc on 25-12-30.
//

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>
#include <QTreeWidgetItem>

#include <QUrl>          // 拖拽路径解析用
#include "../ui/ui_mainwindow.h"
#include "../include/CharacteristicsDialog.h"

#include "../include/PEHeaderReader.h"
#include "../include/PEHeaderModifier.h"

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = Q_NULLPTR);
    ~MainWindow() override;
private slots:
    //  信号槽：自动关联（命名规则：on_控件名_信号名）
    // 1. Open按钮点击（UI中按钮对象名：OpenBtn）
    void on_OpenBtn_clicked();
    // 2. Save按钮点击（UI中按钮对象名：SaveBtn）
    void on_SaveBtn_clicked();
    // 3. 菜单Open动作（UI中动作对象名：actionopen）
    void on_actionopen_triggered();
    // 4. 菜单Close动作（UI中动作对象名：actionClose）
    void on_actionClose_triggered();
    // 5. 菜单Save动作（UI中动作对象名：actionSave）
    void on_actionSave_triggered();
    // 6. TreeWidget节点点击（UI中树对象名：treeWidget）
    void on_treeWidget_itemClicked(QTreeWidgetItem *item, int column);

    // Table单元格点击槽函数
    void on_tableWidget_cellClicked(int row, int column);
private:
    Ui::MainWindow *ui;  // UI对象指针（关联自动生成的UI类）
    PEFile::Header::PEHeaderModifier *m_peModifier;  // PE后端对象
    QString m_curFilePath;  // 当前打开的文件路径
    bool m_isModified;
    // 解析PE文件并填充UI
    void parsePEFile(const QString &filePath);
    // 初始化TreeWidget的PE结构
    void initPETreeWidget();
    bool checkUnsavedChanges();
protected://这几个访问权限必须放protected
    // 1. 窗口关闭事件（检查未保存修改）
    void closeEvent(QCloseEvent *event) override;
    // 2. 拖拽文件进入窗口事件（检查是否是合法文件）
    void dragEnterEvent(QDragEnterEvent *event) override;
    // 3. 拖拽文件放下事件（处理文件打开）
    void dropEvent(QDropEvent *event) override;
};

#endif //MAINWINDOW_H
