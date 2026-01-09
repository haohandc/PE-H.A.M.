#ifndef CHARACTERISTICSDIALOG_H
#define CHARACTERISTICSDIALOG_H

#include <QDialog>
#include <QCheckBox>
#include <QList>
#include "../ui/ui_dialog.h" // 引入UI头文件
#include "../include/PEHeaderModifier.h"

// 编辑类型：File/DLL Characteristics
enum class EditType {
    FILE_CHARAC = 1,
    DLL_CHARAC = 2
};

class CharacteristicsDialog : public QDialog {
    Q_OBJECT
public:
    // 构造函数：编辑类型 + 当前特征值 + 父窗口
    explicit CharacteristicsDialog(EditType type, WORD curValue, QWidget *parent = nullptr);
    ~CharacteristicsDialog() override;

    // 获取修改后的特征值
    WORD getModifiedValue() const { return m_modifiedValue; }

private slots:
    // 复选框状态变更（同步特征值）
    void onCheckBoxStateChanged(Qt::CheckState state);
    // 确定/取消按钮响应（复用UI的buttonBox信号）
    void onBtnOkClicked();
    void onBtnCancelClicked();

private:
    // 初始化：移除静态控件 + 动态创建特征项复选框
    void initDynamicCheckBoxes();
    // 根据当前值初始化复选框勾选状态
    void initCheckBoxStates(WORD curValue);
    // 安全转换std::string到QString
    QString safeStdStringToQString(const std::string& str);

    // 核心成员
    Ui::Dialog *ui;                      // UI对象
    EditType m_editType;                // 编辑类型
    WORD m_originalValue;               // 原始特征值
    WORD m_modifiedValue;               // 修改后特征值
    QList<QCheckBox*> m_dynamicCheckBoxes; // 动态创建的复选框列表
};

#endif // CHARACTERISTICSDIALOG_H