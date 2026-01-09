#include "../include/CharacteristicsDialog.h"
#include <QDebug>
#include <QMessageBox>

// 构造函数：加载UI + 初始化动态复选框
CharacteristicsDialog::CharacteristicsDialog(EditType type, WORD curValue, QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::Dialog)
    , m_editType(type)
    , m_originalValue(curValue)
    , m_modifiedValue(curValue)
{
    // 1. 加载UI（Qt Designer生成的框架）
    ui->setupUi(this);

    // 2. 校验编辑类型合法性
    if (m_editType != EditType::FILE_CHARAC && m_editType != EditType::DLL_CHARAC) {
        QMessageBox::critical(this, tr("错误"), tr("非法的编辑类型！"));
        reject();
        return;
    }

    // 3. 设置窗口标题
    setWindowTitle(type == EditType::FILE_CHARAC ? tr("File Characteristics 编辑") : tr("DLL Characteristics 编辑"));
    setMinimumSize(500, 400); // 调整窗口最小尺寸

    // 4. 移除UI里的静态控件（单个checkBox + spacer），替换为动态复选框
    initDynamicCheckBoxes();

    // 5. 初始化复选框勾选状态
    initCheckBoxStates(curValue);

    // 6. 重新绑定按钮信号（替换UI默认的accept/reject，增加业务逻辑）
    disconnect(ui->buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
    disconnect(ui->buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &CharacteristicsDialog::onBtnOkClicked);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &CharacteristicsDialog::onBtnCancelClicked);
}

// 析构函数：释放UI和动态控件
CharacteristicsDialog::~CharacteristicsDialog() {
    // 释放动态创建的复选框
    for (QCheckBox *cb : m_dynamicCheckBoxes) {
        delete cb;
    }
    m_dynamicCheckBoxes.clear();
    // 释放UI对象
    delete ui;
}

// 核心：移除静态控件 + 动态创建对应数量的特征项复选框
void CharacteristicsDialog::initDynamicCheckBoxes() {
    // 1. 移除UI里的静态控件（单个checkBox + spacer）
    delete ui->checkBox;
    ui->checkBox = nullptr; // 置空避免野指针
    ui->verticalLayout->removeItem(ui->verticalSpacer);
    delete ui->verticalSpacer;
    ui->verticalSpacer = nullptr;

    // 2. 初始化PEModifier，获取特征列表
    PEFile::Header::PEHeaderModifier modifier;
    if (m_editType == EditType::FILE_CHARAC) {
        // File特征：15项 → 动态创建15个复选框
        auto fileList = modifier.getFileCharacteristicsList();
        if (fileList.size() != 15) {
            qCritical() << "File特征列表数量异常：" << fileList.size();
            QMessageBox::warning(this, tr("警告"), tr("File特征列表加载异常！"));
            return;
        }
        // 遍历创建复选框
        for (const auto& item : fileList) {
            QCheckBox *cb = new QCheckBox(QString("%1: %2")
                .arg(safeStdStringToQString(item.name))
                .arg(safeStdStringToQString(item.desc)));
            cb->setObjectName(QString::number(item.Characteristics)); // 绑定特征值
            ui->verticalLayout->addWidget(cb); // 添加到主布局
            m_dynamicCheckBoxes.append(cb);
            // 绑定状态变更信号
            connect(cb, &QCheckBox::checkStateChanged, this, &CharacteristicsDialog::onCheckBoxStateChanged);
        }
    } else {
        // DLL特征：8项 → 动态创建8个复选框
        auto dllList = modifier.getDllCharacteristicsList();
        if (dllList.size() != 8) {
            qCritical() << "DLL特征列表数量异常：" << dllList.size();
            QMessageBox::warning(this, tr("警告"), tr("DLL特征列表加载异常！"));
            return;
        }
        // 遍历创建复选框
        for (const auto& item : dllList) {
            QCheckBox *cb = new QCheckBox(QString("%1: %2")
                .arg(safeStdStringToQString(item.name))
                .arg(safeStdStringToQString(item.desc)));
            cb->setObjectName(QString::number(item.dllCharacteristics)); // 绑定特征值
            ui->verticalLayout->addWidget(cb); // 添加到主布局
            m_dynamicCheckBoxes.append(cb);
            // 绑定状态变更信号
            connect(cb, &QCheckBox::checkStateChanged, this, &CharacteristicsDialog::onCheckBoxStateChanged);
        }
    }

    // 3. 添加伸缩项（让复选框置顶，按钮置底）
    QSpacerItem *spacer = new QSpacerItem(20, 40, QSizePolicy::Minimum, QSizePolicy::Expanding);
    ui->verticalLayout->insertItem(m_dynamicCheckBoxes.count(), spacer); // 插入到复选框和按钮之间
}

// 根据当前特征值初始化复选框勾选状态
void CharacteristicsDialog::initCheckBoxStates(WORD curValue) {
    for (QCheckBox *cb : m_dynamicCheckBoxes) {
        // 安全解析特征值
        bool convertOk = false;
        WORD flag = cb->objectName().toUInt(&convertOk);
        if (!convertOk || flag > 0xFFFF) {
            cb->setEnabled(false); // 禁用非法项
            continue;
        }
        // 按位与判断是否勾选
        cb->setChecked((curValue & flag) != 0);
    }
}

// 复选框状态变更：同步特征值
void CharacteristicsDialog::onCheckBoxStateChanged(Qt::CheckState state) {
    QCheckBox *cb = qobject_cast<QCheckBox*>(sender());
    if (!cb) return;

    // 解析特征值
    bool convertOk = false;
    WORD flag = cb->objectName().toUInt(&convertOk);
    if (!convertOk || flag > 0xFFFF) return;

    // 更新特征值（置位/复位）
    if (state == Qt::Checked) {
        m_modifiedValue |= flag;
    } else {
        m_modifiedValue &= ~flag;
    }
}

// 确定按钮：确认修改并关闭
void CharacteristicsDialog::onBtnOkClicked() {
    qDebug() << "最终特征值：0x" << QString::number(m_modifiedValue, 16);
    accept(); // 关闭对话框并返回Accepted
}

// 取消按钮：恢复原始值并关闭
void CharacteristicsDialog::onBtnCancelClicked() {
    m_modifiedValue = m_originalValue;
    reject(); // 关闭对话框并返回Rejected
}

// 安全转换std::string到QString（防止空/非法字符串崩溃）
QString CharacteristicsDialog::safeStdStringToQString(const std::string& str) {
    if (str.empty()) return tr("未知");
    try {
        return QString::fromStdString(str);
    } catch (...) {
        return tr("无效");
    }
}