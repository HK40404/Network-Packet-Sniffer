#ifndef CONFIRMWINDOW_H
#define CONFIRMWINDOW_H

#include <QDialog>

namespace Ui {
class ConfirmWindow;
}

class ConfirmWindow : public QDialog
{
    Q_OBJECT

public:
    explicit ConfirmWindow(QWidget *parent = nullptr);
    ~ConfirmWindow();

private:
    Ui::ConfirmWindow *ui;
};

#endif // CONFIRMWINDOW_H
