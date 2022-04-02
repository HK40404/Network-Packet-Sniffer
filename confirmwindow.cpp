#include "confirmwindow.h"
#include "ui_confirmwindow.h"

ConfirmWindow::ConfirmWindow(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ConfirmWindow)
{
    ui->setupUi(this);
}

ConfirmWindow::~ConfirmWindow()
{
    delete ui;
}
