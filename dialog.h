#ifndef DIALOG_H
#define DIALOG_H

#include <QDialog>
#include "sniffer.h"

namespace Ui {
class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = nullptr);
    void show_warning(bool show);
    void set_rule_text();   // set text by rules saved last time
    QString get_filter_exp();
    void clear_filter();
    void set_filter(Filter f);
    ~Dialog();

private slots:
    void on_save_button_clicked();
    void on_clear_button_clicked();

private:
    Ui::Dialog *ui;
    Filter filter;
};

#endif // DIALOG_H
