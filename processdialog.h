#ifndef PROCESSDIALOG_H
#define PROCESSDIALOG_H

#include <QDialog>
#include <QVector>
#include <QString>
#include "sniffer.h"
#include <cstring>
#include <QDebug>
#include "confirmwindow.h"

class MainWindow;

class Procinfo{
public:
    int pid;
    QString proc_name;
};

namespace Ui {
class ProcessDialog;
}

class ProcessDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ProcessDialog(QWidget *parent = nullptr);
    void get_stream_info(QString pid);
    void set_table();
    void clear_table();
    ~ProcessDialog();

private slots:
    void on_trace_button_clicked();

    void on_tableWidget_cellClicked(int row, int column);

private:
    Ui::ProcessDialog *ui;
    QVector<Procinfo> stream_infos;
    QVector<Filter> stream_filters;
};

#endif // PROCESSDIALOG_H
