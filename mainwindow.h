#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QString>
#include "dialog.h"
#include "processdialog.h"
#include <QDebug>
#include <QTimer>
#include <QDesktopWidget>
#include "sniffer.h"
#include <QThread>
#include <QTableWidgetItem>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

private:
    Ui::MainWindow *ui;
    Dialog * ruleDlg[3];
    ProcessDialog * process_dialog;
    QThread thread;

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void add_packet_row(QString ether_saddr, QString ether_daddr, QString ip_saddr, QString ip_daddr, int sport, int dport);
    void table_init();
    QString get_filter_exp();
    void trace_stream(Filter f);

signals:
    void capture_packets(int cap_num, bool prom_flag, QString filter_exp);

public slots:
    void finish_capture();

private slots:
    void on_pushButton_clicked();
    void on_tableWidget_cellClicked(int row, int column);
    void on_ruleButton1_clicked();
    void on_ruleButton2_clicked();
    void on_ruleButton3_clicked();
    void on_pnum_input_editingFinished();
    void on_pushButton_2_clicked();
    void on_clear_button_clicked();
    void on_tableWidget_itemChanged(QTableWidgetItem *item);
};
#endif // MAINWINDOW_H
