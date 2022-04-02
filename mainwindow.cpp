#include "mainwindow.h"
#include "ui_mainwindow.h"

extern QVector<snfPacket> packets;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    for (int i = 0; i < 3; ++i)
        ruleDlg[i] = new Dialog(this);
    process_dialog = new ProcessDialog(this);
    ui->pnum_input->setAlignment(Qt::AlignCenter);
    ui->warning->hide();
    table_init();
    QDesktopWidget *desktop = QApplication::desktop();
    move((desktop->width()-this->width())/2,(desktop->height()-this->height())/2);

    Sniffer * sniffer = new Sniffer();
    sniffer->moveToThread(&thread);
    // when thread finish, delete sniffer obj
    connect(&thread, &QThread::finished, sniffer, &QObject::deleteLater);
    // when cap signal emit, start capturing
    connect(this, &MainWindow::capture_packets, sniffer, &Sniffer::capture);
    // when capture finish, do something
    connect(sniffer, &Sniffer::finish_capture, this, &MainWindow::finish_capture);
    // start thread
    thread.start();
}

MainWindow::~MainWindow()
{
    thread.quit();
    thread.wait();
    for (int i = 0; i < 3; ++i)
        delete ruleDlg[i];
    delete process_dialog;
    delete ui;
}

void MainWindow::table_init(){
    ui->tableWidget->setColumnWidth(0, 100);
    ui->tableWidget->setColumnWidth(1, 270);
    ui->tableWidget->setColumnWidth(2, 270);
    ui->tableWidget->setColumnWidth(3, 230);
    ui->tableWidget->setColumnWidth(4, 230);
    ui->tableWidget->setColumnWidth(5, 100);
    ui->tableWidget->setColumnWidth(6, 100);
    // adaptive column length
    // ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

/*
 *  点多少次，同一个子线程执行多少次capture
*/
void MainWindow::on_pushButton_clicked() {
    QString exp = get_filter_exp();
    qDebug("%s", exp.toStdString().c_str());

    int cap_num = ui->pnum_input->text().toInt();
    bool prom_flag = false;
    if (ui->promisc_flag->currentIndex() == 1)
        prom_flag = true;
    emit capture_packets(cap_num, prom_flag, exp);
}

QString MainWindow::get_filter_exp() {
    QString exp = "";
    for (int i = 0; i < 3; ++i) {
        QString exp_i = ruleDlg[i]->get_filter_exp();
        if (exp_i != "") {
            if (exp != "") exp += " or ";
            exp += "(" + exp_i + ")";
        }
    }
    return exp;
}

void MainWindow::add_packet_row(QString ether_saddr, QString ether_daddr,
                                QString ip_saddr, QString ip_daddr, int sport, int dport) {
    int row = ui->tableWidget->rowCount();
    ui->tableWidget->insertRow(row);
    QTableWidgetItem * order_item = new QTableWidgetItem(QString::number(row+1));
    ui->tableWidget->setItem(row,0,order_item);
    QTableWidgetItem * e_saddr_item = new QTableWidgetItem(ether_saddr);
    ui->tableWidget->setItem(row,1,e_saddr_item);
    QTableWidgetItem * e_daddr_item = new QTableWidgetItem(ether_daddr);
    ui->tableWidget->setItem(row,2,e_daddr_item);
    QTableWidgetItem * ip_saddr_item = new QTableWidgetItem(ip_saddr);
    ui->tableWidget->setItem(row,3,ip_saddr_item);
    QTableWidgetItem * ip_daddr_item = new QTableWidgetItem(ip_daddr);
    ui->tableWidget->setItem(row,4,ip_daddr_item);

    QTableWidgetItem * sport_item;
    if (sport == 0) sport_item = new QTableWidgetItem("-");
    else sport_item = new QTableWidgetItem(QString::number(sport));
    ui->tableWidget->setItem(row,5,sport_item);

    QTableWidgetItem * dport_item;
    if (dport == 0) dport_item = new QTableWidgetItem("-");
    else dport_item = new QTableWidgetItem(QString::number(dport));
    ui->tableWidget->setItem(row,6,dport_item);
}

void MainWindow::on_tableWidget_cellClicked(int row, int column) {
    QString * payload = &packets[row].packet;
    QString text = packets[row].info;
    text += "------------------------------------------------------------------------------------\n";
    text += Sniffer::get_readable_payload(payload);
    ui->textBrowser->setText(text);
}

void MainWindow::on_ruleButton1_clicked() {
    ruleDlg[0]->show_warning(false);
    ruleDlg[0]->set_rule_text();
    ruleDlg[0]->show();
}


void MainWindow::on_ruleButton2_clicked() {
    ruleDlg[1]->show_warning(false);
    ruleDlg[1]->set_rule_text();
    ruleDlg[1]->show();
}


void MainWindow::on_ruleButton3_clicked(){
    ruleDlg[2]->show_warning(false);
    ruleDlg[2]->set_rule_text();
    ruleDlg[2]->show();
}


void MainWindow::on_pnum_input_editingFinished() {
    bool flag = true;
    int num = ui->pnum_input->text().toInt(&flag);
    if (!flag or num < 0) {
        ui->warning->setText("设置失败：非法格式");
        ui->warning->show();
        QTimer::singleShot(3000,ui->warning,SLOT(hide()));
        ui->pnum_input->setText("5");
        return;
    }
    else if (num > 100) {
        ui->warning->setText("设置失败：输入数字过大");
        ui->warning->show();
        QTimer::singleShot(3000,ui->warning,SLOT(hide()));
        ui->pnum_input->setText("5");
        return;
    }
}

void MainWindow::on_pushButton_2_clicked() {
    process_dialog->clear_table();
    process_dialog->show();
}

void MainWindow::trace_stream(Filter f) {
    for (int i = 0; i < 3; ++i)
        ruleDlg[i]->clear_filter();
    // trace Local => Peer
    ruleDlg[0]->set_filter(f);
    // trace Peer => Local
    Filter p2l;
    p2l.protocol = f.protocol;
    p2l.sip = f.dip;
    p2l.sport = f.dport;
    p2l.dip = f.sip;
    p2l.dport = f.sport;
    ruleDlg[1]->set_filter(p2l);
}

void MainWindow::on_clear_button_clicked() {
    packets.clear();
    packets.squeeze();
    int row = ui->tableWidget->rowCount();
    for (int i = row-1; i >= 0; i--)
        ui->tableWidget->removeRow(i);
    ui->textBrowser->setText("");
}

void MainWindow::finish_capture() {
    // do something if need in future
}

void MainWindow::on_tableWidget_itemChanged(QTableWidgetItem *item) {
    ui->tableWidget->scrollToBottom();
}

