#include "dialog.h"
#include "ui_dialog.h"
#include <QTimer>

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    show_warning(false);
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::show_warning(bool show) {
    if (show) ui->warning->show();
    else ui->warning->hide();
}

void Dialog::set_rule_text() {
    if (filter.check()) {
        ui->sip_input->setText(filter.sip);
        ui->dip_input->setText(filter.dip);
        ui->sport_input->setText(filter.sport);
        ui->dport_input->setText(filter.dport);
        if (filter.protocol == "IP")
            ui->proto_selection->setCurrentIndex(1);
        else if (filter.protocol == "ARP")
            ui->proto_selection->setCurrentIndex(2);
        else if (filter.protocol == "ICMP")
            ui->proto_selection->setCurrentIndex(3);
        else if (filter.protocol == "TCP")
            ui->proto_selection->setCurrentIndex(4);
        else if (filter.protocol == "UDP")
            ui->proto_selection->setCurrentIndex(5);
        else if (filter.protocol == "HTTP")
            ui->proto_selection->setCurrentIndex(6);
    }
}

QString Dialog::get_filter_exp() {
    return filter.get_filter_exp();
}

void Dialog::on_save_button_clicked() {
    Filter f;
    f.sip = ui->sip_input->text();
    f.sport = ui->sport_input->text();
    f.dip = ui->dip_input->text();
    f.dport = ui->dport_input->text();
    if (ui->proto_selection->currentIndex() != 0)
        f.protocol = ui->proto_selection->currentText();
//    qDebug("sip: %s", f.sip.toStdString().c_str());
//    qDebug("dip: %s", f.dip.toStdString().c_str());
//    qDebug("sport: %s", f.sport.toStdString().c_str());
//    qDebug("dport: %s", f.dport.toStdString().c_str());
//    qDebug("proto: %s", f.protocol.toStdString().c_str());
    if (f.check()) {
        filter = f;
        ui->warning->setText("规则保存成功！");
        show_warning(true);
        QTimer::singleShot(3000,ui->warning,SLOT(hide()));
    } else {
        ui->warning->setText("请输入合法的IP地址/端口号！");
        show_warning(true);
        QTimer::singleShot(3000,ui->warning,SLOT(hide()));
    }
}

void Dialog::on_clear_button_clicked() {
    clear_filter();
}

void Dialog::clear_filter() {
    filter = Filter();
    ui->sip_input->setText("");
    ui->dip_input->setText("");
    ui->sport_input->setText("");
    ui->dport_input->setText("");
    ui->proto_selection->setCurrentIndex(0);
}

void Dialog::set_filter(Filter f) {
    filter = f;
}
