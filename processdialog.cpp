#include "processdialog.h"
#include "ui_processdialog.h"
#include "mainwindow.h"

void exec_cmd(const char * cmd, QString * result) {
    FILE * fp = NULL;
    char buf[1024];
    if ((fp = popen(cmd, "r")) != NULL) {
        while (fgets(buf, sizeof(buf), fp) != NULL) {
            result->append(QString(buf));
        }
        pclose(fp);
    }
}

/*
 * input pid or pname
 * get stream info and filter
*/
void ProcessDialog::get_stream_info(QString pid) {

    string cmd = "ss -tnp | grep " + pid.toStdString();
    QString result = "";
    exec_cmd(cmd.c_str(), &result);
    int len = result.size();
    string exp = "";

    int i = 0;
    int seg = 0;
    // skip first line
    if(result.mid(0, 5) == "State") {
        while(result[i++] != '\n');
    }
    while (i < len) {
        while (result[i] != ' ') i++;
        seg += 1;
        while (result[i] == ' ') i++;

        if (seg == 3) {
            Filter f;
            Procinfo pinfo;

            /* processing local ip address:port */
            // find sep char ':'
            int sep = i-1;
            while (result[++sep] != ':');
            f.sip = result.mid(i, sep-i);
            i = sep + 1;
            // find sep char ' '
            while (result[++sep] != ' ');
            f.sport = result.mid(i, sep-i);
            i = sep;
            while (result[i] == ' ') i++;

            /* processing peer ip address:port */
            // find sep char ':'
            sep = i-1;
            while (result[++sep] != ':');
            f.dip = result.mid(i, sep-i);
            i = sep + 1;
            // find sep char ' '
            while (result[++sep] != ' ');
            f.dport = result.mid(i, sep-i);

            // find "[proc name]"
            i = sep;
            while (result[i++] != '"');
            sep = i;
            while (result[++sep] != '"');
            pinfo.proc_name = result.mid(i, sep-i);
            // find =[pid]
            i = sep + 1;
            while(result[i++] != '=');
            sep = i-1;
            while(result[++sep] != ',');
            pinfo.pid = result.mid(i, sep-i).toInt();
            i = sep;
            while(result[i++] != '\n');

            seg = 0;
            stream_infos.push_back(pinfo);
            stream_filters.push_back(f);
        }
    }
    assert(stream_filters.size() == stream_infos.size());
}

ProcessDialog::ProcessDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ProcessDialog)
{
    ui->setupUi(this);
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

ProcessDialog::~ProcessDialog()
{
    delete ui;
}

void ProcessDialog::on_trace_button_clicked() {
    clear_table();
    get_stream_info(ui->proc_input->text());
    set_table();
}

void ProcessDialog::set_table() {
    for (int i = 0; i < stream_infos.size(); i++) {
        int row = ui->tableWidget->rowCount();
        ui->tableWidget->insertRow(row);
        QTableWidgetItem * pname_item = new QTableWidgetItem(stream_infos[i].proc_name);
        ui->tableWidget->setItem(row,0,pname_item);
        QTableWidgetItem * pid_item = new QTableWidgetItem(QString::number(stream_infos[i].pid));
        ui->tableWidget->setItem(row,1,pid_item);
        QTableWidgetItem * saddr_item = new QTableWidgetItem(stream_filters[i].sip);
        ui->tableWidget->setItem(row,2,saddr_item);
        QTableWidgetItem * sport_item = new QTableWidgetItem(stream_filters[i].sport);
        ui->tableWidget->setItem(row,3,sport_item);
        QTableWidgetItem * daddr_item = new QTableWidgetItem(stream_filters[i].dip);
        ui->tableWidget->setItem(row,4,daddr_item);
        QTableWidgetItem * dport_item = new QTableWidgetItem(stream_filters[i].dport);
        ui->tableWidget->setItem(row,5,dport_item);
    }
    ui->tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

void ProcessDialog::clear_table() {
    stream_filters.clear();
    stream_filters.squeeze();
    stream_infos.clear();
    stream_infos.squeeze();
    int row = ui->tableWidget->rowCount();
    for (int i = row-1; i >= 0; i--)
        ui->tableWidget->removeRow(i);
}

void ProcessDialog::on_tableWidget_cellClicked(int row, int column) {
    MainWindow * p = (MainWindow *)parent();
    QString exp = p->get_filter_exp();
    Filter f;
    f.protocol = "TCP";
    f.sip = stream_filters[row].sip;
    f.sport = stream_filters[row].sport;
    f.dip = stream_filters[row].dip;
    f.dport = stream_filters[row].dport;
    ConfirmWindow * window = new ConfirmWindow(this);
    int ret = window->exec();
    if (ret == QDialog::Accepted) {
        p->trace_stream(f);
    }
    delete window;
}
