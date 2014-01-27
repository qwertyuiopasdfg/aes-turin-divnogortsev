#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QTextStream>
#include <QRegExp>
#include <QMessageBox>
#include <string>

using namespace std;

MainWindow::MainWindow( QWidget *parent ) :
    QMainWindow( parent ),
    ui( new Ui::MainWindow )
{
    ui->setupUi( this );

    changedAlgorithm();
    hide();
    aboutabout();

    connect(ui->pushButtonOpenInput,    SIGNAL( clicked() ),                        SLOT( openInput() ));
    connect(ui->pushButtonOpenKey,      SIGNAL( clicked() ),                        SLOT( openKey() ));
    connect(ui->pushButtonOpenOutput,   SIGNAL( clicked() ),                        SLOT( openOutput() ));
    connect(ui->pushButtonOpenVector,   SIGNAL( clicked() ),                        SLOT( openVector() ));
    connect(ui->pushButtonEncrypt,      SIGNAL( clicked() ),                        SLOT( encrypt() ));
    connect(ui->pushButtonDecrypt,      SIGNAL( clicked() ),                        SLOT( decrypt() ));
    connect(ui->pushButtonVector,       SIGNAL( clicked() ),                        SLOT( generateVector() ));
    connect(ui->pushButtonKey,          SIGNAL( clicked() ),                        SLOT( generateKey() ));
    connect(ui->pushButtonDisplay,      SIGNAL( clicked() ),                        SLOT( display() ));
    connect(ui->pushButtonFileInput,    SIGNAL( clicked() ),                        SLOT( claerInput() ));
    connect(ui->pushButtonFileOutput,   SIGNAL( clicked() ),                        SLOT( claerOutput() ));
    connect(ui->comboBoxAlgorithm,      SIGNAL( currentIndexChanged( QString )),    SLOT( changedAlgorithm() ));
    connect(ui->comboBoxMode,           SIGNAL( currentIndexChanged( QString )),    SLOT( changedAlgorithm() ));
    //connect(ui->comboBoxGOST,           SIGNAL( currentIndexChanged( QString )),    SLOT( changedAlgorithm() ));
}

void MainWindow::openVector()
{
    QString str;
    filenameVector = QFileDialog::getOpenFileName( this, QString::fromLocal8Bit( "Открыть файл с вектором" ) );
    if ( !filenameVector.isEmpty() ) {
        QFile file( filenameVector );
        file.open( QIODevice::ReadOnly );
        str = file.readAll().constData();
        file.close();
        ui->lineEditVector->setText( QString::fromLocal8Bit( QStringToCharStr( str ), str.size() ));
    }
}

void MainWindow::openInput()
{
    QString str = QFileDialog::getOpenFileName( this, QString::fromLocal8Bit( "Открыть файл с данныими" ) );
    if ( !str.isEmpty() ) {
        ui->lineEditInputFile->setText( str );
        str = FileToQString( str );
        ui->textEditInput->setText( QString::fromLocal8Bit( QStringToCharStr( str ), str.size() ) );
    }
}

void MainWindow::openKey()
{
    QString str;
    filenameKey = QFileDialog::getOpenFileName( this, QString::fromLocal8Bit( "Открыть файл с ключём" ) );
    if ( !filenameKey.isEmpty() ) {
        str = FileToQString( filenameKey );
        ui->lineEditKey->setText( QString::fromLocal8Bit( QStringToCharStr( str ), str.size() ) );
    }
}

void MainWindow::openOutput()
{
    QString str = QFileDialog::getOpenFileName( this, QString::fromLocal8Bit( "Открыть файл для результата" ) );
    if ( !str.isEmpty() ) {
        ui->lineEditOutputFile->setText( str );
    }
}

void MainWindow::display()
{
    ui->comboBoxMode->          setVisible( false );
    //ui->comboBoxGOST->          setVisible( false );
    ui->comboBoxAES->           setVisible( false );

    ui->pushButtonKey->         setVisible( false );
    ui->lineEditKey->           setVisible( false );
    ui->pushButtonOpenKey->     setVisible( false );

    ui->pushButtonVector->      setVisible( false );
    ui->lineEditVector->        setVisible( false );
    ui->pushButtonOpenVector->  setVisible( false );

    ui->pushButtonDisplay->     setVisible( false );

    ui->pushButtonDecrypt->     setVisible( false );


    ui->textEditInput->         setVisible( true );

    ui->textEditOutput->        setVisible( true );

    QString algorithm = ui->comboBoxAlgorithm->currentText();
    QString mode;
    about();
    lengthblock();
    lengthkey();

    if ( algorithm == "DES" ) {
        ui->comboBoxMode->          setVisible( true );
        ui->pushButtonKey->         setVisible( true );
        ui->lineEditKey->           setVisible( true );
        ui->pushButtonOpenKey->     setVisible( true );

        ui->pushButtonDecrypt->     setVisible( true );

        mode = ui->comboBoxMode->currentText();
        if ( mode == "CBC" || mode == "CFB" || mode == "OFB" ) {
            // vector
            ui->pushButtonVector->      setVisible( true );
            ui->lineEditVector->        setVisible( true );
            ui->pushButtonOpenVector->  setVisible( true );
        }
    }

   if ( algorithm == "GOST" )
   {
            // mode
            //ui->pushButtonMode->        setVisible( true );
            // modes
            //ui->comboBoxGOST->          setVisible( true );
            // key
            ui->pushButtonKey->         setVisible( true );
            ui->lineEditKey->           setVisible( true );
            ui->pushButtonOpenKey->     setVisible( true );
            // decrypt
            ui->pushButtonDecrypt->     setVisible( true );

            //mode = ui->comboBoxGOST->currentText();
            if ( mode == "CBC" || mode == "CFB" || mode == "OFB" )
            {
                // vector
                ui->pushButtonVector->      setVisible( true );
                ui->lineEditVector->        setVisible( true );
                ui->pushButtonOpenVector->  setVisible( true );
            }

        }

    if ( algorithm == "AES" ) {
        // mode
        //ui->pushButtonMode->        setVisible( true );
        // modes
        ui->comboBoxMode->          setVisible( true );
        ui->comboBoxAES->          setVisible( true );
        // key
        ui->pushButtonKey->         setVisible( true );
        ui->lineEditKey->           setVisible( true );
        ui->pushButtonOpenKey->     setVisible( true );
        // decrypt
        ui->pushButtonDecrypt->     setVisible( true );

        mode = ui->comboBoxMode->currentText();
        if ( mode == "CBC" || mode == "CFB" || mode == "OFB" ) {
            // vector
            ui->pushButtonVector->      setVisible( true );
            ui->lineEditVector->        setVisible( true );
            ui->pushButtonOpenVector->  setVisible( true );
        }
    }

    if ( algorithm == "IDEA" ) {
        // mode
        //ui->pushButtonMode->        setVisible( true );
        // modes
        ui->comboBoxMode->          setVisible( true );
        // key
        ui->pushButtonKey->         setVisible( true );
        ui->lineEditKey->           setVisible( true );
        ui->pushButtonOpenKey->     setVisible( true );
        // decrypt
        ui->pushButtonDecrypt->     setVisible( true );

        mode = ui->comboBoxMode->currentText();
        if ( mode == "CBC" || mode == "CFB" || mode == "OFB" ) {
            // vector
            ui->pushButtonVector->      setVisible( true );
            ui->lineEditVector->        setVisible( true );
            ui->pushButtonOpenVector->  setVisible( true );
        }
    }
}

void MainWindow::hide()
{
    ui->pushButtonDisplay-> setVisible( true );

    ui->textEditInput->     setVisible( false );

    ui->textEditOutput->    setVisible( false );
}

void MainWindow::changedAlgorithm()
{
    bool flag = ui->pushButtonDisplay->isVisible();
    display();
    if ( flag ) {
        hide();
    }
}

void MainWindow::encrypt()
{
    QString algorithm = ui->comboBoxAlgorithm->currentText();
    QString mode;
    QString filenameInput = ui->lineEditInputFile->text();
    QString filenameOutput = ui->lineEditOutputFile->text();
    QString str;
    if ( filenameInput.isEmpty() ) {
        QMessageBox::information(this, QString::fromLocal8Bit("Ошибка"), QString::fromLocal8Bit("Не задан файл с данными"));
        return;
    }
    if ( filenameOutput.isEmpty() ) {
        QMessageBox::information(this, QString::fromLocal8Bit("Ошибка"), QString::fromLocal8Bit("Не задан файл для результата"));
        return;
    }
    if ( algorithm == "DES" ) {
        mode = ui->comboBoxMode->currentText();
        if ( mode == "CBC" || mode == "CFB" || mode == "OFB" ) {
            if ( filenameVector.isEmpty() ) {
                QMessageBox::information(this, QString::fromLocal8Bit("Ошибка"), QString::fromLocal8Bit("Вектор не задан"));
                return;
            }
        }
    }
    if ( algorithm == "GOST" ) {
        //mode = ui->comboBoxGOST->currentText();
        if ( mode == "CBC" || mode == "CFB" || mode == "OFB" ) {
            if ( filenameVector.isEmpty() ) {
                QMessageBox::information(this, QString::fromLocal8Bit("Ошибка"), QString::fromLocal8Bit("Вектор не задан"));
                return;
            }
        }
    }
    if ( algorithm == "AES" ) {
        mode = ui->comboBoxMode->currentText();
        if ( mode == "CBC" || mode == "CFB" || mode == "OFB" ) {
            if ( filenameVector.isEmpty() ) {
                QMessageBox::information(this, QString::fromLocal8Bit("Ошибка"), QString::fromLocal8Bit("Вектор не задан"));
                return;
            }
        }
        mode += ui->comboBoxAES->currentText();
    }
    if ( algorithm == "IDEA" ) {
        mode = ui->comboBoxMode->currentText();
        if ( mode == "CBC" || mode == "CFB" || mode == "OFB" ) {
            if ( filenameVector.isEmpty() ) {
                QMessageBox::information(this, QString::fromLocal8Bit("Ошибка"), QString::fromLocal8Bit("Вектор не задан"));
                return;
            }
        }
    }
    if ( algorithm == "DES" || algorithm == "GOST" || algorithm == "AES" || algorithm == "IDEA" ) {
        if ( filenameKey.isEmpty() ) {
            QMessageBox::information(this, QString::fromLocal8Bit("Ошибка"), QString::fromLocal8Bit("Ключ не задан"));
            return;
        }
    }



    if ( algorithm == "DES" )         DES         ( filenameInput, filenameKey, filenameOutput, 1, mode, filenameVector );

    if ( algorithm == "AES" )         AES         ( filenameInput, filenameKey, filenameOutput, 1, mode, filenameVector );


}

void MainWindow::decrypt()
{
    QString algorithm = ui->comboBoxAlgorithm->currentText();
    QString mode;
    QString filenameInput;
    QString filenameOutput;
    QString str;
    if ( algorithm == "DES" ) {
        mode = ui->comboBoxMode->currentText();
    }
    if ( algorithm == "GOST" ) {
        //mode = ui->comboBoxGOST->currentText();
    }
    if ( algorithm == "AES" ) {
        mode = ui->comboBoxMode->currentText();
        mode += ui->comboBoxAES->currentText();
    }
    if ( algorithm == "IDEA" ) {
        mode = ui->comboBoxMode->currentText();
    }
    filenameInput = ui->lineEditInputFile->text();
    filenameOutput = ui->lineEditOutputFile->text();

    if ( algorithm == "DES" )     DES     ( filenameInput, filenameKey, filenameOutput, 0, mode, filenameVector );

    if ( algorithm == "AES" )     AES     ( filenameInput, filenameKey, filenameOutput, 0, mode, filenameVector );

    str = FileToQString( filenameOutput );
    ui->textEditOutput->setText( QString::fromLocal8Bit( QStringToCharStr( str ), str.size() ) );
}

void MainWindow::generateVector()
{
    unsigned int size = lengthblock();
    generate( size );
    ui->lineEditVector->setText( gen( size ));
    filenameVector = "generatevector";
}

void MainWindow::generateKey()
{
    unsigned int size = lengthkey();
    generate( size );
    QFile file( "generate" );
    file.open(QIODevice::ReadOnly);
    QString str = file.readAll().constData();
    file.close();
    filenameKey = "generatekey";
    ui->lineEditKey->setText( QString::fromLocal8Bit( QStringToCharStr( str ), str.size()) );
}

void MainWindow::about()
{
    QString algorithm = ui->comboBoxAlgorithm->currentText();
    QFile file( "about/" + algorithm + ".txt" );
    file.open( QIODevice::ReadOnly );
    QString str = file.readAll().constData();
    file.close();
    //ui->textEditAbout->setText( QString::fromLocal8Bit( QStringToCharStr( str ), str.size() ));
}

void MainWindow::aboutabout()
{
    QFile file( "about/about.txt" );
    file.open( QIODevice::ReadOnly );
    QString str = file.readAll().constData();
    file.close();
    //ui->textEditAbout->setText( QString::fromLocal8Bit( QStringToCharStr( str ), str.size() ));
}

void MainWindow::claerInput()
{
    ui->lineEditInputFile-> setText( "" );
    ui->textEditInput->     setText( "" );
}

void MainWindow::claerOutput()
{
    ui->lineEditOutputFile->    setText( "" );
    ui->textEditOutput->        setText( "" );
}

unsigned int MainWindow::lengthblock()
{
    QString str = ui->comboBoxAlgorithm->currentText();
    unsigned int size;
    if ( str == "DES" )     size = 8;
    if ( str == "GOST" )    size = 8;
    if ( str == "AES" )     size = 16;
    if ( str == "IDEA" )    size = 8;
    ui->lineEditVector->setMaxLength( size );
    return size;
}

unsigned int MainWindow::lengthkey()
{
    QString str = ui->comboBoxAlgorithm->currentText();
    unsigned int size;
    if ( str == "DES" )     size = 8;
    if ( str == "GOST" )    size = 32;
    if ( str == "AES" ) {
        str = ui->comboBoxAES->currentText();
        if ( str == "128" ) size = 16;
        if ( str == "192" ) size = 24;
        if ( str == "256" ) size = 32;
    }
    if ( str == "IDEA" ) size = 16;
    ui->lineEditKey->setMaxLength( size );
    return size;
}

void MainWindow::update()
{
}

MainWindow::~MainWindow()
{
    delete ui;
}
