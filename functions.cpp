#include "mainwindow.h"
#include "des.h"
#include <QFile>
#include <QTime>

char * QStringToCharStr(QString str) {
    char * charstr = new char [str.size()];
    string stdstr = str.toStdString();
    for (int i = 0; i < str.size(); i++) {
        charstr[i] = stdstr[i];
    }
    return charstr;
}

QString gen(unsigned int size)
{
    QString str;
    unsigned char c[size];
    qsrand(QTime(0,0,0).secsTo(QTime::currentTime()));
    for (unsigned int i = 0; i < size; i++) {
        c[i] = qrand() % 256;
        str += c[i];
    }
    return str;
}

void generate(unsigned int size)
{
    QString str;
    unsigned char c[size];
    qsrand(QTime(0,0,0).secsTo(QTime::currentTime()));
    for (unsigned int i = 0; i < size; i++) {
        c[i] = qrand() % 256;
        str += c[i];
    }

    FILE *f;
    f = fopen( "generate", "wb" );
    fwrite(c, 1, size, f);
    fclose(f);
}

QString FileToQString( QString filename )
{
    QString str;

    FILE *f;
    f = fopen( filename.toUtf8().constData(), "rb" );
    unsigned char c[1024];
    unsigned int size = fread( c, 1, 1024, f );
    fclose(f);

    for ( unsigned int i = 0; i < size; i++ ) {
        str += c[i];
    }

    return str;
}

QString FileToQString16( QString filename )
{
    QString str;

    FILE *f;
    f = fopen( filename.toUtf8().constData(), "rb" );
    unsigned char c[1024];
    unsigned int size = fread( c, 1, 1024, f );
    fclose(f);

    unsigned char temp;
    for (unsigned int i = 0; i < size; i++) {
        temp = c[i] / 16;
        if (temp < 10) temp += '0';
        else {
            temp -= 10;
            temp += 'a';
        }
        str += temp;
        temp = c[i] % 16;
        if (temp < 10) {
            temp += '0';
        }
        else {
            temp -= 10;
            temp += 'a';
        }
        str += temp;
    }

    return str;
}

