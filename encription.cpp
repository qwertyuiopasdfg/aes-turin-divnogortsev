
#include "des.h"
#include "gost.h"
#include "aes.h"
#include <QString>
#include <fstream>

using namespace std;

#define size_max 1024

void DES( const QString filename_i, const QString filename_k, const QString filename_o, bool enc, const QString mode, const QString filename_v )
{
    unsigned char i[size_max] = {0};
    unsigned char o[size_max] = {0};
    unsigned char k[8] = {0};
    unsigned char v[8] = {0};

    FILE *file_i, *file_o, *file_k, *file_v;

    file_i = fopen( filename_i.toUtf8().constData(), "rb" );
    file_o = fopen( filename_o.toUtf8().constData(), "wb" );
    file_k = fopen( filename_k.toUtf8().constData(), "rb" );
    if ( ( file_v = fopen( filename_v.toUtf8().constData(), "rb" ) )) {
        fread( v, 1, 8, file_v );
    }

    unsigned int j;
    unsigned int size;
    unsigned int blocks;

    fread( k, 1, 8, file_k );
    des_key_schedule schedule;
    des_set_key_unchecked(&k, schedule);

    while ( ( size = fread(i, 1, size_max, file_i ) )) {
        blocks = size / 8;
        if ( size % 8  > 0 ) blocks++;
        if ( enc ) {
            if ( mode == "ECB" ) des_enc_ecb( schedule, i, o, blocks );
            if ( mode == "CBC" ) des_enc_cbc( schedule, v, i, o, blocks );
            if ( mode == "CFB" ) des_enc_cfb( schedule, v, i, o, blocks );
            if ( mode == "OFB" ) des_enc_ofb( schedule, v, i, o, blocks );
            fwrite( o, 1, 8 * blocks, file_o );
            for ( j = 0; j < size_max; j++ ) i[j] = NULL;
        }
        else {
            if ( mode == "ECB" ) des_dec_ecb( schedule, i, o, blocks );
            if ( mode == "CBC" ) des_dec_cbc( schedule, v, i, o, blocks );
            if ( mode == "CFB" ) des_dec_cfb( schedule, v, i, o, blocks );
            if ( mode == "OFB" ) des_dec_ofb( schedule, v, i, o, blocks );
            for ( j = 0; o[j] && j < size_max ; j++ );
            fwrite( o, 1, j, file_o);
        }
    }

    fclose(file_i);
    fclose(file_k);
    fclose(file_o);
}



void AES(const QString filename_i, const QString filename_k, const QString filename_o, bool enc, QString mode, const QString filename_v )
{
    unsigned char i[size_max] = {0};
    unsigned char o[size_max] = {0};
    extern unsigned char Key[32];
    unsigned char v[16] = {0};

    FILE *file_i, *file_o, *file_k, *file_v;

    file_i = fopen( filename_i.toUtf8().constData(), "rb" );
    file_o = fopen( filename_o.toUtf8().constData(), "wb" );
    file_k = fopen( filename_k.toUtf8().constData(), "rb" );
    if ( ( file_v = fopen( filename_v.toUtf8().constData(), "rb" ) )) {
        fread( v, 1, 16, file_v );
    }

    unsigned int j;
    unsigned int size;
    unsigned int blocks;

    extern int Nr;
    extern int Nk;
    extern void KeyExpansion();
    if (mode.mid( 3, 3 ) == "128") Nr = 128;
    if (mode.mid( 3, 3 ) == "192") Nr = 192;
    if (mode.mid( 3, 3 ) == "256") Nr = 256;
    mode = mode.mid( 0, 3);
    Nk = Nr / 32;
    Nr = Nk + 6;

    fread( Key, 1, Nk * 4, file_k );
    KeyExpansion();

    while ( ( size = fread(i, 1, size_max, file_i ) ) ) {
        blocks = size / 16;
        if ( size % 16  > 0 ) blocks++;
        if ( enc ) {
            if ( mode == "ECB" ) aes_enc_ecb( i, o, blocks );
            if ( mode == "CBC" ) aes_enc_cbc( v, i, o, blocks );
            if ( mode == "CFB" ) aes_enc_cfb( v, i, o, blocks );
            if ( mode == "OFB" ) aes_enc_ofb( v, i, o, blocks );
            fwrite( o, 1, 16 * blocks, file_o );
            for ( j = 0; j < size_max; j++ ) i[j] = NULL;
        }
        else {
            if ( mode == "ECB" ) aes_dec_ecb( i, o, blocks );
            if ( mode == "CBC" ) aes_dec_cbc( v, i, o, blocks );
            if ( mode == "CFB" ) aes_dec_cfb( v, i, o, blocks );
            if ( mode == "OFB" ) aes_dec_ofb( v, i, o, blocks );
            for ( j = 0; o[j] && j < size_max ; j++ );
            fwrite( o, 1, j, file_o );
        }
    }

    fclose(file_i);
    fclose(file_o);
    fclose(file_k);
    fclose(file_v);
}

