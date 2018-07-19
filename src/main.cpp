/*
 * AES
 * ESB
 * Padding as PKCS7
 *
*/

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <tchar.h>

#define SIZE_DATA 32768 //Размер входного массива байтов

void EncryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void DecryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void PrintDwData(BYTE *_dwData, size_t size);

int main(/*int argv, char *argc[]*/)
{
    //Режим работы программы
    TCHAR tMode;// = L'e';

    //Соль для генерации пароля
    TCHAR password[MAX_PATH];// = L"pass";

SelectModeLoop:

    wprintf(L"Encrypt (e) or decrypt (d) these files?\n");
    wscanf(L"%lc", &tMode);

    wprintf(L"Enter the password to encrypt(decrypt) the data:\n");
    wscanf(L"%ls", password);

    if((tMode != L'e') && (tMode != L'd'))
    {
        wprintf(L"Mode selection error, please select mode again!\n");
        goto SelectModeLoop;
    }

    //--------------- Поиск файла по маске ------------------

    WIN32_FIND_DATA FindFileData;
    //LARGE_INTEGER filesize;
    HANDLE hFind;

    //Маска
    LPCTSTR lpzMaskFile = L"*";

    hFind = FindFirstFile(lpzMaskFile, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        wprintf(L"FindFirstFile failed %d\n", GetLastError());
        return 0;
    }
    do
    {
        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            //_tprintf(TEXT("<DIR> %s\n"), FindFileData.cFileName);
            continue;
        }
        else
        {
            if(tMode == L'e')
            {
                wprintf(L"Encryption file: %ls...\n", FindFileData.cFileName);
                EncryptMyFile(FindFileData.cFileName, password);
                wprintf(L"Encryption was successful!\n\n");

                //return 0;
            }
            if(tMode == L'd')
            {
                wprintf(L"Decryption file: %ls...\n", FindFileData.cFileName);
                DecryptMyFile(FindFileData.cFileName, password);
                wprintf(L"\nDecryption was successful!\n\n");
                //return 0;
            }

            //filesize.LowPart = FindFileData.nFileSizeLow;
            //filesize.HighPart = FindFileData.nFileSizeHigh;
        }
    }
    while (FindNextFile(hFind, &FindFileData) != 0);

    FindClose(hFind);

    return 0;
}

void EncryptMyFile(LPTSTR _wszNameFile, LPTSTR _password)
{
    HCRYPTPROV hProv = 0; //Дескриптор крипртопровайдера
    HCRYPTKEY hKey = 0;   //Дескриптор ключа
    HCRYPTHASH hHash = 0; //Дескриптор хэш-объекта

    size_t sizeBuffRead = SIZE_DATA - 1;     //Сколько байт читаем из файла
    BYTE pbSrcData[SIZE_DATA]; //Данные для шифрования
    DWORD dwDataLen;  //Размер незашифрованных данных
    BYTE  bCryptBuf[SIZE_DATA]; //Указатель на массив результата
    DWORD  buflen = SIZE_DATA;          //Размер массива результата
    size_t sh = 0;

    //Пароль
    LPTSTR wszPassword = _password;

    //Длина пароля в байтах
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    bool work = true;   //Условие совершения итераций while

    //----------------------Формируем имена файлов-----------------------------

    WCHAR *wszNameFile = _wszNameFile;
    WCHAR wszNameFileEncrypt[128];
    LPCTSTR wszExpansion = L".pussy";
    LPCTSTR wszProgName = L"pussyCrypt.exe";

    wcsncpy(wszNameFileEncrypt, wszNameFile, 128);
    wcscat(wszNameFileEncrypt, wszExpansion);

    //-----------------------------------------------------------------------

    if(!(wcscmp(wszNameFile, wszProgName)))
    {
        return;
    }

    //Открытие файлов
    FILE *f = _wfopen(wszNameFile, L"ab+" );              //исходный
    FILE *sf = _wfopen(wszNameFileEncrypt, L"ab+" );     //зашифрованный
    if((f == 0) || (sf == 0))
    {
        wprintf(L"Error open file!");
        goto Cleanup;
    }
    //Получаем контекст криптопровайдера
    if(!CryptAcquireContext(
                &hProv,
                NULL,
                MS_ENH_RSA_AES_PROV,
                PROV_RSA_AES,
                CRYPT_VERIFYCONTEXT))
    {
        wprintf(L"Error %x during CryptAcquireContext!\n", GetLastError());
        goto Cleanup;
    }

    //Инициирование хеширования потока данных
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        wprintf(L"Error %x during CryptCreateHash!\n", GetLastError());
        goto Cleanup;
    }

    //Хеширование пароля
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        wprintf(L"Error %x during CryptHashData!\n", GetLastError());
        goto Cleanup;
    }

    //Создание ключа сеанса, полученного из хеша пароля
    if(!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        wprintf(L"Error %x during CryptDeriveKey!\n", GetLastError());
        goto Cleanup;
    }

    while(work)
    {
        //---------------читаем файл-----------------
        sh = fread(pbSrcData, sizeof(BYTE), sizeBuffRead, f);
        if(sh != sizeBuffRead)
        {
            if(feof(f))
            {
                for(unsigned i = sh; i < sizeBuffRead; i++)
                {
                    pbSrcData[i] = sizeBuffRead - sh;
                }
                work = false;
            }
            if(ferror(f))
                wprintf(L"File read error.");
        }
        //-------------------------------------------
        /*
        printf("Data:\n");
        PrintDwData(pbSrcData, sh);
*/

        dwDataLen = sh;   //Количество полезных байотв в блоке шифрования

        //Копируем в буфер результата незашифрованные данные в размере этого буфера
        for(unsigned i = 0; i < dwDataLen; i++)
        {
            bCryptBuf[i] = pbSrcData[i];
        }

        //Шифрование блока
        if (!CryptEncrypt(
                    hKey,
                    0,      // no hash
                    TRUE,   // "final" flag
                    0,      // reserved
                    bCryptBuf,  // buffer with data
                    &dwDataLen, // return size for ciphered text
                    buflen))    //Размер блока
        {
            wprintf(L"Error %d during CryptEncrypt!\n", GetLastError());
            goto Cleanup;
        }
        /*
        printf("Encrypt data:\n");
        PrintDwData(bCryptBuf, sh);
        printf("Success!");
*/
        //--------------Пишем в файл---------------
        fwrite(bCryptBuf, sizeof(BYTE), dwDataLen, sf);
        if(ferror(sf))
            wprintf(L"Error write file!\n");
        //----------------------------------------
    }

Cleanup:
    if(hKey)
    {
        CryptDestroyKey(hKey);
    }
    if(hHash)
    {
        CryptDestroyHash(hHash);
    }
    if(hProv)
    {
        CryptReleaseContext(hProv, 0);
    }

    fclose(f);
    fclose(sf);
}

void DecryptMyFile(LPTSTR _wszNameFile, LPTSTR _password)
{
    HCRYPTPROV hProv = 0; //Дескриптор крипртопровайдера
    HCRYPTKEY hKey = 0;   //Дескриптор ключа
    HCRYPTHASH hHash = 0; //Дескриптор хэш-объекта

    size_t sizeBuffRead = SIZE_DATA;     //Сколько байт читаем из файла
    BYTE pbSrcData[SIZE_DATA]; //Данные для шифрования
    DWORD dwDataLen;  //Размер незашифрованных данных
    BYTE  bCryptBuf[SIZE_DATA]; //Указатель на массив результата
    DWORD  buflen = SIZE_DATA;          //Размер массива результата
    size_t sh = 0;

    //Пароль
    LPTSTR wszPassword = _password;
    //Длина пароля в байтах
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    bool work = true;   //Условие совершения итераций while

    //----------------------Формируем имена файлов-----------------------------

    WCHAR *wszNameFile = _wszNameFile;
    WCHAR wszNameFileDecrypt[128];
    LPCTSTR wszExpansionDecrypt = L".dec";
    LPCTSTR wszProgName = L"pussyCrypt.exe";

    //size_t pos = wcscspn(wszNameFile, wszExpansion);
    //printf("pos = %d\n", pos);

    wcsncpy(wszNameFileDecrypt, wszNameFile, 128);
    wcscat(wszNameFileDecrypt, wszExpansionDecrypt);
    //    wprintf(L"wszNameFileDecrypt = %ls\n", wszNameFileDecrypt);

    //-----------------------------------------------------------------------

    if(!(wcscmp(wszNameFile, wszProgName)))
    {
        return;
    }

    //Открытие файлов
    FILE *f = _wfopen(wszNameFile, L"ab+" );          //исходный
    FILE *svf = _wfopen(wszNameFileDecrypt, L"ab+" );    //расшифрованный
    if((f == 0) || (svf == 0))
    {
        wprintf(L"Error file!");
        goto Cleanup;
    }

    //Получаем контекст криптопровайдера
    if(!CryptAcquireContext(
                &hProv,
                NULL,
                MS_ENH_RSA_AES_PROV,
                PROV_RSA_AES,
                CRYPT_VERIFYCONTEXT))
    {
        wprintf(L"Error %x during CryptAcquireContext!\n", GetLastError());
        goto Cleanup;
    }

    //Инициирование хеширования потока данных
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        wprintf(L"Error %x during CryptCreateHash!\n", GetLastError());
        goto Cleanup;
    }

    //Хеширование пароля
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        wprintf(L"Error %x during CryptHashData!\n", GetLastError());
        goto Cleanup;
    }

    //Создание ключа сеанса, полученного из хеша пароля
    if(!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        wprintf(L"Error %x during CryptDeriveKey!\n", GetLastError());
        goto Cleanup;
    }

    while(work)
    {
        //---------------читаем файл-----------------
        sh = fread(pbSrcData, sizeof(BYTE), sizeBuffRead, f);
        if(sh != sizeBuffRead)
        {
            if( (sh == 0)&&(feof(f)) )
                goto Cleanup;
            if(feof(f))
            {
                buflen = sh;
            }

            if(ferror(f))
                wprintf(L"File read error.");
        }
        //-------------------------------------------
        /*
        printf("Data:\n");
        PrintDwData(pbSrcData, sh);
*/
        dwDataLen = buflen;   //Количество полезных байотв в блоке шифрования

        //Копируем в буфер результата зашифрованные данные в размере этого буфера
        for(unsigned i = 0; i < dwDataLen; i++)
        {
            bCryptBuf[i] = pbSrcData[i];
        }

        //Расшифровка данных
        if (!CryptDecrypt(
                    hKey,
                    0,
                    TRUE,
                    0,
                    bCryptBuf,
                    &dwDataLen))
        {
            wprintf(L"Error %x during CryptDecrypt!\n", GetLastError());
            goto Cleanup;
        }
        /*
        printf("Decrypt data:\n");
        PrintDwData(bCryptBuf, sh);
*/
        //--------------Пишем в файл---------------
        fwrite(bCryptBuf, sizeof(BYTE), dwDataLen, svf);
        if(ferror(svf))
            wprintf(L"Error write file!\n");
        //------------------------------------------
    }

Cleanup:
    if(hKey)
    {
        CryptDestroyKey(hKey);
    }
    if(hHash)
    {
        CryptDestroyHash(hHash);
    }
    if(hProv)
    {
        CryptReleaseContext(hProv, 0);
    }

    fclose(f);
    fclose(svf);

}

void PrintDwData(BYTE *_dwData, size_t size)
{
    for(size_t i = 0; i < size; i++)
    {
        wprintf(L"%02x ",  _dwData[i]);
    }
    wprintf(L"\n");
}
