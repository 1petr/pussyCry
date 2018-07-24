/*
 * AES
 * ESB
 * Padding as PKCS7
 *
*/

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#define SIZE_DATA 32768 //Размер входного массива байтов

bool errorFlag = false; //Флаг ошибки для прекращения работы программы
//bool notDel = false;

void EncryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void DecryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void PrintDwData(BYTE *_dwData, size_t size);

int main()
{
    //Режим работы программы
    TCHAR tMode;

    //Соль для генерации пароля
    TCHAR password[MAX_PATH];

    //Маска для поиска файлов
    LPCTSTR lpzMaskFile;

SelectModeLoop:

    wprintf(L"Encrypt (e) or decrypt (d) these files?\n");
    wscanf(L"%lc", &tMode);

    wprintf(L"Enter the password to encrypt(decrypt) the data:\n");
    wscanf(L"%ls", password);

    if((tMode != L'e') && (tMode != L'd'))
    {
        wprintf(L"\nMode selection error, please select mode again!\n\n");
        fflush(stdin); //Очистка входного буфера
        goto SelectModeLoop;
    }

    if(tMode == L'e')
        lpzMaskFile = L"*";
    if(tMode == L'd')
        lpzMaskFile = L"*.pussy";

    //--------------- Поиск файла по маске ------------------

    WIN32_FIND_DATA FindFileData;
    HANDLE hFind;

    hFind = FindFirstFile(lpzMaskFile, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        //wprintf(L"FindFirstFile failed %d\n", GetLastError());
        errorFlag++;
        return 0;
    }
    do
    {
        //notDel = false;
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
                if(!errorFlag) wprintf(L"Encryption was successful!\n\n");

                //Удаляем файл
                if(!errorFlag)
                {
                    DeleteFileW(FindFileData.cFileName);
                }
            }
            if(tMode == L'd')
            {
                wprintf(L"Decryption file: %ls...\n", FindFileData.cFileName);
                DecryptMyFile(FindFileData.cFileName, password);
                if(!errorFlag) wprintf(L"\nDecryption was successful!\n\n");

                //Удаляем файл
                if(!errorFlag)
                {
                    DeleteFileW(FindFileData.cFileName);
                }
            }
        }
    }
    while ((FindNextFile(hFind, &FindFileData) != 0) && (!errorFlag));

    FindClose(hFind);

    if(errorFlag)
    {
        wprintf(L"\nOoops!\nInvalid password!\n\n");
        system("pause");
    }

    return 0;
}

void EncryptMyFile(LPTSTR _wszNameFile, LPTSTR _password)
{
    FILE *f;
    FILE *sf;

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
    WCHAR wszNameFileEncrypt[MAX_PATH];
    LPCTSTR wszExpansion = L".pussy";
    LPCTSTR wszProgName = L"pussyCrypt.exe";

    wcsncpy(wszNameFileEncrypt, wszNameFile, MAX_PATH);
    wcscat(wszNameFileEncrypt, wszExpansion);

    //-----------------------------------------------------------------------

    if(!(wcscmp(wszNameFile, wszProgName))) //Сравнение имени файла с именем программы
    {
        return;
    }

//    size_t len1 = wcscspn(wszNameFile, wszExpansion);
//    size_t len2 = wcslen(wszNameFile);
/*
    if((wcscspn(wszNameFile, wszExpansion) + 6) == wcslen(wszNameFile)) //Для исключения повторного шифрования
    {
        //errorFlag++;
        notDel = true;
        return;
    }
*/
    //Открытие файлов
    f = _wfopen(wszNameFile, L"ab+" );              //исходный
    sf = _wfopen(wszNameFileEncrypt, L"ab+" );     //зашифрованный
    if((f == 0) || (sf == 0))
    {
        wprintf(L"Error open file!");
        errorFlag++;
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
        errorFlag++;
        goto Cleanup;
    }

    //Инициирование хеширования потока данных
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        wprintf(L"Error %x during CryptCreateHash!\n", GetLastError());
        errorFlag++;
        goto Cleanup;
    }

    //Хеширование пароля
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        wprintf(L"Error %x during CryptHashData!\n", GetLastError());
        errorFlag++;
        goto Cleanup;
    }

    //Создание ключа сеанса, полученного из хеша пароля
    if(!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        wprintf(L"Error %x during CryptDeriveKey!\n", GetLastError());
        errorFlag++;
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
            {
                errorFlag++;
                wprintf(L"File read error.");
            }
        }

        //-------------------------------------------
        /*
        printf("Data:\n");
        PrintDwData(pbSrcData, sh);
*/
        dwDataLen = sh;   //Количество полезных байтов в блоке шифрования

        //Копируем в буфер результата незашифрованные данные в размере этого буфера
        for(size_t i = 0; i < dwDataLen; i++)
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
            //wprintf(L"Error %d during CryptEncrypt!\n", GetLastError());
            errorFlag++;
            goto Cleanup;
        }
        /*
        printf("Encrypt data:\n");
        PrintDwData(bCryptBuf, sh);
*/
        //--------------Пишем в файл------------------------------

        fwrite(bCryptBuf, sizeof(BYTE), dwDataLen, sf);
        if(ferror(sf))
        {
            errorFlag++;
            wprintf(L"Error write file!\n");
            goto Cleanup;
        }

        //--------------------------------------------------------
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
    if(errorFlag)
    {
        if(_wremove(wszNameFileEncrypt) != 0)  // удаление файла
            wprintf(L"Error delete file!\n");
    }
}

void DecryptMyFile(LPTSTR _wszNameFile, LPTSTR _password)
{
    FILE *f;
    FILE *svf;

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
    WCHAR wszNameFileDecrypt[MAX_PATH];
    LPCTSTR wszProgName = L"pussyCrypt.exe";

    wcsncpy(wszNameFileDecrypt, L"\0", MAX_PATH);                             //Обнуляем строку
    wcsncpy(wszNameFileDecrypt, wszNameFile, (wcslen(wszNameFile) - 6)); //Стираем расширение .pussy

    //-----------------------------------------------------------------------

    if(!(wcscmp(wszNameFile, wszProgName)))     //Сравнение имени файла с именем программы
    {
        return;
    }

    //Открытие файлов
    f = _wfopen(wszNameFile, L"ab+" );          //исходный
    svf = _wfopen(wszNameFileDecrypt, L"ab+" );    //расшифрованный
    if((f == 0) || (svf == 0))
    {
        wprintf(L"Error file!");
        errorFlag++;
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
        errorFlag++;
        goto Cleanup;
    }

    //Инициирование хеширования потока данных
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        wprintf(L"Error %x during CryptCreateHash!\n", GetLastError());
        errorFlag++;
        goto Cleanup;
    }

    //Хеширование пароля
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        wprintf(L"Error %x during CryptHashData!\n", GetLastError());
        errorFlag++;
        goto Cleanup;
    }

    //Создание ключа сеанса, полученного из хеша пароля
    if(!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        wprintf(L"Error %x during CryptDeriveKey!\n", GetLastError());
        errorFlag++;
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
            {
                errorFlag++;
                wprintf(L"File read error.");
            }

        }
        //-------------------------------------------
        /*
        printf("Data:\n");
        PrintDwData(pbSrcData, sh);
*/
        dwDataLen = buflen;   //Блоки байтов

        //Копируем в буфер результата зашифрованные данные в размере этого буфера
        for(size_t i = 0; i < dwDataLen; i++)
        {
            bCryptBuf[i] = pbSrcData[i];
        }

        //Расшифровка блока
        if (!CryptDecrypt(
                    hKey,
                    0,
                    TRUE,
                    0,
                    bCryptBuf,
                    &dwDataLen))
        {
            //wprintf(L"Error %x during CryptDecrypt!\n", GetLastError());
            errorFlag++;
            goto Cleanup;
        }
        /*
        printf("Decrypt data:\n");
        PrintDwData(bCryptBuf, sh);
*/
        //--------------Пишем в файл-------------------------
        fwrite(bCryptBuf, sizeof(BYTE), dwDataLen, svf);
        if(ferror(svf))
        {
            wprintf(L"Error write file!\n");
            errorFlag++;
            goto Cleanup;
        }

        //--------------------------------------------------
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
    if(errorFlag)
    {
        if(_wremove(wszNameFileDecrypt) != 0)  // удаление файла
            wprintf(L"Error delete file!\n");
    }

}

void PrintDwData(BYTE *_dwData, size_t size)
{
    for(size_t i = 0; i < size; i++)
    {
        wprintf(L"%02x ",  _dwData[i]);
    }
    wprintf(L"\n");
}
