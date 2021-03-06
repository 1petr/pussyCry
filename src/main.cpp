/*
 * AES
 * ESB
 * Padding as PKCS7
 * WIN API
 *
*/

#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <iostream>

#define SIZE_DATA 32768 //Размер входного массива байтов
#define WEXE_NAME L"trend.exe"

bool errorFlag = false; //Флаг ошибки для прекращения работы программы

void EncryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void DecryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void PrintDwData(BYTE *_dwData, size_t size);
LPTSTR RenameThisFile(LPTSTR _wszNameFile, bool isFolder = false);

int main()
{
    setlocale(LC_ALL, "");

    //Для хранения текущей директории
    TCHAR sMyCurrentDirectory[MAX_PATH] = L"";

    //Режим работы программы
    TCHAR tMode = L'e';

    //Соль для генерации пароля
    TCHAR password[MAX_PATH] = L"";

    //Маска для поиска файлов
    LPCTSTR lpzMaskFile = L"";

    WIN32_FIND_DATA FindFileData;
    WCHAR *MyFindFileName;
    HANDLE hFind;
    size_t uAllFilesCount = 0;  //Общее количество файлов
    size_t uFilesCount = 0;     //Номер файла

    wprintf(L"Enter the path of the directory: ");
    wscanf(L"%ls", sMyCurrentDirectory);
    fflush(stdin); //Очистка входного буфера

    SetCurrentDirectoryW(sMyCurrentDirectory);

SelectModeLoop:

    wprintf(L"Encrypt (e) or decrypt (d) these files? : ");
    wscanf(L"%lc", &tMode);

    if((tMode != L'e') && (tMode != L'd'))
    {
        wprintf(L"\nMode selection error, please select mode again!\n\n");
        fflush(stdin); //Очистка входного буфера
        goto SelectModeLoop;
    }

    wprintf(L"Enter the password to encrypt(decrypt) the data: ");
    wscanf(L"%ls", password);

    //-------------Подсчет файлов по маске-------------------

    if(tMode == L'e')
        lpzMaskFile = L"*";
    if(tMode == L'd')
        lpzMaskFile = L"*.end";

    hFind = FindFirstFile(lpzMaskFile, &FindFileData);
    assert(hFind);
    do
    {
         MyFindFileName = FindFileData.cFileName;
         if((wcscmp(MyFindFileName, L".")) && (wcscmp(MyFindFileName, L"..")) && (wcscmp(MyFindFileName, WEXE_NAME)))
         {
              //wprintf(L"%s\n", MyFindFileName);
              uAllFilesCount++;
         }
    }
    while(FindNextFile(hFind, &FindFileData) != 0);

    //wprintf(L"%d files were found!\n", uAllFilesCount);

    //--------------- Поиск файла по маске ------------------

    hFind = FindFirstFile(lpzMaskFile, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        //wprintf(L"FindFirstFile failed %d\n", GetLastError());
        errorFlag++;
        return 0;
    }
    do
    {
        MyFindFileName = FindFileData.cFileName;

        if(!(wcscmp(MyFindFileName, WEXE_NAME))) //Сравнение имени файла с именем программы, не криптовать бинарник
        {
            continue;
        }

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) //Обработка директорий
        {
            if((wcscmp(MyFindFileName, L".")) && (wcscmp(MyFindFileName, L"..")) && tMode == L'e')
            {
                uFilesCount++;
                wprintf(L"Encrypting the directory name( %d/%d ): %ls\n", uFilesCount, uAllFilesCount, MyFindFileName);
                RenameThisFile(MyFindFileName, true);
            }
        }
        else
        {
            uFilesCount++;
            if(tMode == L'e')
            {
                wprintf(L"Encryption file( %d/%d ): %ls\n", uFilesCount, uAllFilesCount, MyFindFileName);

                if(!(MyFindFileName = RenameThisFile(MyFindFileName)))  //переименоание файла и защита от перешифровки
                {
                    wprintf(L"The file's already encrypted, skipping it.\n\n");
                    continue;
                }

                if(!errorFlag)
                    EncryptMyFile(MyFindFileName, password);
                if(!errorFlag)
                {
                    wprintf(L"Done.\n\n");
                }
            }
            if(tMode == L'd')
            {
                wprintf(L"Decryption file( %d/%d ): %ls\n", uFilesCount, uAllFilesCount, MyFindFileName);
                if(!errorFlag)
                    DecryptMyFile(MyFindFileName, password);
                if(!errorFlag)
                    wprintf(L"Done.\n\n");
            }
            //Удаляем незашифрованный файл
            if(!errorFlag)
            {
                DeleteFileW(MyFindFileName);
            }
        }
    }
    while((FindNextFile(hFind, &FindFileData) != 0) && (!errorFlag));

    FindClose(hFind);

    if(errorFlag)
    {
        wprintf(L"\nOoops! Error!\n\n");
        system("pause");
    }

    wprintf(L"\nDONE!");

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
    DWORD  buflen = SIZE_DATA;  //Размер массива результата
    size_t sh = 0;              //Количество считанных символов

    //Пароль
    LPTSTR wszPassword = _password;

    //Длина пароля в байтах
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    bool work = true;   //Условие совершения итераций while

    //----------------------Формируем имена файлов-----------------------------

    WCHAR *wszNameFile = _wszNameFile;
    WCHAR wszNameFileEncrypt[MAX_PATH];
    LPCTSTR wszExpansion = L".end";

    wcsncpy(wszNameFileEncrypt, wszNameFile, MAX_PATH);
    wcscat(wszNameFileEncrypt, wszExpansion);

    //-----------------------------------------------------------------------

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
        if(_wremove(wszNameFileEncrypt) != 0)  // удаление файла в случае ошибки
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
    BYTE pbSrcData[SIZE_DATA];  //Данные для шифрования
    DWORD dwDataLen;            //Размер незашифрованных данных
    BYTE  bCryptBuf[SIZE_DATA]; //Указатель на массив результата
    DWORD  buflen = SIZE_DATA;  //Размер массива результата
    size_t sh = 0;              //Количество прочитанных символов

    //Пароль
    LPTSTR wszPassword = _password;
    //Длина пароля в байтах
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    bool work = true;   //Условие совершения итераций while

    //----------------------Формируем имена файлов-----------------------------

    WCHAR *wszNameFile = _wszNameFile;
    WCHAR wszNameFileDecrypt[MAX_PATH];

    wcsncpy(wszNameFileDecrypt, L"\0", MAX_PATH);                             //Обнуляем строку
    wcsncpy(wszNameFileDecrypt, wszNameFile, (wcslen(wszNameFile) - 4)); //Стираем расширение .end

    //-----------------------------------------------------------------------

    //Открытие файлов
    f = _wfopen(wszNameFile, L"ab+" );          //исходный
    svf = _wfopen(wszNameFileDecrypt, L"ab+" );    //расшифрованный
    if((f == 0) || (svf == 0))
    {
        //wprintf(L"Error file!");
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
        //wprintf(L"Error %x during CryptAcquireContext!\n", GetLastError());
        errorFlag++;
        goto Cleanup;
    }

    //Инициирование хеширования потока данных
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        //wprintf(L"Error %x during CryptCreateHash!\n", GetLastError());
        errorFlag++;
        goto Cleanup;
    }

    //Хеширование пароля
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        //wprintf(L"Error %x during CryptHashData!\n", GetLastError());
        errorFlag++;
        goto Cleanup;
    }

    //Создание ключа сеанса, полученного из хеша пароля
    if(!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        //wprintf(L"Error %x during CryptDeriveKey!\n", GetLastError());
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
                //wprintf(L"File read error.");
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
            //wprintf(L"Error write file!\n");
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
        {
            wprintf(L"Error delete file!\n");
        }
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

LPTSTR RenameThisFile(LPTSTR _wszNameFile, bool isFolder)
{
    HCRYPTPROV hProv = 0; //Дескриптор крипртопровайдера
    HCRYPTHASH hHash = 0; //Дескриптор хэш-объекта

    //Пароль
    LPCTSTR wszPassword = _wszNameFile;

    //Длина пароля в байтах
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    DWORD dwHashLen = 32;
    BYTE bHash[dwHashLen]; //байтовый массив ВЫХОДНЫХ данных

    char PathToFile[MAX_PATH] = ""; //Полный путь
    char DestNameFile[MAX_PATH] = "";  //Полный путь с новым именем

    char NameFileA[MAX_PATH] = ""; //Имя файла char*
    wcstombs(NameFileA, _wszNameFile, MAX_PATH);    // wchar_t* -> char*
    char NameFile[MAX_PATH] = ""; //Полный путь файла char*

    char Expansion[MAX_PATH] = "";

    char sHash[MAX_PATH] = "";  //хеш строкой
    char spHash[dwHashLen][MAX_PATH];   //строка для каждого байта хеша

    //Получаем контекст криптопровайдера
    if(!CryptAcquireContext(
                &hProv,
                NULL,
                MS_ENH_RSA_AES_PROV,
                PROV_RSA_AES,
                CRYPT_VERIFYCONTEXT))
    {
        //wprintf(L"Error %x during CryptAcquireContext!\n", GetLastError());
    }

    //Инициирование хеширования потока данных
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        //wprintf(L"Error %x during CryptCreateHash!\n", GetLastError());
    }

    //Хеширование пароля
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        //wprintf(L"Error %x during CryptHashData!\n", GetLastError());
    }

    //получаю значение хэша
    if(!CryptGetHashParam(hHash, HP_HASHVAL, bHash, &dwHashLen, 0)){

        //wprintf(L"Error %x during CryptGetHashParam!\n", GetLastError());
    }

    //Переписать хеш в строку
    for(DWORD i = 0; i < dwHashLen; i++)
    {
        //Если папка, то длина хеша 10 байт
        if(isFolder)
        {
            if(i%3 == 0)
            {
                sprintf(spHash[i], "%02x", bHash[i]);
                strcat(sHash, spHash[i]);
            }
        }
        else
        {
            if(i%3 == 0)
            {
                sprintf(spHash[i], "%02x", bHash[i]);
                strcat(sHash, spHash[i]);
            }
        }
    }

    //Получаем путь текущей директории
    GetCurrentDirectoryA(MAX_PATH, PathToFile);
    strcat(PathToFile, "\\");

    //Получаем расширение файла
    size_t count = 0;
    for(size_t i = 0; i < strlen(NameFileA); i++)
    {
        if(NameFileA[i] == '.')
            count = i;
    }
    if(count == 0) count = strlen(NameFileA); //Для файлов без расширения
    for(size_t i = 0, j = 0; i < strlen(NameFileA); i++)
    {
        if(i >= count)
        {
            Expansion[j] = NameFileA[i];
            j++;
        }
    }

    //Если файл зашифрован, выходим
    if(!strcmp(Expansion, ".end"))
    {
        //wprintf(L"Error rechiper files!\n");
        return 0;
    }

    //Формируем путь до файла
    strcat(NameFile, PathToFile);
    strcat(NameFile, NameFileA);

    //Формируем новый путь до файла
    strncpy(DestNameFile, PathToFile, MAX_PATH);  // ncpy для перезаписи static
    strcat(DestNameFile, sHash);
    strcat(DestNameFile, Expansion);

    //Переимеонвание файла
    if(!MoveFileA(NameFile, DestNameFile))
    {
       // wprintf(L"Error %x during MoveFileA!\n", GetLastError());
    }

    //осовждаю дескриптор хэш объекта
    if(!CryptDestroyHash(hHash))
    {
       // wprintf(L"Error %x during CryptDestroyHash!\n", GetLastError());
    }
    //освобождаю дескриптор криптопровайдера
    if(!CryptReleaseContext(hProv, 0))
    {
        //wprintf(L"Error %x during CryptReleaseContext!\n", GetLastError());
    }

    //const size_t size = strlen(DestNameFile) + 1;
    static WCHAR wDestName[MAX_PATH];
    wcsncpy(wDestName, L"", MAX_PATH);
    mbstowcs(wDestName, strcat(sHash, Expansion), MAX_PATH);

    return wDestName;
}
