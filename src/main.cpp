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

void EncryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void DecryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void PrintDwData(BYTE *_dwData, size_t size);

int main(int argv, char *argc[])
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
        printf("FindFirstFile failed %d\n", GetLastError());
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

    wscanf(L"%lc", &tMode);

    return 0;
}

void EncryptMyFile(LPTSTR _wszNameFile, LPTSTR _password)
{
    HCRYPTPROV hProv = 0; //Дескриптор крипртопровайдера
    HCRYPTKEY hKey = 0;   //Дескриптор ключа
    HCRYPTHASH hHash = 0; //Дескриптор хэш-объекта
    DWORD dwCount = 16;   //Размер блока
    BYTE dwData[32];      //Блок данных (блок + 16 байт неизвестной информации от CryptEncrypt())
  /*BYTE dwDataT[32] = {0xe9, 0xe6, 0x17, 0x06, 0x4f, 0x0b, 0xb2, 0x94,
                       0xe7, 0xd2, 0x8f, 0xfa, 0xe9, 0x24, 0x0b, 0x23,
                       0xad, 0x67, 0xc6, 0xcc, 0xb1, 0x48, 0xc4, 0xa3,
                       0x95, 0x65, 0xd3, 0x79, 0x3d, 0xef, 0xfe, 0x8f}; // -->> .qmake.stash.pussy */

    //Пароль
    LPTSTR wszPassword = _password;
    //Длина пароля в байтах
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    bool work = true;   //Условие совершения итераций while
    size_t sh = 0;      //Сколько символов считано из файла

    //----------------------Формируем имена файлов-----------------------------

    WCHAR *wszNameFile = _wszNameFile;
    WCHAR wszNameFileEncrypt[128];
    WCHAR *wszExpansion = L".pussy";

    wcsncpy(wszNameFileEncrypt, wszNameFile, 128);
    wcscat(wszNameFileEncrypt, wszExpansion);

    //-----------------------------------------------------------------------

    if(wszNameFile == L"pussyCrypt.exe")
    {
        return;
    }

    //Открытие файлов
    FILE *f = _wfopen(wszNameFile, L"ab+" );          //исходный
    FILE *sf = _wfopen(wszNameFileEncrypt, L"ab+" );     //зашифрованный
    if((f == 0) || (sf == 0))
    {
        printf("Ошибка открытия файла!");
        return;
    }

    //Получаем контекст криптопровайдера
    if(!CryptAcquireContext(
                &hProv,
                NULL,
                MS_ENH_RSA_AES_PROV,
                PROV_RSA_AES,
                CRYPT_VERIFYCONTEXT))
    {
        printf("Error %x during CryptAcquireContext!\n", GetLastError());
        goto Cleanup;
    }

    //Инициирование хеширования потока данных
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        printf("Error %x during CryptCreateHash!\n", GetLastError());
        goto Cleanup;
    }

    //Хеширование пароля
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        printf("Error %x during CryptHashData!\n", GetLastError());
        goto Cleanup;
    }

    //Создание ключа сеанса, полученного из хеша пароля
    if(!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        printf("Error %x during CryptDeriveKey!\n", GetLastError());
        goto Cleanup;
    }

    while(work)
    {
        //---------------читаем файл-----------------
        sh = fread(dwData, sizeof(BYTE), 16, f);
        if(sh != 16)
        {
            if(feof(f))
            {
                for(DWORD i = sh; i < 16; i++)
                {
                    dwData[i] = 16 - sh;
                }
                work = false;
            }
            if(ferror(f))
                printf("File read error.");
        }
        //-------------------------------------------
/*
        printf("Data:\n");
        PrintDwData(dwData, sh);
*/

        dwCount = 16;   //Обнуление счетчика зашифрованных байтов

        //Шифрование блока
        if (!CryptEncrypt(
                    hKey,
                    0,
                    TRUE,
                    0,
                    dwData,
                    &dwCount,
                    sizeof(dwData)))
        {
            printf("Error %d during CryptEncrypt!\n", GetLastError());
            goto Cleanup;
        }
/*
        printf("Encrypt data:\n");
        PrintDwData(dwData, sh);

        printf("Success!");
*/
        //--------------Пишем в файл---------------
        fwrite(&dwData, sizeof(BYTE), 32, sf);
        if(ferror(sf))
            printf("Error write file!\n");
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

void PrintDwData(BYTE *_dwData, size_t size)
{
    for(size_t i = 0; i < size; i++)
    {
        printf("%02x ",  _dwData[i]);
    }
    printf("\n");
}

void DecryptMyFile(LPTSTR _wszNameFile, LPTSTR _password)
{
    HCRYPTPROV hProv = 0; //Дескриптор крипртопровайдера
    HCRYPTKEY hKey = 0;   //Дескриптор ключа
    HCRYPTHASH hHash = 0; //Дескриптор хэш-объекта
    DWORD dwCount = 16;   //Размер блока
    BYTE dwData[32];      //Блок данных (блок + 16 байт неизвестной информации от CryptEncrypt())

    //Пароль
    LPTSTR wszPassword = _password;
    //Длина пароля в байтах
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    bool work = true;   //Условие совершения итераций while
    size_t sh = 0;      //Сколько символов считано из файла

    //----------------------Формируем имена файлов-----------------------------

    WCHAR *wszNameFile = _wszNameFile;
    WCHAR wszNameFileDecrypt[128];
    WCHAR *wszExpansionDecrypt = L".dec";

    //size_t pos = wcscspn(wszNameFile, wszExpansion);
    //printf("pos = %d\n", pos);

    wcsncpy(wszNameFileDecrypt, wszNameFile, 128);
    wcscat(wszNameFileDecrypt, wszExpansionDecrypt);
//    wprintf(L"wszNameFileDecrypt = %ls\n", wszNameFileDecrypt);

    //-----------------------------------------------------------------------

    if(wszNameFile == L"pussyCrypt.exe")
    {
        return;
    }

    //Открытие файлов
    FILE *f = _wfopen(wszNameFile, L"ab+" );          //исходный
    FILE *svf = _wfopen(wszNameFileDecrypt, L"ab+" );    //расшифрованный
    if((f == 0) || (svf == 0))
    {
        printf("Error file!");
        return;
    }

    //Получаем контекст криптопровайдера
    if(!CryptAcquireContext(
                &hProv,
                NULL,
                MS_ENH_RSA_AES_PROV,
                PROV_RSA_AES,
                CRYPT_VERIFYCONTEXT))
    {
        printf("Error %x during CryptAcquireContext!\n", GetLastError());
        goto Cleanup;
    }

    //Инициирование хеширования потока данных
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        printf("Error %x during CryptCreateHash!\n", GetLastError());
        goto Cleanup;
    }

    //Хеширование пароля
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        printf("Error %x during CryptHashData!\n", GetLastError());
        goto Cleanup;
    }

    //Создание ключа сеанса, полученного из хеша пароля
    if(!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        printf("Error %x during CryptDeriveKey!\n", GetLastError());
        goto Cleanup;
    }

    while(work)
    {
        //---------------читаем файл-----------------
        sh = fread(dwData, sizeof(BYTE), 32, f);
        if(sh != 32)
        {
            if(feof(f))
            {
                for(DWORD i = sh; i < 32; i++)
                {
                    dwData[i] = 32 - sh;
                }
                work = false;
            }
            if(ferror(f))
                printf("File read error.");
        }
        //-------------------------------------------
/*
        printf("Data:\n");
        PrintDwData(dwData, sh);
*/
        dwCount = 32;   //Обнуление счетчика зашифрованных байтов

        //Расшифровка данных
        if (!CryptDecrypt(
                    hKey,
                    0,
                    TRUE,
                    0,
                    dwData,
                    &dwCount))
        {
            printf("Error %x during CryptDecrypt!\n", GetLastError());
            goto Cleanup;
        }
/*
        printf("Decrypt data:\n");
        PrintDwData(dwData, sh);
*/
        //--------------Пишем в файл---------------
        fwrite(&dwData, sizeof(BYTE), 16, svf);
        if(ferror(svf))
            printf("Error write file!\n");
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
