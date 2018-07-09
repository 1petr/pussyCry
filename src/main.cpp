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

int main(int argv, char *argc[])
{
    //Поиск файла по маске
 /*   WIN32_FIND_DATA FindFileData;
    LARGE_INTEGER filesize;
    HANDLE hFind;

    LPCTSTR lpzMaskFile = L"*.o";

    hFind = FindFirstFile(lpzMaskFile, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        printf("FindFirstFile failed %d\n", GetLastError());
    }
    else
    {
        _tprintf(TEXT("The first file found is %s\n"),FindFileData.cFileName);
    }

    do
    {
       if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
       {
          _tprintf(TEXT("%s   <DIR>\n"), FindFileData.cFileName);
       }
       else
       {
          filesize.LowPart = FindFileData.nFileSizeLow;
          filesize.HighPart = FindFileData.nFileSizeHigh;
          _tprintf(TEXT("%s   %ld bytes\n"), FindFileData.cFileName, filesize.QuadPart);
       }
    }
    while (FindNextFile(hFind, &FindFileData) != 0);

    FindClose(hFind);
*/
    //---------------------------------------------------------

    //char* to wchar_t*
    const size_t size = strlen(argc[2]) + 1;
    wchar_t* wPass = new wchar_t[size];
    mbstowcs(wPass, argc[2], size);

    HCRYPTPROV hProv = 0; //Дескриптор крипртопровайдера
    HCRYPTKEY hKey = 0;   //Дескриптор ключа
    HCRYPTHASH hHash = 0; //Дескриптор хэш-объекта
    DWORD dwCount = 16;   //Размер блока
    BYTE dwData[32];      //Блок данных (блок + 16 байт неизвестной информации от CryptEncrypt())

    //Пароль
    LPWSTR wszPassword = wPass;
    //Длина пароля в байтах
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    bool work = true;   //Условие совершения итераций while
    size_t sh = 0;      //Сколько символов считано из файла

    //Формируем имена файлов
    char cryptname[128] = "";
    char decryptname[128] = "decrypt.";

    strcat(cryptname, argc[1]);
    strcat(cryptname, ".pussy");
    strcat(decryptname, argc[1]);

    //Открытие файлов
    FILE *f = fopen(argc[1], "ab+" );          //исходный
    FILE *sf = fopen(cryptname, "ab+" );       //зашифрованный
    FILE *svf = fopen(decryptname, "ab+" );    //расшифрованный

    if((f == 0) || (sf == 0) || (svf == 0))
    {
        printf("Ошибка открытия файла!");
        return 0;
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
        //------читаем файл------------
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
        //-----------------------------
/*
        printf("\nData:\n");
        for(BYTE i = 0; i < 16; i++)
        {
            printf("%02x ",  dwData[i]);
        }
        printf("\n");
*/
        //Шифрование
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
        for(BYTE i = 0; i < 16; i++)
        {
            printf("%02x ",  dwData[i]);
        }
        printf("\n");
*/
        //-----Пишем в файл------------
        fwrite(&dwData, sizeof(BYTE), 16, sf);
        if(ferror(sf))
            printf("Ошибка потока ввода/вывода!\n");
        //-----------------------------

        //Расшифровка данных
        if (!CryptDecrypt(
                    hKey,
                    0,
                    TRUE,
                    0,
                    dwData,
                    &dwCount))
        {
            printf("Error %x during CryptEncrypt!\n", GetLastError());
            goto Cleanup;
        }
/*
        printf("Decrypt data:\n");
        for(BYTE i = 0; i < 16; i++)
        {
            printf("%02x ",  dwData[i]);
        }
        printf("\n");
*/
        //-----Пишем в файл------------
        fwrite(&dwData, sizeof(BYTE), sh, svf);
        if(ferror(sf))
            printf("Ошибка потока ввода/вывода!\n");
        //-----------------------------
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
    fclose(svf);
    delete[] wPass;

    return 0;
}
