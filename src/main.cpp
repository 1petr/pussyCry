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

#define SIZE_DATA 32768 //������ �室���� ���ᨢ� ���⮢
#define WEXE_NAME L"trend.exe"

static bool errorFlag = false; //���� �訡�� ��� �४�饭�� ࠡ��� �ணࠬ��

void EncryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void DecryptMyFile(LPTSTR _wszNameFile, LPTSTR _password);
void PrintDwData(BYTE *_dwData, size_t size);
LPTSTR RenameThisFile(LPTSTR _wszNameFile, bool isFolder = false);

int main()
{
    setlocale(LC_ALL, "");

    //��� �࠭���� ⥪�饩 ��४�ਨ
    TCHAR sMyCurrentDirectory[MAX_PATH] = L"";

    //����� ࠡ��� �ணࠬ��
    TCHAR tMode = L'e';

    //���� ��� �����樨 ��஫�
    TCHAR password[MAX_PATH] = L"";

    //��᪠ ��� ���᪠ 䠩���
    LPCTSTR lpzMaskFile = L"";

    WIN32_FIND_DATA FindFileData;
    WCHAR *MyFindFileName;
    HANDLE hFind;
    size_t uAllFilesCount = 0;  //��饥 ������⢮ 䠩���
    size_t uFilesCount = 0;     //����� 䠩��

    wprintf(L"Enter the path of the directory: ");
    _getws(sMyCurrentDirectory);
    fflush(stdin); //���⪠ �室���� ����

    SetCurrentDirectoryW(sMyCurrentDirectory);

SelectModeLoop:

    wprintf(L"Encrypt (e) or decrypt (d) these files? : ");
    _getws(&tMode);

    if((tMode != L'e') && (tMode != L'd'))
    {
        wprintf(L"\nMode selection error, please select mode again!\n\n");
        fflush(stdin); //���⪠ �室���� ����
        goto SelectModeLoop;
    }

    wprintf(L"Enter the password to encrypt(decrypt) the data: ");
    _getws(password);

    //-------------������ 䠩��� �� ��᪥-------------------

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

    //--------------- ���� 䠩�� �� ��᪥ ------------------

    hFind = FindFirstFile(lpzMaskFile, &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        //wprintf(L"FindFirstFile failed %d\n", GetLastError());
        errorFlag = true;
        return 0;
    }
    do
    {
        MyFindFileName = FindFileData.cFileName;

        if(!(wcscmp(MyFindFileName, WEXE_NAME))) //�ࠢ����� ����� 䠩�� � ������ �ணࠬ��, �� �ਯ⮢��� ����୨�
        {
            continue;
        }

        if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) //��ࠡ�⪠ ��४�਩
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

                if(!(MyFindFileName = RenameThisFile(MyFindFileName)))  //��२�������� 䠩�� � ���� �� �����஢��
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
            //����塞 ������஢���� 䠩�
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

    wprintf(L"\nDONE!\n");

    return 0;
}

void EncryptMyFile(LPTSTR _wszNameFile, LPTSTR _password)
{
    FILE *f;
    FILE *sf;

    HCRYPTPROV hProv = 0; //���ਯ�� �ਯ�⮯஢�����
    HCRYPTKEY hKey = 0;   //���ਯ�� ����
    HCRYPTHASH hHash = 0; //���ਯ�� ���-��ꥪ�

    size_t sizeBuffRead = SIZE_DATA - 1;     //����쪮 ���� �⠥� �� 䠩��
    BYTE pbSrcData[SIZE_DATA]; //����� ��� ��஢����
    DWORD dwDataLen;  //������ ������஢����� ������
    BYTE  bCryptBuf[SIZE_DATA]; //�����⥫� �� ���ᨢ १����
    DWORD  buflen = SIZE_DATA;  //������ ���ᨢ� १����
    size_t sh = 0;              //������⢮ ��⠭��� ᨬ�����

    //��஫�
    LPTSTR wszPassword = _password;

    //����� ��஫� � �����
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    bool work = true;   //�᫮��� ᮢ��襭�� ���権 while

    //----------------------��ନ�㥬 ����� 䠩���-----------------------------

    WCHAR *wszNameFile = _wszNameFile;
    WCHAR wszNameFileEncrypt[MAX_PATH];
    LPCTSTR wszExpansion = L".end";

    wcsncpy(wszNameFileEncrypt, wszNameFile, MAX_PATH);
    wcscat(wszNameFileEncrypt, wszExpansion);

    //-----------------------------------------------------------------------

    //����⨥ 䠩���
    f = _wfopen(wszNameFile, L"ab+" );              //��室��
    sf = _wfopen(wszNameFileEncrypt, L"ab+" );     //����஢����
    if((f == nullptr) || (sf == nullptr))
    {
        wprintf(L"Error open file!");
        errorFlag = true;
        goto Cleanup;
    }

    //����砥� ���⥪�� �ਯ⮯஢�����
    if(!CryptAcquireContext(
                &hProv,
                nullptr,
                MS_ENH_RSA_AES_PROV,
                PROV_RSA_AES,
                CRYPT_VERIFYCONTEXT))
    {
        wprintf(L"Error %x during CryptAcquireContext!\n", GetLastError());
        errorFlag = true;
        goto Cleanup;
    }

    //���樨஢���� ��஢���� ��⮪� ������
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        wprintf(L"Error %x during CryptCreateHash!\n", GetLastError());
        errorFlag = true;
        goto Cleanup;
    }

    //���஢���� ��஫�
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        wprintf(L"Error %x during CryptHashData!\n", GetLastError());
        errorFlag = true;
        goto Cleanup;
    }

    //�������� ���� ᥠ��, ����祭���� �� �� ��஫�
    if(!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        wprintf(L"Error %x during CryptDeriveKey!\n", GetLastError());
        errorFlag = true;
        goto Cleanup;
    }

    while(work)
    {
        //---------------�⠥� 䠩�-----------------

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
                errorFlag = true;
                wprintf(L"File read error.");
            }
        }

        //-------------------------------------------
        /*
        printf("Data:\n");
        PrintDwData(pbSrcData, sh);
*/
        dwDataLen = sh;   //������⢮ �������� ���⮢ � ����� ��஢����

        //�����㥬 � ���� १���� ������஢���� ����� � ࠧ��� �⮣� ����
        for(size_t i = 0; i < dwDataLen; i++)
        {
            bCryptBuf[i] = pbSrcData[i];
        }

        //���஢���� �����
        if (!CryptEncrypt(
                    hKey,
                    0,      // no hash
                    TRUE,   // "final" flag
                    0,      // reserved
                    bCryptBuf,  // buffer with data
                    &dwDataLen, // return size for ciphered text
                    buflen))    //������ �����
        {
            //wprintf(L"Error %d during CryptEncrypt!\n", GetLastError());
            errorFlag = true;
            goto Cleanup;
        }
        /*
        printf("Encrypt data:\n");
        PrintDwData(bCryptBuf, sh);
*/
        //--------------��襬 � 䠩�------------------------------

        fwrite(bCryptBuf, sizeof(BYTE), dwDataLen, sf);
        if(ferror(sf))
        {
            errorFlag = true;
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
        if(_wremove(wszNameFileEncrypt) != 0)  // 㤠����� 䠩�� � ��砥 �訡��
            wprintf(L"Error delete file!\n");
    }
}

void DecryptMyFile(LPTSTR _wszNameFile, LPTSTR _password)
{
    FILE *f;
    FILE *svf;

    HCRYPTPROV hProv = 0; //���ਯ�� �ਯ�⮯஢�����
    HCRYPTKEY hKey = 0;   //���ਯ�� ����
    HCRYPTHASH hHash = 0; //���ਯ�� ���-��ꥪ�

    size_t sizeBuffRead = SIZE_DATA;     //����쪮 ���� �⠥� �� 䠩��
    BYTE pbSrcData[SIZE_DATA];  //����� ��� ��஢����
    DWORD dwDataLen;            //������ ������஢����� ������
    BYTE  bCryptBuf[SIZE_DATA]; //�����⥫� �� ���ᨢ १����
    DWORD  buflen = SIZE_DATA;  //������ ���ᨢ� १����
    size_t sh = 0;              //������⢮ ���⠭��� ᨬ�����

    //��஫�
    LPTSTR wszPassword = _password;
    //����� ��஫� � �����
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    bool work = true;   //�᫮��� ᮢ��襭�� ���権 while

    //----------------------��ନ�㥬 ����� 䠩���-----------------------------

    WCHAR *wszNameFile = _wszNameFile;
    WCHAR wszNameFileDecrypt[MAX_PATH];

    wcsncpy(wszNameFileDecrypt, L"\0", MAX_PATH);                             //����塞 ��ப�
    wcsncpy(wszNameFileDecrypt, wszNameFile, (wcslen(wszNameFile) - 4)); //��ࠥ� ���७�� .end

    //-----------------------------------------------------------------------

    //����⨥ 䠩���
    f = _wfopen(wszNameFile, L"ab+" );          //��室��
    svf = _wfopen(wszNameFileDecrypt, L"ab+" );    //����஢����
    if((f == nullptr) || (svf == nullptr))
    {
        //wprintf(L"Error file!");
        errorFlag = true;
        goto Cleanup;
    }

    //����砥� ���⥪�� �ਯ⮯஢�����
    if(!CryptAcquireContext(
                &hProv,
                nullptr,
                MS_ENH_RSA_AES_PROV,
                PROV_RSA_AES,
                CRYPT_VERIFYCONTEXT))
    {
        //wprintf(L"Error %x during CryptAcquireContext!\n", GetLastError());
        errorFlag = true;
        goto Cleanup;
    }

    //���樨஢���� ��஢���� ��⮪� ������
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        //wprintf(L"Error %x during CryptCreateHash!\n", GetLastError());
        errorFlag = true;
        goto Cleanup;
    }

    //���஢���� ��஫�
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        //wprintf(L"Error %x during CryptHashData!\n", GetLastError());
        errorFlag = true;
        goto Cleanup;
    }

    //�������� ���� ᥠ��, ����祭���� �� �� ��஫�
    if(!CryptDeriveKey(hProv, CALG_AES_128, hHash, CRYPT_EXPORTABLE, &hKey))
    {
        //wprintf(L"Error %x during CryptDeriveKey!\n", GetLastError());
        errorFlag = true;
        goto Cleanup;
    }

    while(work)
    {
        //---------------�⠥� 䠩�-----------------
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
                errorFlag = true;
                //wprintf(L"File read error.");
            }
        }
        //-------------------------------------------
        /*
        printf("Data:\n");
        PrintDwData(pbSrcData, sh);
*/
        dwDataLen = buflen;   //����� ���⮢

        //�����㥬 � ���� १���� ����஢���� ����� � ࠧ��� �⮣� ����
        for(size_t i = 0; i < dwDataLen; i++)
        {
            bCryptBuf[i] = pbSrcData[i];
        }

        //�����஢�� �����
        if (!CryptDecrypt(
                    hKey,
                    0,
                    TRUE,
                    0,
                    bCryptBuf,
                    &dwDataLen))
        {
            //wprintf(L"Error %x during CryptDecrypt!\n", GetLastError());
            errorFlag = true;
            goto Cleanup;
        }
        /*
        printf("Decrypt data:\n");
        PrintDwData(bCryptBuf, sh);
*/
        //--------------��襬 � 䠩�-------------------------
        fwrite(bCryptBuf, sizeof(BYTE), dwDataLen, svf);
        if(ferror(svf))
        {
            //wprintf(L"Error write file!\n");
            errorFlag = true;
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
        if(_wremove(wszNameFileDecrypt) != 0)  // 㤠����� 䠩��
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
    HCRYPTPROV hProv = 0; //���ਯ�� �ਯ�⮯஢�����
    HCRYPTHASH hHash = 0; //���ਯ�� ���-��ꥪ�

    //��஫�
    LPCTSTR wszPassword = _wszNameFile;

    //����� ��஫� � �����
    DWORD cbPassword = (wcslen(wszPassword) + 1)*sizeof(WCHAR);

    DWORD dwHashLen = 32;
    BYTE bHash[dwHashLen]; //���⮢� ���ᨢ �������� ������

    char PathToFile[MAX_PATH] = ""; //����� ����
    char DestNameFile[MAX_PATH] = "";  //����� ���� � ���� ������

    char NameFileA[MAX_PATH] = ""; //��� 䠩�� char*
    wcstombs(NameFileA, _wszNameFile, MAX_PATH);    // wchar_t* -> char*
    char NameFile[MAX_PATH] = ""; //����� ���� 䠩�� char*

    char Expansion[MAX_PATH] = "";

    char sHash[MAX_PATH] = "";  //�� ��ப��
    char spHash[dwHashLen][MAX_PATH];   //��ப� ��� ������� ���� ��

    //����砥� ���⥪�� �ਯ⮯஢�����
    if(!CryptAcquireContext(
                &hProv,
                nullptr,
                MS_ENH_RSA_AES_PROV,
                PROV_RSA_AES,
                CRYPT_VERIFYCONTEXT))
    {
        //wprintf(L"Error %x during CryptAcquireContext!\n", GetLastError());
    }

    //���樨஢���� ��஢���� ��⮪� ������
    if(!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        //wprintf(L"Error %x during CryptCreateHash!\n", GetLastError());
    }

    //���஢���� ��஫�
    if(!CryptHashData(hHash, (PBYTE)wszPassword, cbPassword, 0))
    {
        //wprintf(L"Error %x during CryptHashData!\n", GetLastError());
    }

    //������ ���祭�� ���
    if(!CryptGetHashParam(hHash, HP_HASHVAL, bHash, &dwHashLen, 0)){

        //wprintf(L"Error %x during CryptGetHashParam!\n", GetLastError());
    }

    //��९���� �� � ��ப�
    for(DWORD i = 0; i < dwHashLen; i++)
    {
        //�᫨ �����, � ����� �� 10 ����
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

    //����砥� ���� ⥪�饩 ��४�ਨ
    GetCurrentDirectoryA(MAX_PATH, PathToFile);
    strcat(PathToFile, "\\");

    //����砥� ���७�� 䠩��
    size_t count = 0;
    for(size_t i = 0; i < strlen(NameFileA); i++)
    {
        if(NameFileA[i] == '.')
            count = i;
    }
    if(count == 0) count = strlen(NameFileA); //��� 䠩��� ��� ���७��
    for(size_t i = 0, j = 0; i < strlen(NameFileA); i++)
    {
        if(i >= count)
        {
            Expansion[j] = NameFileA[i];
            j++;
        }
    }

    //�᫨ 䠩� ����஢��, ��室��
    if(!strcmp(Expansion, ".end"))
    {
        //wprintf(L"Error rechiper files!\n");
        return nullptr;
    }

    //��ନ�㥬 ���� �� 䠩��
    strcat(NameFile, PathToFile);
    strcat(NameFile, NameFileA);

    //��ନ�㥬 ���� ���� �� 䠩��
    strncpy(DestNameFile, PathToFile, MAX_PATH);  // ncpy ��� ��१���� static
    strcat(DestNameFile, sHash);
    strcat(DestNameFile, Expansion);

    //��२��������� 䠩��
    if(!MoveFileA(NameFile, DestNameFile))
    {
       // wprintf(L"Error %x during MoveFileA!\n", GetLastError());
    }

    //�ᮢ���� ���ਯ�� ��� ��ꥪ�
    if(!CryptDestroyHash(hHash))
    {
       // wprintf(L"Error %x during CryptDestroyHash!\n", GetLastError());
    }
    //�᢮������ ���ਯ�� �ਯ⮯஢�����
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
