#pragma once

#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")
#include <windows.h>
#include <bcrypt.h>
#include <dpapi.h>
#include <ncrypt.h>
#include <optional>

#include <stdexcept>
#include <cstdint>
#include <cstring>

namespace CryptoHelper {
    // Memory helpers
    inline void secure_zero_memory(void* ptr, size_t len) {
        if (!ptr || len == 0) return;
        SecureZeroMemory(ptr, len);
    }


    inline bool lock_memory(void* ptr, size_t len) {
        return (VirtualLock(ptr, len) != 0); // Non-zero is success
    }

    inline bool unlock_memory(void* ptr, size_t len) {
        return (VirtualUnlock(ptr, len) != 0); // Non-zero is success
    }

    inline void gen_secure_random_bytes(uint8_t* buffer, size_t length) {
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, buffer, static_cast<ULONG>(length), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
            throw std::runtime_error("BCryptGenRandom failed");
        }
    }

    // Windows APIs

    std::string OpenFileDialog(HWND hwnd) {
        OPENFILENAMEA ofn;       // Estrutura da API do Windows
        char szFile[260] = { 0 }; // Buffer para o caminho do arquivo

        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hwnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "Sanctum Diary (*.sdde)\0*.sdde\0Todos os arquivos\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.lpstrFileTitle = NULL;
        ofn.nMaxFileTitle = 0;
        ofn.lpstrInitialDir = NULL;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

        if (GetOpenFileNameA(&ofn)) {
            std::string result(szFile);
            secure_zero_memory(szFile, sizeof(szFile)); 
            return result;
        }
        return "";
    }

    std::string SaveFileDialog(HWND hwnd, bool restrict=true) {
        OPENFILENAMEA ofn;
        char szFile[MAX_PATH] = { 0 };

        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hwnd;
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        if(restrict) {
            ofn.lpstrFilter = "Sanctum Diary (*.sdde)\0*.sdde\0";
        } else {
            ofn.lpstrFilter = "All Files (*.*)\0*.*\0";
        }
        ofn.nFilterIndex = 1;
        ofn.lpstrFileTitle = NULL;
        ofn.nMaxFileTitle = 0;
        ofn.lpstrInitialDir = NULL;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
        if(restrict) ofn.lpstrDefExt = "sdde";

        if (GetSaveFileNameA(&ofn)) {
            return std::string(szFile);
        }
        
        return "";
    }


    inline bool create_windows_hello_key(const std::wstring& key_name) {
        NCRYPT_PROV_HANDLE hProv = 0;
        NCRYPT_KEY_HANDLE hKey = 0;
        
        // 1. Abrir o Provedor de Armazenamento de Chaves (TPM)
        if (NCryptOpenStorageProvider(&hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) return false;

        // 2. Criar a chave
        if (NCryptCreatePersistedKey(hProv, &hKey, BCRYPT_RSA_ALGORITHM, key_name.c_str(), 0, 0) != ERROR_SUCCESS) {
            NCryptFreeObject(hProv);
            return false;
        }

        // 3. Configurar a Política de UI para forçar o Windows Hello
        NCRYPT_UI_POLICY uiPolicy = {};
        uiPolicy.dwVersion = 1;
        uiPolicy.dwFlags = 0x00000001; // Força Biometria/PIN
        uiPolicy.pszCreationTitle = L"Proteção de Chave Scrypt";
        uiPolicy.pszFriendlyName = L"Digite sua chave Sanctum";
        uiPolicy.pszDescription = L"Autentique-se para acessar seus dados seguros.";

        NCryptSetProperty(hKey, NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&uiPolicy, sizeof(uiPolicy), 0);

        // 4. Finalizar a criação da chave (ela é gravada no TPM aqui)
        SECURITY_STATUS status = NCryptFinalizeKey(hKey, 0);

        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        return (status == ERROR_SUCCESS);
    }

    inline std::optional<std::vector<uint8_t>> decrypt_with_hello(const std::wstring& key_name, const std::vector<uint8_t>& encrypted_data) {
        NCRYPT_PROV_HANDLE hProv = 0;
        NCRYPT_KEY_HANDLE hKey = 0;
        DWORD bytes_needed = 0;

        // 1. Abrir o provedor TPM
        if (NCryptOpenStorageProvider(&hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) 
            return std::nullopt;

        // 2. Abrir a chave persistente
        if (NCryptOpenKey(hProv, &hKey, key_name.c_str(), 0, 0) != ERROR_SUCCESS) {
            NCryptFreeObject(hProv);
            return std::nullopt;
        }

        // 3. Primeira chamada para descobrir o tamanho do buffer de saída
        // O Windows Hello/PIN pop-up geralmente aparece aqui ou na próxima chamada
        SECURITY_STATUS status = NCryptDecrypt(hKey, 
                                            (PBYTE)encrypted_data.data(), (DWORD)encrypted_data.size(), 
                                            NULL, NULL, 0, &bytes_needed, 
                                            NCRYPT_PAD_PKCS1_FLAG);

        if (status != ERROR_SUCCESS) {
            NCryptFreeObject(hKey);
            NCryptFreeObject(hProv);
            return std::nullopt;
        }

        std::vector<uint8_t> decrypted_secret(bytes_needed);
        // Trava a memória para onde o segredo será escrito
        CryptoHelper::lock_memory(decrypted_secret.data(), decrypted_secret.size());

        // 4. Descriptografia real (pop-up de biometria garantido aqui)
        status = NCryptDecrypt(hKey, 
                            (PBYTE)encrypted_data.data(), (DWORD)encrypted_data.size(), 
                            NULL, decrypted_secret.data(), (DWORD)decrypted_secret.size(), 
                            &bytes_needed, NCRYPT_PAD_PKCS1_FLAG);

        if (status != ERROR_SUCCESS) {
            CryptoHelper::secure_zero_memory(decrypted_secret.data(), decrypted_secret.size());
            CryptoHelper::unlock_memory(decrypted_secret.data(), decrypted_secret.size());
            decrypted_secret.clear();
            NCryptFreeObject(hKey);
            NCryptFreeObject(hProv);
            return std::nullopt;
        } else {
            decrypted_secret.resize(bytes_needed);
        }

        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        return decrypted_secret;
    }

    // Função para cifrar o segredo do Scrypt usando a chave do Windows Hello
    inline std::vector<uint8_t> encrypt_with_hello(const std::wstring& key_name, const std::vector<uint8_t>& secret) {
        NCRYPT_PROV_HANDLE hProv = 0;
        NCRYPT_KEY_HANDLE hKey = 0;
        DWORD bytes_done = 0;

        NCryptOpenStorageProvider(&hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0);
        
        // Abrir a chave existente (Isso NÃO dispara o Windows Hello ainda)
        if (NCryptOpenKey(hProv, &hKey, key_name.c_str(), 0, 0) != ERROR_SUCCESS) return {};

        // Cifrar os dados (O Windows Hello será disparado se a chave exigir autenticação para uso)
        // Nota: Para RSA, o tamanho do segredo deve ser menor que o tamanho da chave.
        // Se a dk do Scrypt for maior, use RSA para cifrar uma chave AES temporária (Envelope Encryption).
        std::vector<uint8_t> encrypted(512); // Buffer para RSA 2048/4096
        NCryptEncrypt(hKey, (PBYTE)secret.data(), (DWORD)secret.size(), NULL, encrypted.data(), (DWORD)encrypted.size(), &bytes_done, NCRYPT_PAD_PKCS1_FLAG);
        
        encrypted.resize(bytes_done);

        NCryptFreeObject(hKey);
        NCryptFreeObject(hProv);
        return encrypted;
    }

    inline bool delete_windows_hello_key(const std::wstring& key_name) {
        NCRYPT_PROV_HANDLE hProv = 0;
        NCRYPT_KEY_HANDLE hKey = 0;

        // 1. Abrir o provedor
        if (NCryptOpenStorageProvider(&hProv, MS_PLATFORM_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) 
            return false;

        // 2. Abrir a chave existente
        // Nota: Abrir a chave para deletar geralmente NÃO dispara o prompt do Windows Hello
        if (NCryptOpenKey(hProv, &hKey, key_name.c_str(), 0, 0) != ERROR_SUCCESS) {
            NCryptFreeObject(hProv);
            return false;
        }

        // 3. Deletar a chave do hardware (TPM)
        // Esta função também libera o handle hKey automaticamente se tiver sucesso
        SECURITY_STATUS status = NCryptDeleteKey(hKey, 0);

        NCryptFreeObject(hProv);
        return (status == ERROR_SUCCESS);
    }
}