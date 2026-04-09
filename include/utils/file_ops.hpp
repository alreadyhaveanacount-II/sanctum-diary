#pragma once

#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;

void save_binary(const fs::path& path, const void* data, size_t size) {
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path());
    }

    std::ofstream file(path, std::ios::binary);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(data), size);
        file.close();
    }
}

void truncate_file(const fs::path& path, size_t new_size) {
    fs::resize_file(path, new_size);
}

void rewrite_binary_section(const fs::path& path, const void* data, size_t size, size_t offset) {
    std::ofstream file(path, std::ios::binary | std::ios::in | std::ios::out);
    
    if (file.is_open()) {
        file.seekp(offset, std::ios::beg); // Move para a posição desejada a partir do início
        file.write(reinterpret_cast<const char*>(data), size);
        file.close();
    }
}

void append_binary(const fs::path& path, const void* data, size_t size) {
    if (path.has_parent_path()) {
        fs::create_directories(path.parent_path());
    }

    std::ofstream file(path, std::ios::binary | std::ios::app);
    if (file.is_open()) {
        file.write(reinterpret_cast<const char*>(data), size);
        file.close();
    }
}

uintmax_t get_file_size(const fs::path& path) {
    return fs::file_size(path);
}

std::vector<uint8_t> read_file_range(const fs::path& path, size_t start_index, size_t length) {
    if (!fs::exists(path)) return {};

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return {};

    // Verifica se o arquivo é grande o suficiente para o índice inicial
    uintmax_t total_size = fs::file_size(path);
    if (start_index >= total_size) return {};

    // Ajusta o comprimento se ultrapassar o fim do arquivo
    if (start_index + length > total_size) {
        length = total_size - start_index;
    }

    std::vector<uint8_t> buffer(length);
    
    // Move o cursor para o índice e lê os bytes
    file.seekg(start_index);
    if (file.read(reinterpret_cast<char*>(buffer.data()), length)) {
        return buffer;
    }

    return {};
}