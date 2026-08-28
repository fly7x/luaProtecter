#pragma once

#include <vector>
#include <cstdint>
#include <string>

class Bytecode {
public:
    Bytecode() = default;
    explicit Bytecode(std::vector<uint8_t>&& data) : data_(std::move(data)) {}
    explicit Bytecode(const std::vector<uint8_t>& data) : data_(data) {}
    
    const std::vector<uint8_t>& data() const { return data_; }
    std::vector<uint8_t>& data() { return data_; }
    bool empty() const { return data_.empty(); }
    size_t size() const { return data_.size(); }
    
    std::string toString() const {
        return std::string(data_.begin(), data_.end());
    }
    
private:
    std::vector<uint8_t> data_;
};