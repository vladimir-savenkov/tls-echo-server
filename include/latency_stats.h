#pragma once

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>

// Ограниченная память: 8 интервалов на каждое удвоение микросекунд.
// Квантили возвращают верхнюю границу интервала (погрешность до 9.1%).
class LatencyStats {
public:
    void record(double microseconds) {
        const auto index = static_cast<std::size_t>(std::clamp(
            std::floor(std::log2(std::max(1.0, microseconds)) * 8), 0.0, 511.0));
        ++buckets_[index];
        ++count_;
    }
    void merge(const LatencyStats& other) {
        for (std::size_t i = 0; i < buckets_.size(); ++i) buckets_[i] += other.buckets_[i];
        count_ += other.count_;
    }
    uint64_t count() const { return count_; }
    double percentile(double fraction) const {
        if (count_ == 0) return 0;
        const auto target = std::max<uint64_t>(1, static_cast<uint64_t>(
            std::ceil(std::clamp(fraction, 0.0, 1.0) * static_cast<double>(count_))));
        uint64_t seen = 0;
        for (std::size_t i = 0; i < buckets_.size(); ++i) {
            seen += buckets_[i];
            if (seen >= target) return std::exp2(static_cast<double>(i + 1) / 8);
        }
        return 0;
    }
private:
    std::array<uint64_t, 512> buckets_{};
    uint64_t count_ = 0;
};
