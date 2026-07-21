#include "logger.hpp"

Logger::Logger(const std::string& filepath) : file_(filepath, std::ios::app) {
    if (!file_) {
        throw std::runtime_error("[logger] [ERROR]: Failed to open: " + filepath);
    }

    worker_ = std::thread(&Logger::run, this);
}

Logger::~Logger() {
    shutdown();
}

void Logger::log(LogLevel level, std::string msg) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) {
            return;
        }
        queue_.push_back(format(level, std::move(msg)));
    }

    cv_.notify_one();
}

void Logger::debug(std::string msg) {
    log(LogLevel::Debug, std::move(msg));
}

void Logger::error(std::string msg) {
    log(LogLevel::Error, std::move(msg));
}

void Logger::info(std::string msg) {
    log(LogLevel::Info, std::move(msg));
}

void Logger::warn(std::string msg) {
    log(LogLevel::Warn, std::move(msg));
}

void Logger::shutdown() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (stopping_) {
            return;
        }

        stopping_ = true;
    }

    cv_.notify_one();
    if (worker_.joinable()) {
        worker_.join();
    }
}

std::string Logger::format(LogLevel level, std::string msg) const {
    using namespace std::chrono;
    auto now = system_clock::now();
    auto t = system_clock::to_time_t(now);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%Y-%m-%d %H:%H:%S")
        << '.' << std::setw(3) << std::setfill('0') << ms.count()
        << " [" << to_string(level) << "] "
        << msg << std::endl;
    
    return oss.str();
}

void Logger::run() {
    std::deque<std::string> local_batch;

    while (true) {
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait(lock, [this] {
                return stopping_ || !queue_.empty();
            });

            if (queue_.empty() && stopping_) {
                break;
            }

            std::swap(local_batch, queue_);
        }

        for (auto& line : local_batch) {
            file_ << line;
        }
        
        file_.flush();
        local_batch.clear();
    }

    file_.flush();
}
