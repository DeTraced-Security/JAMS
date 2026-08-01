#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>

namespace Utils {
    enum class LogLevel {
        Debug, Info,
        Warn, Error
    };

    inline const char* to_string(LogLevel lvl) {
        switch (lvl) {
            case LogLevel::Debug: {
                return "DEBUG";
            }
            case LogLevel::Error: {
                return "ERROR";
            }
            case LogLevel::Info: {
                return "INFO";
            }
            case LogLevel::Warn: {
                return "WARN";
            }
        }

        return "?";
    }

    class Logger {
        public:
            explicit Logger(const std::string& filepath);
            ~Logger();

            Logger(const Logger&) = delete;
            Logger& operator=(const Logger&) = delete;

            void log(LogLevel level, std::string msg);

            void debug(std::string msg);
            void info(std::string msg);
            void warn(std::string msg);
            void error(std::string msg);

            void shutdown();
        
        private:
            std::ofstream file_;
            std::thread worker_;
            std::mutex mutex_;
            std::condition_variable cv_;
            std::deque<std::string> queue_;
            bool stopping_{false};

            std::string format(LogLevel level, std::string msg) const;
            void run();
    };
};
